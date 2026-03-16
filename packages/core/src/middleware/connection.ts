import type { MiddlewareContext, MiddlewareHandler } from "./types.js"
import { createMiddlewareError } from "./types.js"

/**
 * Connection tracking for throttling
 */
interface ConnectionInfo {
  clientIp: string
  connectedAt: number
}

/**
 * Configuration for connection throttling
 */
export interface ConnectionThrottleConfig {
  /** Enable connection throttling */
  enabled: boolean

  /** Maximum concurrent connections globally */
  maxGlobal: number

  /** Maximum concurrent connections per IP */
  maxPerIp: number
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: ConnectionThrottleConfig = {
  enabled: true,
  maxGlobal: 100,
  maxPerIp: 10,
}

/**
 * Connection throttling middleware
 * Limits concurrent connections globally and per-IP to prevent resource exhaustion
 */
export function connectionThrottle(config: Partial<ConnectionThrottleConfig> = {}): MiddlewareHandler {
  const cfg = { ...DEFAULT_CONFIG, ...config }

  // Track active connections
  const activeConnections = new Map<string, ConnectionInfo>()

  // Track connections per IP
  const connectionsPerIp = new Map<string, Set<string>>()

  return async (ctx: MiddlewareContext, next: () => Promise<void>) => {
    // Skip if disabled
    if (!cfg.enabled) {
      return next()
    }

    const connectionId = `${ctx.clientIp}:${Date.now()}:${Math.random()}`
    const clientIp = ctx.clientIp

    // Check global connection limit
    if (activeConnections.size >= cfg.maxGlobal) {
      console.error("[connection] Global connection limit reached", {
        current: activeConnections.size,
        max: cfg.maxGlobal,
        requestId: ctx.requestId,
      })

      throw createMiddlewareError(
        `Server at capacity (${cfg.maxGlobal} concurrent connections). Please try again later.`,
        503,
      )
    }

    // Check per-IP connection limit
    const ipConnections = connectionsPerIp.get(clientIp)
    if (ipConnections && ipConnections.size >= cfg.maxPerIp) {
      console.error("[connection] Per-IP connection limit reached", {
        clientIp,
        current: ipConnections.size,
        max: cfg.maxPerIp,
        requestId: ctx.requestId,
      })

      throw createMiddlewareError(
        `Too many concurrent connections from your IP (${cfg.maxPerIp} max). Please close some connections.`,
        429,
      )
    }

    // Add connection to tracking
    const connInfo: ConnectionInfo = {
      clientIp,
      connectedAt: Date.now(),
    }

    activeConnections.set(connectionId, connInfo)

    // Track per-IP
    if (!connectionsPerIp.has(clientIp)) {
      connectionsPerIp.set(clientIp, new Set())
    }
    connectionsPerIp.get(clientIp)!.add(connectionId)

    // Setup cleanup on connection close
    const cleanup = () => {
      activeConnections.delete(connectionId)

      const ipSet = connectionsPerIp.get(clientIp)
      if (ipSet) {
        ipSet.delete(connectionId)
        if (ipSet.size === 0) {
          connectionsPerIp.delete(clientIp)
        }
      }
    }

    // Cleanup when connection closes
    ctx.req.on("close", cleanup)
    ctx.req.on("error", cleanup)

    try {
      // Process request
      await next()
    } finally {
      // Cleanup after request completes
      cleanup()
    }
  }
}

/**
 * Get connection stats for monitoring
 */
export function getConnectionStats(
  activeConnections: Map<string, ConnectionInfo>,
  connectionsPerIp: Map<string, Set<string>>,
): {
  totalConnections: number
  uniqueIps: number
  topIps: Array<{ ip: string; count: number }>
} {
  const ipCounts = Array.from(connectionsPerIp.entries())
    .map(([ip, connections]) => ({ ip, count: connections.size }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  return {
    totalConnections: activeConnections.size,
    uniqueIps: connectionsPerIp.size,
    topIps: ipCounts,
  }
}
