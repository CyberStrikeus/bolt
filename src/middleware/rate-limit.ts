import type { MiddlewareContext, MiddlewareHandler } from "./types.js"
import { createMiddlewareError } from "./types.js"

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  /** Enable rate limiting */
  enabled: boolean

  /** Global IP rate: requests per minute */
  globalIpLimit: number

  /** Authenticated client rate: requests per minute */
  clientLimit: number

  /** Authenticated client burst capacity */
  clientBurst: number

  /** Pairing endpoint rate: requests per 5 minutes per IP */
  pairLimit: number

  /** MCP endpoint rate: requests per minute per session */
  mcpLimit: number

  /** Cleanup interval for stale entries (ms) */
  cleanupInterval: number
}

/**
 * Token bucket for rate limiting
 */
interface TokenBucket {
  tokens: number
  lastRefill: number
  capacity: number
  refillRate: number // tokens per minute
}

/**
 * Sliding window for IP-based rate limiting
 */
interface SlidingWindow {
  requests: number[]
  windowSize: number // in ms
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: RateLimitConfig = {
  enabled: true,
  globalIpLimit: 300, // 300 req/min per IP
  clientLimit: 100, // 100 req/min per authenticated client
  clientBurst: 20, // Allow bursts of 20
  pairLimit: 10, // 10 pairing attempts per 5 min
  mcpLimit: 50, // 50 MCP requests per min
  cleanupInterval: 5 * 60 * 1000, // 5 minutes
}

/**
 * Rate limiter middleware
 * Implements hybrid token bucket + sliding window approach
 */
export function rateLimiter(config: Partial<RateLimitConfig> = {}): MiddlewareHandler {
  const cfg = { ...DEFAULT_CONFIG, ...config }

  // Token buckets for authenticated clients
  const clientBuckets = new Map<string, TokenBucket>()

  // Sliding windows for IP-based limits
  const ipWindows = new Map<string, SlidingWindow>()

  // Endpoint-specific windows
  const pairWindows = new Map<string, SlidingWindow>()

  // Setup periodic cleanup
  const cleanupTimer = setInterval(() => {
    cleanup(clientBuckets, ipWindows, pairWindows)
  }, cfg.cleanupInterval)

  // Clear timer on process exit
  process.on("beforeExit", () => clearInterval(cleanupTimer))

  return async (ctx: MiddlewareContext, next: () => Promise<void>) => {
    // Skip if disabled
    if (!cfg.enabled) {
      return next()
    }

    const now = Date.now()

    // Check IP-based rate limit (applies to all requests)
    const ipAllowed = checkIpLimit(ctx.clientIp, now, cfg.globalIpLimit, ipWindows)
    if (!ipAllowed) {
      const retryAfter = 60 // 1 minute
      ctx.res.setHeader("Retry-After", String(retryAfter))

      console.error("[rate-limit] IP rate limit exceeded", {
        clientIp: ctx.clientIp,
        requestId: ctx.requestId,
        limit: cfg.globalIpLimit,
      })

      throw createMiddlewareError(
        `Rate limit exceeded (${cfg.globalIpLimit} requests per minute). Please try again later.`,
        429,
      )
    }

    // Check endpoint-specific limits
    if (ctx.pathname === "/pair") {
      const pairAllowed = checkPairLimit(ctx.clientIp, now, cfg.pairLimit, pairWindows)
      if (!pairAllowed) {
        const retryAfter = 300 // 5 minutes
        ctx.res.setHeader("Retry-After", String(retryAfter))

        console.error("[rate-limit] Pairing rate limit exceeded", {
          clientIp: ctx.clientIp,
          requestId: ctx.requestId,
          limit: cfg.pairLimit,
        })

        throw createMiddlewareError(
          `Too many pairing attempts (${cfg.pairLimit} per 5 minutes). Please try again later.`,
          429,
        )
      }
    }

    // Check authenticated client limit (if authenticated)
    if (ctx.authenticated && ctx.clientId) {
      const bucket = getOrCreateBucket(ctx.clientId, cfg.clientLimit, cfg.clientBurst, clientBuckets)
      refillBucket(bucket, now)

      if (bucket.tokens < 1) {
        const retryAfter = Math.ceil(60 / cfg.clientLimit)
        ctx.res.setHeader("Retry-After", String(retryAfter))

        console.error("[rate-limit] Client rate limit exceeded", {
          clientId: ctx.clientId,
          requestId: ctx.requestId,
          limit: cfg.clientLimit,
        })

        throw createMiddlewareError(
          `Rate limit exceeded (${cfg.clientLimit} requests per minute). Please slow down.`,
          429,
        )
      }

      // Consume token
      bucket.tokens -= 1
      ctx.rateLimitRemaining = Math.floor(bucket.tokens)
    }

    // Continue to next middleware
    await next()
  }
}

/**
 * Check IP-based rate limit using sliding window
 */
function checkIpLimit(
  ip: string,
  now: number,
  limit: number,
  windows: Map<string, SlidingWindow>,
): boolean {
  const window = getOrCreateWindow(ip, 60 * 1000, windows) // 1 minute window

  // Remove old requests outside window
  window.requests = window.requests.filter((time) => now - time < window.windowSize)

  // Check if under limit
  if (window.requests.length >= limit) {
    return false
  }

  // Add current request
  window.requests.push(now)
  return true
}

/**
 * Check pairing endpoint limit (5 minute window)
 */
function checkPairLimit(
  ip: string,
  now: number,
  limit: number,
  windows: Map<string, SlidingWindow>,
): boolean {
  const window = getOrCreateWindow(ip, 5 * 60 * 1000, windows) // 5 minute window

  // Remove old requests
  window.requests = window.requests.filter((time) => now - time < window.windowSize)

  // Check limit
  if (window.requests.length >= limit) {
    return false
  }

  // Add current request
  window.requests.push(now)
  return true
}

/**
 * Get or create token bucket for client
 */
function getOrCreateBucket(
  clientId: string,
  refillRate: number,
  capacity: number,
  buckets: Map<string, TokenBucket>,
): TokenBucket {
  let bucket = buckets.get(clientId)

  if (!bucket) {
    bucket = {
      tokens: capacity,
      lastRefill: Date.now(),
      capacity,
      refillRate,
    }
    buckets.set(clientId, bucket)
  }

  return bucket
}

/**
 * Refill token bucket based on time elapsed
 */
function refillBucket(bucket: TokenBucket, now: number): void {
  const elapsed = now - bucket.lastRefill
  const tokensToAdd = (elapsed / (60 * 1000)) * bucket.refillRate

  bucket.tokens = Math.min(bucket.capacity, bucket.tokens + tokensToAdd)
  bucket.lastRefill = now
}

/**
 * Get or create sliding window
 */
function getOrCreateWindow(
  key: string,
  windowSize: number,
  windows: Map<string, SlidingWindow>,
): SlidingWindow {
  let window = windows.get(key)

  if (!window) {
    window = {
      requests: [],
      windowSize,
    }
    windows.set(key, window)
  }

  return window
}

/**
 * Cleanup stale entries
 */
function cleanup(
  clientBuckets: Map<string, TokenBucket>,
  ipWindows: Map<string, SlidingWindow>,
  pairWindows: Map<string, SlidingWindow>,
): void {
  const now = Date.now()

  // Remove stale IP windows (no requests in last 5 minutes)
  for (const [ip, window] of ipWindows.entries()) {
    const lastRequest = Math.max(...window.requests, 0)
    if (now - lastRequest > 5 * 60 * 1000) {
      ipWindows.delete(ip)
    }
  }

  // Remove stale pair windows
  for (const [ip, window] of pairWindows.entries()) {
    const lastRequest = Math.max(...window.requests, 0)
    if (now - lastRequest > 10 * 60 * 1000) {
      pairWindows.delete(ip)
    }
  }

  // Remove stale client buckets (no activity in last 10 minutes)
  for (const [clientId, bucket] of clientBuckets.entries()) {
    if (now - bucket.lastRefill > 10 * 60 * 1000) {
      clientBuckets.delete(clientId)
    }
  }

  console.error("[rate-limit] Cleanup completed", {
    ipWindows: ipWindows.size,
    pairWindows: pairWindows.size,
    clientBuckets: clientBuckets.size,
  })
}
