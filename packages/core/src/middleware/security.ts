import type { MiddlewareContext, MiddlewareHandler } from "./types.js"
import { createMiddlewareError } from "./types.js"

/**
 * Configuration for request security validation
 */
export interface SecurityConfig {
  /** Maximum request body size in bytes (default: 1MB) */
  maxBodySize: number

  /** Maximum header size in bytes (default: 8KB) */
  maxHeaderSize: number

  /** Request timeout in milliseconds (default: 30s) */
  timeout: number
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: SecurityConfig = {
  maxBodySize: 1024 * 1024, // 1 MB
  maxHeaderSize: 8 * 1024, // 8 KB
  timeout: 30000, // 30 seconds
}

/**
 * Security validation middleware
 * Enforces request size limits and timeout to prevent abuse
 */
export function securityValidator(config: Partial<SecurityConfig> = {}): MiddlewareHandler {
  const cfg = { ...DEFAULT_CONFIG, ...config }

  return async (ctx: MiddlewareContext, next: () => Promise<void>) => {
    // Validate header size
    const headerSize = estimateHeaderSize(ctx.req)
    if (headerSize > cfg.maxHeaderSize) {
      console.error("[security] Header size too large", {
        size: headerSize,
        max: cfg.maxHeaderSize,
        requestId: ctx.requestId,
      })

      throw createMiddlewareError(
        `Request headers too large (${formatBytes(headerSize)} / ${formatBytes(cfg.maxHeaderSize)} max)`,
        413,
      )
    }

    // Only validate body size for requests with bodies (POST, PUT, PATCH)
    const hasBody = ["POST", "PUT", "PATCH"].includes(ctx.method)

    if (hasBody) {
      // Read body with size limit
      try {
        ctx.bodyStr = await readBodyWithLimit(ctx, cfg.maxBodySize, cfg.timeout)
      } catch (error) {
        if (error instanceof Error) {
          throw createMiddlewareError(error.message, 413)
        }
        throw error
      }
    }

    // Continue to next middleware
    await next()
  }
}

/**
 * Estimate total header size
 */
function estimateHeaderSize(req: { rawHeaders?: string[]; headers: Record<string, unknown> }): number {
  // Use rawHeaders if available (more accurate)
  if (req.rawHeaders && Array.isArray(req.rawHeaders)) {
    return req.rawHeaders.reduce((total, header) => total + header.length, 0)
  }

  // Fallback to headers object
  let size = 0
  for (const [key, value] of Object.entries(req.headers)) {
    size += key.length
    if (typeof value === "string") {
      size += value.length
    } else if (Array.isArray(value)) {
      size += value.join(",").length
    }
  }

  return size
}

/**
 * Read request body with size limit
 * Rejects BEFORE buffering entire body to prevent memory exhaustion
 */
function readBodyWithLimit(
  ctx: MiddlewareContext,
  maxSize: number,
  timeout: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let totalSize = 0
    let timedOut = false

    // Setup timeout
    const timer = setTimeout(() => {
      timedOut = true
      ctx.req.destroy()
      reject(new Error(`Request timeout (${timeout}ms)`))
    }, timeout)

    ctx.req.on("data", (chunk: Buffer) => {
      if (timedOut) return

      totalSize += chunk.length

      // Reject immediately if size exceeds limit
      if (totalSize > maxSize) {
        clearTimeout(timer)
        ctx.req.destroy()
        reject(
          new Error(
            `Request body too large (${formatBytes(totalSize)} / ${formatBytes(maxSize)} max)`,
          ),
        )
        return
      }

      chunks.push(chunk)
    })

    ctx.req.on("end", () => {
      if (timedOut) return

      clearTimeout(timer)
      const body = Buffer.concat(chunks).toString("utf-8")
      resolve(body)
    })

    ctx.req.on("error", (error) => {
      clearTimeout(timer)
      reject(error)
    })
  })
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
