import type { MiddlewareContext, MiddlewareError, MiddlewareHandler } from "./types.js"

/**
 * Error handler middleware
 * Catches errors from the pipeline and converts them to HTTP responses
 */
export function errorHandler(): MiddlewareHandler {
  return async (ctx: MiddlewareContext, next: () => Promise<void>) => {
    try {
      // Execute the rest of the pipeline
      await next()
    } catch (err) {
      // Convert unknown errors to MiddlewareError
      const error = normalizeError(err)

      // Store error in context for logging
      ctx.error = error

      // Determine status code
      const statusCode = error.statusCode || 500

      // Determine if we should expose the error message
      const expose = error.expose !== false && statusCode < 500

      // Log error to console (will be replaced with structured logging later)
      if (statusCode >= 500) {
        console.error("[middleware] Internal error:", {
          requestId: ctx.requestId,
          path: ctx.pathname,
          error: error.message,
          stack: error.stack,
        })
      } else {
        console.error("[middleware] Client error:", {
          requestId: ctx.requestId,
          path: ctx.pathname,
          statusCode,
          error: error.message,
        })
      }

      // Send error response
      sendErrorResponse(ctx, statusCode, expose ? error.message : getDefaultErrorMessage(statusCode))
    }
  }
}

/**
 * Normalize any error to MiddlewareError
 */
function normalizeError(err: unknown): MiddlewareError {
  if (err instanceof Error) {
    return err as MiddlewareError
  }

  // Convert non-Error objects to Error
  const message = typeof err === "string" ? err : "Unknown error occurred"
  return new Error(message) as MiddlewareError
}

/**
 * Get default error message for status code
 */
function getDefaultErrorMessage(statusCode: number): string {
  switch (statusCode) {
    case 400:
      return "Bad Request"
    case 401:
      return "Unauthorized"
    case 403:
      return "Forbidden"
    case 404:
      return "Not Found"
    case 413:
      return "Request Entity Too Large"
    case 429:
      return "Too Many Requests"
    case 500:
      return "Internal Server Error"
    case 503:
      return "Service Unavailable"
    default:
      return "An error occurred"
  }
}

/**
 * Send JSON error response
 */
function sendErrorResponse(ctx: MiddlewareContext, statusCode: number, message: string): void {
  // Prevent double-sending if response already started
  if (ctx.res.headersSent) {
    console.error("[middleware] Cannot send error response - headers already sent")
    return
  }

  const errorResponse = {
    error: {
      message,
      requestId: ctx.requestId,
      statusCode,
    },
  }

  ctx.res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "X-Request-Id": ctx.requestId,
  })

  ctx.res.end(JSON.stringify(errorResponse))
}
