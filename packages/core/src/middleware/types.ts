import type http from "node:http"

/**
 * Middleware context passed through the pipeline
 * Contains request/response, parsed data, and metadata
 */
export interface MiddlewareContext {
  /** Original HTTP request */
  req: http.IncomingMessage

  /** HTTP response to write to */
  res: http.ServerResponse

  /** Parsed URL pathname */
  pathname: string

  /** HTTP method (GET, POST, etc.) */
  method: string

  /** Request body as string (populated after body parsing) */
  bodyStr?: string

  /** Whether the request has been authenticated */
  authenticated?: boolean

  /** Client ID if authenticated via Ed25519 */
  clientId?: string

  /** Unique request identifier for tracing */
  requestId: string

  /** Client IP address */
  clientIp: string

  /** Request start timestamp (ms since epoch) */
  startTime: number

  /** Remaining rate limit quota */
  rateLimitRemaining?: number

  /** Error that occurred during processing */
  error?: MiddlewareError
}

/**
 * Middleware handler function
 * Can modify context and call next() to continue the pipeline
 */
export type MiddlewareHandler = (ctx: MiddlewareContext, next: () => Promise<void>) => Promise<void>

/**
 * Enhanced error with HTTP status code and exposure flag
 */
export interface MiddlewareError extends Error {
  /** HTTP status code to return */
  statusCode?: number

  /** Whether to expose error message to client (false = generic message) */
  expose?: boolean

  /** Original error that caused this error */
  cause?: Error
}

/**
 * Create a middleware error
 */
export function createMiddlewareError(
  message: string,
  statusCode: number,
  expose = true,
): MiddlewareError {
  const error = new Error(message) as MiddlewareError
  error.statusCode = statusCode
  error.expose = expose
  return error
}
