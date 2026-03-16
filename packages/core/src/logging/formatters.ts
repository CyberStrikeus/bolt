import { format } from "winston"
import crypto from "node:crypto"

/**
 * Sensitive field names to redact
 */
const SENSITIVE_FIELDS = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "key",
  "auth",
  "authorization",
  "api_key",
  "apikey",
  "private_key",
  "privatekey",
  "access_token",
  "refresh_token",
]

/**
 * Check if a field name is sensitive
 */
function isSensitiveField(fieldName: string): boolean {
  const lower = fieldName.toLowerCase()
  return SENSITIVE_FIELDS.some((sensitive) => lower.includes(sensitive))
}

/**
 * Safe string conversion - prevents RCE via log injection
 */
export function toSafeString(value: unknown): string {
  // Null/undefined
  if (value === null) return "null"
  if (value === undefined) return "undefined"

  // Already a string - escape special chars
  if (typeof value === "string") {
    // Remove control characters and escape special JSON chars
    return value
      .replace(/[\x00-\x1F\x7F-\x9F]/g, "") // Remove control chars
      .replace(/\\/g, "\\\\") // Escape backslash
      .replace(/"/g, '\\"') // Escape quotes
      .replace(/\n/g, "\\n") // Escape newlines
      .replace(/\r/g, "\\r") // Escape carriage returns
      .replace(/\t/g, "\\t") // Escape tabs
  }

  // Numbers, booleans - safe to convert
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value)
  }

  // BigInt
  if (typeof value === "bigint") {
    return value.toString()
  }

  // Functions - don't log the code!
  if (typeof value === "function") {
    return "[Function]"
  }

  // Symbols
  if (typeof value === "symbol") {
    return "[Symbol]"
  }

  // Objects/Arrays - use JSON.stringify with error handling
  try {
    return JSON.stringify(value)
  } catch {
    return "[Circular or Invalid Object]"
  }
}

/**
 * Sanitize sensitive data by replacing with hash
 */
export function sanitizeValue(value: unknown, fieldName?: string): unknown {
  // Check if field name is sensitive
  if (fieldName && isSensitiveField(fieldName)) {
    if (typeof value === "string" && value.length > 0) {
      const hash = crypto.createHash("sha256").update(value).digest("hex").slice(0, 8)
      return `[REDACTED:${hash}]`
    }
    return "[REDACTED]"
  }

  // Convert to safe string first (prevents RCE)
  const safeValue = toSafeString(value)

  // Recursively sanitize objects
  if (value && typeof value === "object") {
    if (Array.isArray(value)) {
      return value.map((item) => toSafeString(sanitizeValue(item)))
    }

    const sanitized: Record<string, string> = {}
    for (const [key, val] of Object.entries(value)) {
      sanitized[toSafeString(key)] = toSafeString(sanitizeValue(val, key))
    }
    return sanitized
  }

  return safeValue
}

/**
 * Truncate long strings to prevent log bloat
 */
export function truncateString(str: string, maxLength = 200): string {
  if (str.length <= maxLength) {
    return str
  }
  return str.slice(0, maxLength) + "...[truncated]"
}

/**
 * JSON formatter with sanitization
 */
export const jsonFormatter: ReturnType<typeof format.combine> = format.combine(
  format.timestamp({ format: "YYYY-MM-DD HH:mm:ss.SSS" }),
  format.errors({ stack: true }),
  format.printf((info) => {
    // Sanitize metadata
    const sanitized: Record<string, unknown> = {
      ...info,
      metadata: info.metadata ? sanitizeValue(info.metadata) : undefined,
    }

    // Remove undefined fields
    Object.keys(sanitized).forEach((key) => {
      if (sanitized[key] === undefined) {
        delete sanitized[key]
      }
    })

    return JSON.stringify(sanitized)
  }),
)

/**
 * Console formatter (human-readable)
 */
export const consoleFormatter: ReturnType<typeof format.combine> = format.combine(
  format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  format.colorize(),
  format.printf((info) => {
    const { timestamp, level, message, category, event, ...meta } = info

    let output = `${timestamp} [${level}]`

    if (category) {
      output += ` [${category}]`
    }

    if (event) {
      output += ` [${event}]`
    }

    output += ` ${message}`

    // Add metadata if present
    const metaKeys = Object.keys(meta).filter((k) => k !== "timestamp" && k !== "level")
    if (metaKeys.length > 0) {
      const sanitized = sanitizeValue(meta)
      output += ` ${JSON.stringify(sanitized)}`
    }

    return output
  }),
)
