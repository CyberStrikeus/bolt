/**
 * Structured logging types for Bolt MCP Server
 */

export type LogLevel = "debug" | "info" | "warn" | "error"

export type LogCategory = "audit" | "tools" | "connections" | "errors" | "metrics" | "security"

/**
 * Base log event structure (all events extend this)
 */
export interface BaseLogEvent {
  /** ISO 8601 timestamp */
  timestamp: string

  /** Log level */
  level: LogLevel

  /** Log category (determines which file to write to) */
  category: LogCategory

  /** Event type (e.g., "tool_call", "auth_success") */
  event: string

  /** Request ID for tracing */
  requestId?: string

  /** Session ID for MCP sessions */
  sessionId?: string

  /** Client ID (Ed25519 fingerprint) */
  clientId?: string

  /** Client name */
  clientName?: string

  /** Client IP address */
  clientIp?: string

  /** Human-readable message */
  message: string

  /** Additional metadata */
  metadata?: Record<string, unknown>
}

/**
 * Audit log event (client activities)
 */
export interface AuditLogEvent extends BaseLogEvent {
  category: "audit"
  event:
    | "pair_request"
    | "pair_success"
    | "pair_failure"
    | "auth_success"
    | "auth_failure"
    | "client_revoked"
    | "tool_call"
    | "tool_complete"
    | "job_started"
    | "job_completed"
    | "job_failed"
    | "job_cancelled"
    | "tools_loaded"
    | "tools_unloaded"
    | "tools_unloaded_all"
    | "server_started"
    | "server_keys_loaded"
    | "server_keys_generated"
    | "clients_loaded"
    | "cert_generated"
    | "admin_health_check"
    | "server_stopped"
    | "setup_token_generated"
    | "setup_token_invalidated"
}

/**
 * Tool execution event (start)
 */
export interface ToolCallEvent extends BaseLogEvent {
  category: "tools"
  event: "tool_call"

  /** Tool name */
  toolName: string

  /** Tool arguments (sanitized) */
  toolArgs: Record<string, unknown>

  /** Hash of arguments for deduplication */
  argsHash: string

  /** Start time */
  startTime: string
}

/**
 * Tool execution result event (end)
 */
export interface ToolResultEvent extends BaseLogEvent {
  category: "tools"
  event: "tool_result"

  /** Tool name */
  toolName: string

  /** Execution duration in milliseconds */
  duration: number

  /** Exit code (0 = success) */
  exitCode: number

  /** Success flag */
  success: boolean

  /** Output size in bytes */
  outputSize: number

  /** Output preview (first 200 chars) */
  outputPreview: string

  /** End time */
  endTime: string
}

/**
 * Connection event (sessions)
 */
export interface ConnectionLogEvent extends BaseLogEvent {
  category: "connections"
  event: "session_start" | "session_end" | "session_expired" | "connection_established" | "connection_closed"

  /** Connection duration (for end events) */
  duration?: number
}

/**
 * Error log event
 */
export interface ErrorLogEvent extends BaseLogEvent {
  category: "errors"
  event: "error"

  /** Error name */
  errorName: string

  /** Error message */
  errorMessage: string

  /** Stack trace */
  stack?: string

  /** HTTP status code (if applicable) */
  statusCode?: number
}

/**
 * Metrics event (performance, throughput)
 */
export interface MetricsLogEvent extends BaseLogEvent {
  category: "metrics"
  event: "request_latency" | "throughput" | "resource_usage"

  /** Metric value */
  value: number

  /** Metric unit */
  unit: string

  /** Additional metric data */
  metrics?: Record<string, number>
}

/**
 * Security event (auth failures, suspicious activity)
 */
export interface SecurityLogEvent extends BaseLogEvent {
  category: "security"
  event:
    | "auth_failure"
    | "rate_limit_exceeded"
    | "invalid_signature"
    | "suspicious_request"
    | "access_denied"
    | "self_signed_cert_warning"

  /** Severity level */
  severity: "low" | "medium" | "high" | "critical"

  /** Action taken (e.g., "blocked", "throttled") */
  action?: string
}

/**
 * Union type of all log events
 */
export type LogEvent =
  | AuditLogEvent
  | ToolCallEvent
  | ToolResultEvent
  | ConnectionLogEvent
  | ErrorLogEvent
  | MetricsLogEvent
  | SecurityLogEvent
