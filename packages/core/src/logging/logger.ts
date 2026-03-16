import winston from "winston"
import { AsyncLocalStorage } from "node:async_hooks"
import { createAllFileTransports, createConsoleTransport } from "./transports.js"
import { toSafeString, sanitizeValue } from "./formatters.js"
import type {
  LogEvent,
  LogCategory,
  LogLevel,
  AuditLogEvent,
  ToolCallEvent,
  ToolResultEvent,
  ConnectionLogEvent,
  ErrorLogEvent,
  MetricsLogEvent,
  SecurityLogEvent,
} from "./types.js"

/**
 * Request context for AsyncLocalStorage
 */
interface RequestContext {
  requestId: string
  sessionId?: string
  clientId?: string
  clientName?: string
  clientIp?: string
}

/**
 * Logger class with structured logging
 */
export class Logger {
  private winston: winston.Logger
  private asyncStorage = new AsyncLocalStorage<RequestContext>()

  constructor() {
    // Create Winston logger with multiple transports
    this.winston = winston.createLogger({
      level: process.env.LOG_LEVEL || "info",
      transports: [createConsoleTransport(), ...createAllFileTransports()],
    })
  }

  /**
   * Set request context for current async operation
   */
  setContext(context: RequestContext): void {
    this.asyncStorage.enterWith(context)
  }

  /**
   * Get current request context
   */
  getContext(): RequestContext | undefined {
    return this.asyncStorage.getStore()
  }

  /**
   * Log a structured event
   * ALL INPUTS ARE SANITIZED TO PREVENT LOG INJECTION/RCE
   */
  log(event: Partial<LogEvent>): void {
    const context = this.getContext()

    // Sanitize ALL string inputs to prevent RCE
    const logEntry: LogEvent = {
      timestamp: new Date().toISOString(),
      level: event.level || "info",
      category: event.category || "audit",
      event: toSafeString(event.event || "unknown"),
      message: toSafeString(event.message || ""),
      requestId: toSafeString(event.requestId || context?.requestId || ""),
      sessionId: event.sessionId ? toSafeString(event.sessionId) : context?.sessionId ? toSafeString(context.sessionId) : undefined,
      clientId: event.clientId ? toSafeString(event.clientId) : context?.clientId ? toSafeString(context.clientId) : undefined,
      clientName: event.clientName ? toSafeString(event.clientName) : context?.clientName ? toSafeString(context.clientName) : undefined,
      clientIp: event.clientIp ? toSafeString(event.clientIp) : context?.clientIp ? toSafeString(context.clientIp) : undefined,
      metadata: event.metadata ? sanitizeValue(event.metadata) : undefined,
      ...event,
    } as LogEvent

    // Route to appropriate Winston logger based on category
    this.winston.log(logEntry.level, toSafeString(logEntry.message), logEntry)
  }

  /**
   * Log audit event (client activities)
   */
  audit(event: Partial<AuditLogEvent>): void {
    this.log({
      ...event,
      category: "audit",
      level: event.level || "info",
    })
  }

  /**
   * Log tool call
   */
  toolCall(event: Partial<ToolCallEvent>): void {
    this.log({
      ...event,
      category: "tools",
      event: "tool_call",
      level: "info",
    })
  }

  /**
   * Log tool result
   */
  toolResult(event: Partial<ToolResultEvent>): void {
    this.log({
      ...event,
      category: "tools",
      event: "tool_result",
      level: event.success ? "info" : "warn",
    })
  }

  /**
   * Log connection event
   */
  connection(event: Partial<ConnectionLogEvent>): void {
    this.log({
      ...event,
      category: "connections",
      level: "info",
    })
  }

  /**
   * Log error (sanitized to prevent RCE)
   */
  error(event: Partial<ErrorLogEvent> | Error, message?: string): void {
    if (event instanceof Error) {
      this.log({
        category: "errors",
        event: "error",
        level: "error",
        message: toSafeString(message || event.message),
        errorName: toSafeString(event.name),
        errorMessage: toSafeString(event.message),
        stack: event.stack ? toSafeString(event.stack) : undefined,
      })
    } else {
      this.log({
        ...event,
        category: "errors",
        event: "error",
        level: "error",
        message: toSafeString(event.message || "Unknown error"),
      })
    }
  }

  /**
   * Log metric
   */
  metric(event: Partial<MetricsLogEvent>): void {
    this.log({
      ...event,
      category: "metrics",
      level: "info",
    })
  }

  /**
   * Log security event
   */
  security(event: Partial<SecurityLogEvent>): void {
    this.log({
      ...event,
      category: "security",
      level: event.severity === "critical" || event.severity === "high" ? "error" : "warn",
    })
  }

  /**
   * Generic log methods (all sanitized)
   */
  info(message: string, metadata?: Record<string, unknown>): void {
    this.log({
      level: "info",
      message: toSafeString(message),
      metadata: metadata ? (sanitizeValue(metadata) as Record<string, unknown>) : undefined,
    })
  }

  warn(message: string, metadata?: Record<string, unknown>): void {
    this.log({
      level: "warn",
      message: toSafeString(message),
      metadata: metadata ? (sanitizeValue(metadata) as Record<string, unknown>) : undefined,
    })
  }

  debug(message: string, metadata?: Record<string, unknown>): void {
    this.log({
      level: "debug",
      message: toSafeString(message),
      metadata: metadata ? (sanitizeValue(metadata) as Record<string, unknown>) : undefined,
    })
  }
}

/**
 * Singleton logger instance
 */
export const logger = new Logger()
