import winston from "winston"
import DailyRotateFile from "winston-daily-rotate-file"
import path from "node:path"
import { jsonFormatter, consoleFormatter } from "./formatters.js"
import type { LogCategory } from "./types.js"

/**
 * Get log directory from environment or default
 */
export function getLogDir(): string {
  const dataDir = process.env.DATA_DIR || path.join(process.cwd(), "data")
  return path.join(dataDir, "logs")
}

/**
 * Create file transport for a specific log category
 */
export function createFileTransport(category: LogCategory): DailyRotateFile {
  return new DailyRotateFile({
    filename: path.join(getLogDir(), `${category}-%DATE%.log`),
    datePattern: "YYYY-MM-DD",
    maxSize: process.env.LOG_MAX_SIZE || "50m",
    maxFiles: process.env.LOG_MAX_FILES || "30d",
    format: jsonFormatter,
    level: process.env.LOG_LEVEL || "info",
    zippedArchive: true,
  })
}

/**
 * Create console transport
 */
export function createConsoleTransport(): winston.transports.ConsoleTransportInstance {
  const logToConsole = process.env.LOG_CONSOLE !== "false"

  if (!logToConsole) {
    // Return a null transport if console logging is disabled
    return new winston.transports.Console({
      silent: true,
    })
  }

  return new winston.transports.Console({
    format: consoleFormatter,
    level: process.env.LOG_LEVEL || "info",
    stderrLevels: ["error", "warn"],
  })
}

/**
 * Create all file transports (one per category)
 */
export function createAllFileTransports(): DailyRotateFile[] {
  const categories: LogCategory[] = ["audit", "tools", "connections", "errors", "metrics", "security"]

  return categories.map((category) => createFileTransport(category))
}

/**
 * Configure log rotation settings
 */
export interface LogRotationConfig {
  /** Maximum log file size before rotation */
  maxSize: string

  /** Maximum number of log files to keep (or time period like "30d") */
  maxFiles: string

  /** Enable compression of rotated files */
  zippedArchive: boolean

  /** Date pattern for file names */
  datePattern: string
}

/**
 * Get log rotation configuration
 */
export function getRotationConfig(): LogRotationConfig {
  return {
    maxSize: process.env.LOG_MAX_SIZE || "50m",
    maxFiles: process.env.LOG_MAX_FILES || "30d",
    zippedArchive: process.env.LOG_COMPRESS !== "false",
    datePattern: "YYYY-MM-DD",
  }
}
