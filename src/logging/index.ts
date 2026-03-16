/**
 * Structured logging system for Bolt MCP Server
 *
 * Features:
 * - Structured JSON logging
 * - Multiple log files by category (audit, tools, connections, errors, metrics, security)
 * - Daily log rotation with compression
 * - PII sanitization (passwords, tokens, keys)
 * - AsyncLocalStorage for request context tracking
 * - Console and file transports
 *
 * Usage:
 * ```typescript
 * import { logger } from './logging'
 *
 * // Set request context
 * logger.setContext({ requestId: '123', clientId: 'abc' })
 *
 * // Log events
 * logger.audit({ event: 'pair_success', message: 'Client paired successfully' })
 * logger.toolCall({ toolName: 'nmap', toolArgs: { target: '192.168.1.1' } })
 * logger.error(new Error('Something went wrong'))
 * ```
 */

export * from "./types.js"
export * from "./logger.js"
export * from "./formatters.js"
export * from "./transports.js"
