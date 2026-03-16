#!/usr/bin/env node

import http from "node:http"
import https from "node:https"
import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "path"
import { fileURLToPath } from "url"
import { execSync } from "node:child_process"
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import { loadAllTools } from "./tools/loader.js"
import { DynamicRegistry } from "./tools/registry.js"
import { createMcpServer } from "./server.js"
import type { Server } from "@modelcontextprotocol/sdk/server/index.js"
import type { ToolDefinition } from "./tools/types.js"
import {
  MiddlewarePipeline,
  errorHandler,
  connectionThrottle,
  securityValidator,
  rateLimiter,
  type MiddlewareContext,
} from "./middleware/index.js"
import { logger } from "./logging/index.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DEFINITIONS_DIR = path.join(__dirname, "..", "src", "definitions")

// --- Configuration ---

const DEFAULT_PORT = 3001
const DEFAULT_HOST = "0.0.0.0"
const SESSION_TIMEOUT_MS = 30 * 60 * 1000 // 30 minutes
const PAIRING_CODE_TTL_MS = 5 * 60 * 1000 // 5 minutes
const NONCE_TTL_MS = 30 * 1000 // 30 second window for replay protection
const TIMESTAMP_DRIFT_MS = 30 * 1000 // 30 second clock drift tolerance
const SETUP_TOKEN_TTL_MS = 30 * 60 * 1000 // 30 minutes for fresh install setup
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "..", "data")

// --- Parse CLI arguments ---

const cliArgs = process.argv.slice(2)
for (let i = 0; i < cliArgs.length; i++) {
  if (cliArgs[i] === "--port" && cliArgs[i + 1]) {
    process.env.PORT = cliArgs[++i]
  } else if (cliArgs[i] === "--host" && cliArgs[i + 1]) {
    process.env.HOST = cliArgs[++i]
  } else if (cliArgs[i] === "--admin-token" && cliArgs[i + 1]) {
    process.env.MCP_ADMIN_TOKEN = cliArgs[++i]
  } else if (cliArgs[i] === "--data-dir" && cliArgs[i + 1]) {
    process.env.DATA_DIR = cliArgs[++i]
  } else if (cliArgs[i] === "--tls") {
    process.env.TLS_ENABLED = "true"
  } else if (cliArgs[i] === "--tls-key" && cliArgs[i + 1]) {
    process.env.TLS_KEY_PATH = cliArgs[++i]
  } else if (cliArgs[i] === "--tls-cert" && cliArgs[i + 1]) {
    process.env.TLS_CERT_PATH = cliArgs[++i]
  }
}

const effectivePort = parseInt(process.env.PORT || String(DEFAULT_PORT), 10)
const effectiveHost = process.env.HOST || DEFAULT_HOST
const adminToken = process.env.MCP_ADMIN_TOKEN || ""
const dataDir = process.env.DATA_DIR || DATA_DIR

// TLS Configuration
const tlsEnabled = process.env.TLS_ENABLED === "true"
const tlsKeyPath = process.env.TLS_KEY_PATH || path.join(dataDir, "tls-key.pem")
const tlsCertPath = process.env.TLS_CERT_PATH || path.join(dataDir, "tls-cert.pem")

/**
 * Constant-time string comparison to prevent timing attacks
 */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  try {
    const bufA = Buffer.from(a)
    const bufB = Buffer.from(b)
    return crypto.timingSafeEqual(bufA, bufB)
  } catch {
    return false
  }
}

/**
 * Generate self-signed TLS certificate for development
 * Production should use Let's Encrypt or proper CA-signed certificates
 */
async function generateSelfSignedCert(keyPath: string, certPath: string): Promise<void> {
  logger.warn("Generating self-signed certificate for development", {
    category: "security",
    metadata: { keyPath, certPath },
  })
  logger.security({
    event: "self_signed_cert_warning",
    message: "Self-signed certificates are NOT secure for production",
    severity: "high",
    action: "warn",
    metadata: { recommendation: "Use Let's Encrypt or proper CA-signed certificate" },
  })

  try {
    // Generate self-signed certificate using openssl
    const cmd = `openssl req -x509 -newkey rsa:4096 -nodes -sha256 \
      -keyout "${keyPath}" \
      -out "${certPath}" \
      -days 365 \
      -subj "/CN=localhost/O=Bolt MCP Server/C=US" \
      2>/dev/null`

    execSync(cmd, { stdio: "inherit" })
    logger.audit({
      event: "cert_generated",
      message: "TLS certificate and private key generated",
      metadata: { certPath, keyPath },
    })
  } catch (error) {
    logger.error(error instanceof Error ? error : new Error(String(error)), "Failed to generate TLS certificate")
    throw error
  }
}

/**
 * Ensure TLS certificates exist
 */
async function ensureTlsCertificates(): Promise<void> {
  if (!tlsEnabled) return

  try {
    await fs.access(tlsKeyPath)
    await fs.access(tlsCertPath)
    logger.info("Using existing TLS certificates", {
      metadata: { keyPath: tlsKeyPath, certPath: tlsCertPath },
    })
  } catch {
    logger.warn("TLS certificates not found, generating self-signed certificate", {
      metadata: { keyPath: tlsKeyPath, certPath: tlsCertPath },
    })
    await generateSelfSignedCert(tlsKeyPath, tlsCertPath)
  }
}

// =====================================================================
// Ed25519 Key Management
// =====================================================================

interface ServerKeys {
  publicKey: crypto.KeyObject
  privateKey: crypto.KeyObject
  publicKeyPem: string
}

interface AuthorizedClient {
  clientId: string // fingerprint of public key
  publicKeyPem: string
  name: string
  pairedAt: string
}

interface SetupToken {
  token: string
  createdAt: number
  ttl: number // milliseconds
}

let serverKeys: ServerKeys
const authorizedClients = new Map<string, AuthorizedClient>()
let setupToken: SetupToken | null = null

const SERVER_KEYS_PATH = () => path.join(dataDir, "server-keys.json")
const CLIENTS_PATH = () => path.join(dataDir, "authorized-clients.json")

/**
 * Compute a short fingerprint for a public key PEM.
 */
function fingerprint(publicKeyPem: string): string {
  return crypto.createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 16)
}

/**
 * Generate or load the server's Ed25519 key pair.
 */
async function initServerKeys(): Promise<void> {
  await fs.mkdir(dataDir, { recursive: true })

  try {
    const raw = await fs.readFile(SERVER_KEYS_PATH(), "utf-8")
    const stored = JSON.parse(raw) as { publicKey: string; privateKey: string }
    serverKeys = {
      publicKey: crypto.createPublicKey(stored.publicKey),
      privateKey: crypto.createPrivateKey(stored.privateKey),
      publicKeyPem: stored.publicKey,
    }
    logger.audit({
      event: "server_keys_loaded",
      message: "Loaded existing server Ed25519 key pair",
    })
  } catch {
    // Generate new key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519")
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string

    await fs.writeFile(
      SERVER_KEYS_PATH(),
      JSON.stringify({ publicKey: publicKeyPem, privateKey: privateKeyPem }),
      { mode: 0o600 }
    )

    serverKeys = { publicKey, privateKey, publicKeyPem }
    logger.audit({
      event: "server_keys_generated",
      message: "Generated new server Ed25519 key pair",
    })
  }

  const keyFingerprint = fingerprint(serverKeys.publicKeyPem)
  logger.info("Server public key fingerprint", {
    metadata: { fingerprint: keyFingerprint },
  })
}

/**
 * Load authorized clients from disk.
 */
async function loadAuthorizedClients(): Promise<void> {
  try {
    const raw = await fs.readFile(CLIENTS_PATH(), "utf-8")
    const clients = JSON.parse(raw) as AuthorizedClient[]
    for (const client of clients) {
      authorizedClients.set(client.clientId, client)
    }
    logger.audit({
      event: "clients_loaded",
      message: "Loaded authorized clients",
      metadata: { count: authorizedClients.size },
    })
  } catch {
    logger.info("No authorized clients found (fresh install)")
  }
}

/**
 * Persist authorized clients to disk.
 */
async function saveAuthorizedClients(): Promise<void> {
  const clients = Array.from(authorizedClients.values())
  await fs.writeFile(CLIENTS_PATH(), JSON.stringify(clients, null, 2), { mode: 0o600 })
}

// =====================================================================
// Pairing Code Management
// =====================================================================

interface PairingCode {
  code: string
  createdAt: number
  used: boolean
}

const activePairingCodes = new Map<string, PairingCode>()

/**
 * Generate a cryptographically random pairing code (format: XXX-XXX).
 */
function generatePairingCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous chars (0/O, 1/I)
  const limit = 256 - (256 % chars.length)
  let code = ""
  while (code.replace("-", "").length < 6) {
    const bytes = crypto.randomBytes(6 - code.replace("-", "").length)
    for (const byte of bytes) {
      if (byte < limit) {
        code += chars[byte % chars.length]
        if (code.replace("-", "").length === 3 && !code.includes("-")) code += "-"
        if (code.replace("-", "").length === 6) break
      }
    }
  }
  return code
}

/**
 * Clean up expired pairing codes.
 */
function cleanupPairingCodes(): void {
  const now = Date.now()
  for (const [code, entry] of activePairingCodes.entries()) {
    if (entry.used || now - entry.createdAt > PAIRING_CODE_TTL_MS) {
      activePairingCodes.delete(code)
    }
  }
}

// =====================================================================
// Replay Protection (nonce + timestamp)
// =====================================================================

const usedNonces = new Map<string, number>() // nonce → timestamp

function cleanupNonces(): void {
  const cutoff = Date.now() - NONCE_TTL_MS * 2
  for (const [nonce, ts] of usedNonces.entries()) {
    if (ts < cutoff) usedNonces.delete(nonce)
  }
}

// =====================================================================
// Ed25519 Signature Verification
// =====================================================================

interface AuthResult {
  authenticated: boolean
  clientId?: string
  error?: string
}

/**
 * Verify an Ed25519-signed request.
 *
 * Required headers:
 *   X-Client-Id:  fingerprint of client public key
 *   X-Timestamp:  ISO 8601 timestamp
 *   X-Nonce:      unique random value
 *   X-Signature:  base64-encoded Ed25519 signature of "{timestamp}\n{nonce}\n{method}\n{path}\n{bodyHash}"
 */
function verifySignature(req: http.IncomingMessage, bodyStr: string): AuthResult {
  const clientId = req.headers["x-client-id"] as string | undefined
  const timestamp = req.headers["x-timestamp"] as string | undefined
  const nonce = req.headers["x-nonce"] as string | undefined
  const signature = req.headers["x-signature"] as string | undefined

  if (!clientId || !timestamp || !nonce || !signature) {
    return { authenticated: false, error: "Missing auth headers (X-Client-Id, X-Timestamp, X-Nonce, X-Signature)" }
  }

  // 1. Check client is authorized
  const client = authorizedClients.get(clientId)
  if (!client) {
    return { authenticated: false, error: "Unknown client" }
  }

  // 2. Check timestamp drift
  const ts = new Date(timestamp).getTime()
  if (isNaN(ts) || Math.abs(Date.now() - ts) > TIMESTAMP_DRIFT_MS) {
    return { authenticated: false, error: "Timestamp out of range" }
  }

  // 3. Check nonce hasn't been used
  if (usedNonces.has(nonce)) {
    return { authenticated: false, error: "Nonce already used (replay detected)" }
  }

  // 4. Verify signature
  const method = (req.method || "GET").toUpperCase()
  const urlPath = req.url || "/"
  const bodyHash = crypto.createHash("sha256").update(bodyStr).digest("hex")
  const message = `${timestamp}\n${nonce}\n${method}\n${urlPath}\n${bodyHash}`

  try {
    const publicKey = crypto.createPublicKey(client.publicKeyPem)
    const valid = crypto.verify(null, Buffer.from(message), publicKey, Buffer.from(signature, "base64"))
    if (!valid) {
      return { authenticated: false, error: "Invalid signature" }
    }
  } catch {
    return { authenticated: false, error: "Signature verification failed" }
  }

  // 5. Record nonce
  usedNonces.set(nonce, Date.now())

  return { authenticated: true, clientId }
}

/**
 * Authenticate /mcp requests.
 * Uses Ed25519 signatures if clients are registered, falls back to admin token if no clients exist.
 */
function authenticateMcpRequest(req: http.IncomingMessage, bodyStr: string): AuthResult {
  // If no clients are registered and no admin token, auth is disabled (local dev)
  if (authorizedClients.size === 0 && !adminToken) {
    return { authenticated: true, clientId: "anonymous" }
  }

  // Try Ed25519 signature auth first
  if (req.headers["x-client-id"]) {
    return verifySignature(req, bodyStr)
  }

  // Fallback: admin token can also access /mcp (for backwards compat / debugging)
  if (adminToken) {
    const authHeader = req.headers.authorization
    if (authHeader) {
      const [scheme, token] = authHeader.split(" ")
      if (scheme === "Bearer" && token && secureCompare(token, adminToken)) {
        return { authenticated: true, clientId: "admin" }
      }
    }
  }

  return { authenticated: false, error: "No valid authentication provided" }
}

/**
 * Authenticate admin-only endpoints (/pair).
 * Requires MCP_ADMIN_TOKEN.
 */
function authenticateAdmin(req: http.IncomingMessage): boolean {
  if (!adminToken) return false // Admin endpoints require a token

  const authHeader = req.headers.authorization
  if (!authHeader) return false

  const [scheme, token] = authHeader.split(" ")
  return scheme === "Bearer" && !!token && secureCompare(token, adminToken)
}

/**
 * Generate a cryptographically secure setup token for fresh installations.
 */
function generateSetupToken(): string {
  return crypto.randomBytes(32).toString("base64url")
}

/**
 * Check if the setup token is still valid (within TTL).
 */
function isSetupTokenValid(): boolean {
  if (!setupToken) return false
  const age = Date.now() - setupToken.createdAt
  return age < setupToken.ttl
}

/**
 * Authenticate /pair endpoint with hybrid approach:
 * - If clients exist: only admin token allowed
 * - If no clients: admin token OR setup token allowed
 */
function authenticatePairRequest(req: http.IncomingMessage): {
  authenticated: boolean
  method?: "admin" | "setup"
  error?: string
} {
  // If clients already exist, only admin token is allowed
  if (authorizedClients.size > 0) {
    if (!adminToken) {
      return { authenticated: false, error: "Admin token required but not set" }
    }

    const authHeader = req.headers.authorization
    if (!authHeader) {
      return { authenticated: false, error: "Authorization header required (Bearer token)" }
    }

    const [scheme, token] = authHeader.split(" ")
    if (scheme === "Bearer" && token && secureCompare(token, adminToken)) {
      return { authenticated: true, method: "admin" }
    }

    return { authenticated: false, error: "Invalid admin token" }
  }

  // No clients exist: allow either admin token OR setup token
  // Try admin token first (if set)
  if (adminToken) {
    const authHeader = req.headers.authorization
    if (authHeader) {
      const [scheme, token] = authHeader.split(" ")
      if (scheme === "Bearer" && token && secureCompare(token, adminToken)) {
        return { authenticated: true, method: "admin" }
      }
    }
  }

  // Try setup token
  if (setupToken && isSetupTokenValid()) {
    const authHeader = req.headers.authorization
    if (authHeader) {
      const [scheme, token] = authHeader.split(" ")
      if (scheme === "Bearer" && token && secureCompare(token, setupToken.token)) {
        return { authenticated: true, method: "setup" }
      }
    }
  }

  // No valid auth provided
  if (setupToken && isSetupTokenValid()) {
    return { authenticated: false, error: "Setup token or admin token required (Bearer token)" }
  }

  return { authenticated: false, error: adminToken ? "Admin token required" : "No authentication configured" }
}

// =====================================================================
// MCP Session Management
// =====================================================================

interface Session {
  server: Server
  transport: StreamableHTTPServerTransport
  registry: DynamicRegistry
  lastActivity: number
}

const sessions = new Map<string, Session>()
let sharedToolDefs: Map<string, ToolDefinition>

// Initialize middleware pipeline
const middlewareEnabled = process.env.MIDDLEWARE_ENABLED !== "false"
const middleware = new MiddlewarePipeline()

// Setup middleware pipeline (do this once, not per request)
if (middlewareEnabled) {
  middleware
    .use(errorHandler())
    .use(connectionThrottle({
      enabled: process.env.CONNECTION_LIMIT_ENABLED !== "false",
      maxGlobal: parseInt(process.env.CONNECTION_LIMIT_GLOBAL || "100", 10),
      maxPerIp: parseInt(process.env.CONNECTION_LIMIT_PER_IP || "10", 10),
    }))
    .use(securityValidator({
      maxBodySize: parseInt(process.env.REQUEST_SIZE_LIMIT || String(1024 * 1024), 10),
      maxHeaderSize: parseInt(process.env.REQUEST_HEADER_LIMIT || String(8 * 1024), 10),
      timeout: parseInt(process.env.REQUEST_TIMEOUT || "30000", 10),
    }))
    .use(rateLimiter({
      enabled: process.env.RATE_LIMIT_ENABLED !== "false",
      globalIpLimit: parseInt(process.env.RATE_LIMIT_GLOBAL_IP || "300", 10),
      clientLimit: parseInt(process.env.RATE_LIMIT_CLIENT || "100", 10),
      clientBurst: parseInt(process.env.RATE_LIMIT_CLIENT_BURST || "20", 10),
      pairLimit: parseInt(process.env.RATE_LIMIT_PAIR || "10", 10),
      mcpLimit: parseInt(process.env.RATE_LIMIT_MCP || "50", 10),
    }))
    // Add route handler as final middleware
    .use(async (ctx: MiddlewareContext) => {
      await handleRoutes(ctx.req, ctx.res, ctx)
    })
}

/**
 * Extract client IP from request
 * Checks X-Forwarded-For header first (for proxies), then falls back to socket
 */
function getClientIp(req: http.IncomingMessage): string {
  // Check X-Forwarded-For header (proxy/load balancer)
  const forwarded = req.headers["x-forwarded-for"]
  if (forwarded) {
    const ip = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0]
    return ip.trim()
  }

  // Fallback to socket address
  return req.socket.remoteAddress || "unknown"
}

function createSession(): Session {
  const registry = new DynamicRegistry()
  registry.initialize(sharedToolDefs)

  const server = createMcpServer(registry)

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    onsessioninitialized: (sessionId: string) => {
      logger.connection({
        event: "session_start",
        message: "MCP session initialized",
        sessionId,
      })
      sessions.set(sessionId, session)
    },
  })

  const session: Session = {
    server,
    transport,
    registry,
    lastActivity: Date.now(),
  }

  server.connect(transport).catch((err) => {
    logger.error(err instanceof Error ? err : new Error(String(err)), "Failed to connect server to transport")
  })

  return session
}

function getSession(req: http.IncomingMessage): Session | undefined {
  const sessionId = req.headers["mcp-session-id"] as string | undefined
  if (!sessionId) return undefined
  const session = sessions.get(sessionId)
  if (session) session.lastActivity = Date.now()
  return session
}

function cleanupSessions(): void {
  const now = Date.now()
  for (const [id, session] of sessions.entries()) {
    if (now - session.lastActivity > SESSION_TIMEOUT_MS) {
      logger.connection({
        event: "session_expired",
        message: "Cleaning up expired session",
        sessionId: id,
        metadata: { lastActivity: new Date(session.lastActivity).toISOString() },
      })
      session.transport.close().catch(() => {})
      sessions.delete(id)
    }
  }
}

// =====================================================================
// CORS & Helpers
// =====================================================================

function setCorsHeaders(res: http.ServerResponse): void {
  res.setHeader("Access-Control-Allow-Origin", "*")
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, X-Client-Id, X-Timestamp, X-Nonce, X-Signature"
  )
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id")
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ""
    req.on("data", (chunk: Buffer) => { data += chunk })
    req.on("end", () => resolve(data))
    req.on("error", reject)
  })
}

function jsonResponse(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" })
  res.end(JSON.stringify(body))
}

// =====================================================================
// Request Router
// =====================================================================

/**
 * Main request handler with middleware integration
 */
async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  // Always set CORS headers
  setCorsHeaders(res)

  // Handle CORS preflight immediately (bypass middleware)
  if (req.method === "OPTIONS") {
    res.writeHead(204)
    res.end()
    return
  }

  // If middleware is disabled, go directly to route handling
  if (!middlewareEnabled) {
    return handleRoutes(req, res)
  }

  // Create middleware context
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`)
  const ctx: MiddlewareContext = {
    req,
    res,
    pathname: url.pathname,
    method: req.method || "GET",
    requestId: crypto.randomUUID(),
    clientIp: getClientIp(req),
    startTime: Date.now(),
  }

  // Execute middleware pipeline (route handler is last middleware)
  await middleware.execute(ctx)
}

/**
 * Route handling logic (called after middleware)
 */
async function handleRoutes(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  ctx?: MiddlewareContext,
): Promise<void> {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`)
  const pathname = url.pathname

  // =================================================================
  // PUBLIC ENDPOINTS
  // These endpoints are accessible without authentication.
  // Protected by rate limiting and connection throttling via middleware.
  // =================================================================

  // --- Health check (no auth required) ---
  // Allows clients to verify this is a Bolt server before pairing
  // --- Health Check ---
  // Public: minimal info (just status)
  // Authenticated: full details (requires admin token)
  if (pathname === "/health" && req.method === "GET") {
    const isAdmin = authenticateAdmin(req)

    if (!isAdmin) {
      // Public health check - minimal information
      logger.debug("Public health check", {
        metadata: { clientIp: getClientIp(req) },
      })

      jsonResponse(res, 200, {
        status: "ok",
        timestamp: new Date().toISOString(),
      })
      return
    }

    // Admin health check - detailed information
    logger.audit({
      event: "admin_health_check",
      message: "Admin accessed detailed health endpoint",
      clientIp: getClientIp(req),
    })

    jsonResponse(res, 200, {
      status: "ok",
      identity: "bolt",
      version: "0.2.0",
      timestamp: new Date().toISOString(),
      transport: "streamable-http",
      auth: "ed25519",
      middleware: middlewareEnabled ? "enabled" : "disabled",
      tls: tlsEnabled ? "enabled" : "disabled",
      activeSessions: sessions.size,
      authorizedClients: authorizedClients.size,
      toolCount: sharedToolDefs?.size ?? 0,
      uptime: Math.floor(process.uptime()),
      memory: {
        heapUsed: Math.floor(process.memoryUsage().heapUsed / 1024 / 1024), // MB
        heapTotal: Math.floor(process.memoryUsage().heapTotal / 1024 / 1024), // MB
        rss: Math.floor(process.memoryUsage().rss / 1024 / 1024), // MB
      },
      serverFingerprint: fingerprint(serverKeys.publicKeyPem),
    })
    return
  }

  // --- Pairing: Generate code (setup token OR admin token required) ---
  // For fresh installs: setup token (30 min) OR admin token
  // After first client: only admin token
  if (pathname === "/pair" && req.method === "POST") {
    const auth = authenticatePairRequest(req)
    if (!auth.authenticated) {
      jsonResponse(res, 401, { error: "Unauthorized", message: auth.error })
      return
    }

    cleanupPairingCodes()

    const code = generatePairingCode()
    activePairingCodes.set(code, {
      code,
      createdAt: Date.now(),
      used: false,
    })

    logger.audit({
      event: "pair_request",
      message: `Pairing code generated via ${auth.method} authentication`,
      metadata: { code, expiresIn: PAIRING_CODE_TTL_MS / 1000, authMethod: auth.method },
    })

    jsonResponse(res, 200, {
      code,
      expiresIn: PAIRING_CODE_TTL_MS / 1000,
      serverFingerprint: fingerprint(serverKeys.publicKeyPem),
    })
    return
  }

  // --- Pairing: Exchange keys (pairing code required) ---
  // New client exchanges public keys using the one-time pairing code.
  // After this, client is authorized for Ed25519 signed requests.
  if (pathname === "/pair/exchange" && req.method === "POST") {
    const bodyStr = ctx?.bodyStr || (await readBody(req))
    let body: { code?: string; clientPublicKey?: string; clientName?: string }
    try {
      body = JSON.parse(bodyStr)
    } catch {
      jsonResponse(res, 400, { error: "Invalid JSON" })
      return
    }

    const { code, clientPublicKey, clientName } = body

    if (!code || !clientPublicKey) {
      jsonResponse(res, 400, { error: "Missing required fields: code, clientPublicKey" })
      return
    }

    // Validate pairing code
    cleanupPairingCodes()
    const pairingEntry = activePairingCodes.get(code)

    if (!pairingEntry) {
      jsonResponse(res, 403, { error: "Invalid or expired pairing code" })
      return
    }

    if (pairingEntry.used) {
      jsonResponse(res, 403, { error: "Pairing code already used" })
      return
    }

    // Validate the client public key is a valid Ed25519 key
    try {
      const keyObj = crypto.createPublicKey(clientPublicKey)
      if (keyObj.asymmetricKeyType !== "ed25519") {
        jsonResponse(res, 400, { error: "Key must be Ed25519" })
        return
      }
    } catch {
      jsonResponse(res, 400, { error: "Invalid public key format (expected PEM-encoded Ed25519)" })
      return
    }

    // Mark code as used
    pairingEntry.used = true
    activePairingCodes.delete(code)

    // Register client
    const clientId = fingerprint(clientPublicKey)
    const client: AuthorizedClient = {
      clientId,
      publicKeyPem: clientPublicKey,
      name: clientName || `client-${clientId.slice(0, 8)}`,
      pairedAt: new Date().toISOString(),
    }

    authorizedClients.set(clientId, client)
    await saveAuthorizedClients()

    // Invalidate setup token after first client is paired
    if (setupToken) {
      logger.audit({
        event: "setup_token_invalidated",
        message: "Setup token invalidated after first client pairing",
        metadata: { clientId, clientName: client.name },
      })
      setupToken = null
    }

    logger.audit({
      event: "pair_success",
      message: `Client paired successfully`,
      clientId,
      clientName: client.name,
      metadata: { pairedAt: client.pairedAt },
    })

    // Return pairing response
    jsonResponse(res, 200, {
      clientId,
      serverPublicKey: serverKeys.publicKeyPem,
      serverFingerprint: fingerprint(serverKeys.publicKeyPem),
      name: client.name,
    })
    return
  }

  // --- List paired clients (admin token required) ---
  if (pathname === "/pair/clients" && req.method === "GET") {
    if (!authenticateAdmin(req)) {
      jsonResponse(res, 401, { error: "Unauthorized", message: "Admin token required" })
      return
    }

    const clients = Array.from(authorizedClients.values()).map((c) => ({
      clientId: c.clientId,
      name: c.name,
      pairedAt: c.pairedAt,
    }))

    jsonResponse(res, 200, { clients })
    return
  }

  // --- Revoke a client (admin token required) ---
  if (pathname.startsWith("/pair/clients/") && req.method === "DELETE") {
    if (!authenticateAdmin(req)) {
      jsonResponse(res, 401, { error: "Unauthorized", message: "Admin token required" })
      return
    }

    const clientId = pathname.split("/pair/clients/")[1]
    if (authorizedClients.has(clientId)) {
      const client = authorizedClients.get(clientId)!
      authorizedClients.delete(clientId)
      await saveAuthorizedClients()
      logger.audit({
        event: "client_revoked",
        message: "Client authorization revoked",
        clientId,
        clientName: client.name,
      })

      jsonResponse(res, 200, { revoked: clientId })
    } else {
      jsonResponse(res, 404, { error: "Client not found" })
    }
    return
  }

  // =================================================================
  // AUTHENTICATED ENDPOINTS
  // These endpoints require Ed25519 signature authentication.
  // Protected by middleware (rate limiting, connection throttling) +
  // Ed25519 signature verification for every request.
  // =================================================================

  // --- MCP endpoint (Ed25519 signature required) ---
  // This is where tool execution happens. Protected by:
  //   1. Middleware (rate limiting, connection throttling, request validation)
  //   2. Ed25519 signed requests (every request must be signed)
  if (pathname === "/mcp") {
    // Read body for signature verification (POST only)
    const bodyStr = req.method === "POST" ? (ctx?.bodyStr || (await readBody(req))) : ""

    // Authenticate (Ed25519 signature verification)
    const auth = authenticateMcpRequest(req, bodyStr)
    if (!auth.authenticated) {
      jsonResponse(res, 401, { error: "Unauthorized", message: auth.error })
      return
    }

    // Update context with auth info
    if (ctx) {
      ctx.authenticated = true
      ctx.clientId = auth.clientId
    }

    if (req.method === "POST") {
      let parsedBody: unknown
      try {
        parsedBody = JSON.parse(bodyStr)
      } catch {
        jsonResponse(res, 400, { error: "Invalid JSON" })
        return
      }

      const existingSession = getSession(req)
      if (existingSession) {
        await existingSession.transport.handleRequest(req, res, parsedBody)
        return
      }

      const isInit = Array.isArray(parsedBody)
        ? (parsedBody as Array<{ method?: string }>).some((m) => m.method === "initialize")
        : (parsedBody as { method?: string }).method === "initialize"

      if (isInit) {
        const session = createSession()
        await session.transport.handleRequest(req, res, parsedBody)
        return
      }

      jsonResponse(res, 400, {
        error: "Bad Request",
        message: "Missing Mcp-Session-Id header. Send an initialize request first.",
      })
      return
    }

    if (req.method === "GET") {
      const session = getSession(req)
      if (!session) {
        jsonResponse(res, 400, { error: "Bad Request", message: "Missing or invalid session ID" })
        return
      }
      await session.transport.handleRequest(req, res)
      return
    }

    if (req.method === "DELETE") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined
      const session = sessionId ? sessions.get(sessionId) : undefined

      if (session) {
        await session.transport.handleRequest(req, res)
        sessions.delete(sessionId!)
        logger.connection({
          event: "session_end",
          message: "MCP session closed",
          sessionId: sessionId!,
        })
      } else {
        jsonResponse(res, 404, { error: "Session not found" })
      }
      return
    }

    jsonResponse(res, 405, { error: "Method not allowed" })
    return
  }

  jsonResponse(res, 404, { error: "Not found" })
}

// =====================================================================
// Main
// =====================================================================

// Periodic cleanup
const cleanupInterval = setInterval(() => {
  cleanupSessions()
  cleanupPairingCodes()
  cleanupNonces()
}, 5 * 60 * 1000)

async function main(): Promise<void> {
  logger.info("Starting Bolt MCP server")

  // Initialize crypto keys and authorized clients
  await initServerKeys()
  await loadAuthorizedClients()

  // Generate setup token for fresh installations (no clients, no admin token)
  if (authorizedClients.size === 0 && !adminToken) {
    setupToken = {
      token: generateSetupToken(),
      createdAt: Date.now(),
      ttl: SETUP_TOKEN_TTL_MS,
    }

    const expiresAt = new Date(setupToken.createdAt + setupToken.ttl).toISOString()
    const expiresIn = Math.floor(setupToken.ttl / 1000 / 60) // minutes

    console.log("\n" + "=".repeat(70))
    console.log("⚠️  FRESH INSTALLATION - SETUP TOKEN GENERATED")
    console.log("=".repeat(70))
    console.log(`\n🔑 Setup Token (valid for ${expiresIn} minutes):`)
    console.log(`\n   ${setupToken.token}\n`)
    console.log(`📅 Expires at: ${expiresAt}`)
    console.log(`\n💡 Use this token to pair your first client:`)
    console.log(`   curl -X POST http://localhost:${effectivePort}/pair \\`)
    console.log(`     -H "Authorization: Bearer ${setupToken.token}"\n`)
    console.log("⚠️  After pairing your first client, you'll need to set MCP_ADMIN_TOKEN")
    console.log("   for future pairing operations.\n")
    console.log("=".repeat(70) + "\n")

    logger.audit({
      event: "setup_token_generated",
      message: "Setup token generated for fresh installation",
      metadata: {
        expiresAt,
        ttlSeconds: setupToken.ttl / 1000,
        note: "Setup token allows first client pairing without admin token",
      },
    })
  }

  // Ensure TLS certificates if TLS is enabled
  await ensureTlsCertificates()

  // Load tool definitions
  sharedToolDefs = await loadAllTools(DEFINITIONS_DIR)
  logger.info("Tool definitions loaded", {
    metadata: { toolCount: sharedToolDefs.size },
  })

  // Create request handler
  const requestHandler = async (req: http.IncomingMessage, res: http.ServerResponse) => {
    try {
      await handleRequest(req, res)
    } catch (err) {
      logger.error(err instanceof Error ? err : new Error(String(err)), "Request handling failed")
      if (!res.headersSent) {
        jsonResponse(res, 500, { error: "Internal server error" })
      }
    }
  }

  // Create HTTP or HTTPS server based on TLS configuration
  const server = tlsEnabled
    ? https.createServer(
        {
          key: await fs.readFile(tlsKeyPath, "utf-8"),
          cert: await fs.readFile(tlsCertPath, "utf-8"),
        },
        requestHandler,
      )
    : http.createServer(requestHandler)

  const protocol = tlsEnabled ? "https" : "http"

  server.listen(effectivePort, effectiveHost, () => {
    logger.audit({
      event: "server_started",
      message: "Bolt MCP server listening",
      metadata: {
        url: `${protocol}://${effectiveHost}:${effectivePort}`,
        endpoints: {
          mcp: `${protocol}://${effectiveHost}:${effectivePort}/mcp`,
          health: `${protocol}://${effectiveHost}:${effectivePort}/health`,
          pair: `${protocol}://${effectiveHost}:${effectivePort}/pair`,
        },
        auth: `Ed25519 signatures (${authorizedClients.size} clients)`,
        middleware: middlewareEnabled ? "enabled" : "disabled",
        tls: tlsEnabled ? "enabled" : "disabled",
        adminToken: adminToken ? "set" : "NOT SET (pairing disabled)",
      },
    })
  })

  // Graceful shutdown
  const shutdown = async (): Promise<void> => {
    logger.info("Shutting down server")
    clearInterval(cleanupInterval)

    for (const [id, session] of sessions.entries()) {
      session.transport.close().catch(() => {})
      sessions.delete(id)
    }

    server.close(() => {
      logger.audit({
        event: "server_stopped",
        message: "Bolt MCP server closed",
      })
      process.exit(0)
    })

    setTimeout(() => process.exit(1), 5000)
  }

  process.on("SIGINT", () => { shutdown().catch(() => process.exit(1)) })
  process.on("SIGTERM", () => { shutdown().catch(() => process.exit(1)) })
}

main().catch((err) => {
  logger.error(err instanceof Error ? err : new Error(String(err)), "Fatal server error")
  process.exit(1)
})
