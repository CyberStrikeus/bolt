#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import path from "path"
import { fileURLToPath } from "url"
import { loadAllTools } from "./tools/loader.js"
import { DynamicRegistry } from "./tools/registry.js"
import { createMcpServer } from "./server.js"
import { logger } from "./logging/index.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DEFINITIONS_DIR = path.join(__dirname, "..", "src", "definitions")

/**
 * MCP Server for Kali Linux Tools - Stdio Transport
 *
 * Features:
 * - 100+ Kali tools available
 * - Dynamic tool loading to minimize context usage
 * - Only loaded tools consume context budget
 * - Meta-tools for search, load, unload operations
 */

async function main() {
  logger.info("Starting Bolt MCP server (stdio transport)")

  // Load all tool definitions
  const tools = await loadAllTools(DEFINITIONS_DIR)

  // Create a fresh registry instance
  const registry = new DynamicRegistry()
  registry.initialize(tools)

  const stats = registry.getStats()
  logger.info("Tool registry ready", {
    metadata: {
      totalTools: stats.totalTools,
      loadedTools: 0,
      contextSaved: `~${stats.totalTools * 500} tokens`,
    },
  })

  // Create MCP server with the registry
  const server = createMcpServer(registry)

  // Connect via stdio transport
  const transport = new StdioServerTransport()
  await server.connect(transport)

  logger.audit({
    event: "server_started",
    message: "Bolt MCP server ready (stdio)",
  })
}

main().catch((err) => {
  logger.error(err instanceof Error ? err : new Error(String(err)), "Fatal server error (stdio)")
  process.exit(1)
})
