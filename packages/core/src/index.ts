#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { loadPlugins, loadConfig } from "./plugin-loader.js"
import { createBoltServer } from "./server.js"

async function main() {
  const config = loadConfig()
  const plugins = await loadPlugins(config)
  const { server } = createBoltServer(plugins)

  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`[bolt] stdio transport connected`)
}

main().catch((err) => {
  console.error("[bolt] Fatal error:", err)
  process.exit(1)
})
