import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js"
import { zodToJsonSchema } from "./schema.js"
import { exec } from "./executor.js"
import type { ToolDef, ToolContext, PluginDef } from "./types.js"

export function createBoltServer(plugins: PluginDef[]) {
  const allTools = plugins.flatMap((p) => p.tools)
  const toolMap = new Map<string, ToolDef>()
  for (const tool of allTools) {
    toolMap.set(tool.name, tool)
  }

  const server = new Server(
    { name: "bolt", version: "1.0.0" },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: allTools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: zodToJsonSchema(t.schema),
    })),
  }))

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name
    const tool = toolMap.get(name)
    if (!tool) {
      return {
        content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
        isError: true,
      }
    }

    const ctx = buildContext(tool)

    try {
      const result = await tool.execute(request.params.arguments ?? {}, ctx)
      return result
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  })

  return { server, tools: allTools }
}

function buildContext(tool: ToolDef): ToolContext {
  const dataDir = process.env.DATA_DIR ?? "/data"
  return {
    exec: (cmd, args, opts) =>
      exec(cmd, args, {
        ...opts,
        sudo: opts?.sudo ?? tool.requiresRoot,
        timeout: opts?.timeout ?? tool.timeout,
      }),
    workDir: dataDir,
    log: (...args: any[]) => console.log(`[${tool.name}]`, ...args),
  }
}
