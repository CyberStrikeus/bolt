import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import type { ToolDef, McpServerConfig } from "./types.js"

function isHttp(config: McpServerConfig): config is { url: string; headers?: Record<string, string> } {
  return "url" in config
}

export async function loadMcpServers(
  servers: Record<string, McpServerConfig>
): Promise<ToolDef[]> {
  const allTools: ToolDef[] = []

  for (const [serverName, config] of Object.entries(servers)) {
    try {
      const client = new Client({ name: "bolt", version: "1.0.0" })

      let transport
      if (isHttp(config)) {
        const headers = config.headers ?? {}
        transport = new StreamableHTTPClientTransport(new URL(config.url), {
          requestInit: { headers },
        })
      } else {
        const mergedEnv: Record<string, string> = {}
        for (const [k, v] of Object.entries(process.env)) {
          if (v !== undefined) mergedEnv[k] = v
        }
        if (config.env) Object.assign(mergedEnv, config.env)

        transport = new StdioClientTransport({
          command: config.command,
          args: config.args,
          env: mergedEnv,
        })
      }

      await client.connect(transport)
      const { tools } = await client.listTools()

      console.log(`[bolt] mcp:${serverName}: ${tools.length} tool(s)`)

      for (const tool of tools) {
        allTools.push({
          name: `${serverName}_${tool.name}`,
          description: `[${serverName}] ${tool.description ?? ""}`,
          schema: {},
          inputSchema: tool.inputSchema as object,
          execute: async (args) => {
            const result = await client.callTool({ name: tool.name, arguments: args })
            const text = (result.content as any[])
              .filter((c) => c.type === "text")
              .map((c) => c.text)
              .join("\n")
            return { content: [{ type: "text" as const, text }] }
          },
        })
      }
    } catch (err) {
      console.error(`[bolt] failed to connect to mcp server ${serverName}:`, err)
    }
  }

  return allTools
}
