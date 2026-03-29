import type { z } from "zod"

export interface ToolDef {
  name: string
  description: string
  schema: Record<string, z.ZodType>
  inputSchema?: object
  execute: (args: any, ctx: ToolContext) => Promise<ToolResult>
  timeout?: number
  requiresRoot?: boolean
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>
}

export interface ToolContext {
  exec: (cmd: string, args: string[], opts?: ExecOpts) => Promise<ExecResult>
  workDir: string
  log: (...args: any[]) => void
}

export interface ExecOpts {
  timeout?: number
  sudo?: boolean
  env?: Record<string, string>
  stdin?: string
}

export interface ExecResult {
  ok: boolean
  stdout: string
  stderr: string
  code: number
  duration: number
}

export interface PluginDef {
  name: string
  version: string
  tools: ToolDef[]
  check?: () => Promise<{ installed: boolean; version?: string }>
  install?: () => Promise<{ ok: boolean; error?: string }>
}

export interface StdioMcpServerConfig {
  command: string
  args?: string[]
  env?: Record<string, string>
}

export interface HttpMcpServerConfig {
  url: string
  headers?: Record<string, string>
}

export type McpServerConfig = StdioMcpServerConfig | HttpMcpServerConfig

export interface BoltConfig {
  port: number
  plugins: string[]
  mcpServers?: Record<string, McpServerConfig>
}

export function text(t: string): ToolResult {
  return { content: [{ type: "text", text: t }] }
}
