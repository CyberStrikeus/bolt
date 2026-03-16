import { z } from "zod"
import type { PluginDef, ToolContext, ToolResult } from "@cyberstrike-io/bolt"

const subfinder = {
  name: "subfinder",
  description:
    "Fast passive subdomain enumeration using multiple sources. Returns discovered subdomains for a target domain.",
  schema: {
    domain: z.string().describe("Target domain (e.g. tesla.com)"),
    sources: z
      .string()
      .optional()
      .describe("Comma-separated data sources (e.g. crtsh,hackertarget)"),
    recursive: z.boolean().optional().describe("Use recursive enumeration"),
    timeout: z.number().optional().describe("Timeout in minutes (default 10)"),
    output_format: z
      .enum(["text", "json"])
      .optional()
      .describe("Output format"),
  },
  timeout: 600,
  execute: async (args: any, ctx: ToolContext): Promise<ToolResult> => {
    const cmd = ["subfinder", "-d", args.domain, "-silent"]
    if (args.sources) cmd.push("-sources", args.sources)
    if (args.recursive) cmd.push("-recursive")
    if (args.timeout) cmd.push("-timeout", String(args.timeout))
    if (args.output_format === "json") cmd.push("-json")

    const r = await ctx.exec(cmd[0], cmd.slice(1))
    if (!r.ok) {
      return { content: [{ type: "text", text: `Error (exit ${r.code}): ${r.stderr}` }] }
    }

    const lines = r.stdout.trim().split("\n").filter(Boolean)
    return {
      content: [
        {
          type: "text",
          text: `Found ${lines.length} subdomain(s) for ${args.domain}:\n\n${r.stdout}`,
        },
      ],
    }
  },
}

export const plugin: PluginDef = {
  name: "subfinder",
  version: "0.1.0",
  tools: [subfinder],
  check: async () => {
    try {
      const p = Bun.spawn(["subfinder", "-version"], {
        stdout: "pipe",
        stderr: "pipe",
      })
      const out = await new Response(p.stderr).text()
      const ok = (await p.exited) === 0
      const match = out.match(/v?([\d.]+)/)
      return { installed: ok, version: match?.[1] }
    } catch {
      return { installed: false }
    }
  },
}
