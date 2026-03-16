import { z } from "zod"
import type { PluginDef, ToolContext, ToolResult } from "@cyberstrike-io/bolt"

const nuclei = {
  name: "nuclei",
  description:
    "Fast vulnerability scanner using community-powered templates. Scans targets for known CVEs, misconfigurations, and exposures.",
  schema: {
    target: z.string().describe("Target URL or host (e.g. https://example.com)"),
    templates: z
      .string()
      .optional()
      .describe("Template IDs or paths (comma-separated)"),
    tags: z
      .string()
      .optional()
      .describe("Template tags to filter (e.g. 'cve,rce,sqli')"),
    severity: z
      .string()
      .optional()
      .describe("Severity filter (e.g. 'critical,high')"),
    rate_limit: z
      .number()
      .optional()
      .describe("Max requests per second (default 150)"),
    extra_args: z
      .string()
      .optional()
      .describe("Additional nuclei arguments"),
  },
  timeout: 900,
  execute: async (args: any, ctx: ToolContext): Promise<ToolResult> => {
    const cmd = ["nuclei", "-u", args.target, "-silent", "-nc"]

    if (args.templates) cmd.push("-t", args.templates)
    if (args.tags) cmd.push("-tags", args.tags)
    if (args.severity) cmd.push("-severity", args.severity)
    if (args.rate_limit) cmd.push("-rl", String(args.rate_limit))
    if (args.extra_args) {
      cmd.push(...args.extra_args.split(/\s+/).filter(Boolean))
    }

    const r = await ctx.exec(cmd[0], cmd.slice(1))
    if (!r.ok && !r.stdout) {
      return { content: [{ type: "text", text: `Error (exit ${r.code}): ${r.stderr}` }] }
    }

    const lines = r.stdout.trim().split("\n").filter(Boolean)
    const summary = lines.length > 0
      ? `Found ${lines.length} finding(s):\n\n${r.stdout}`
      : "No vulnerabilities found."

    return { content: [{ type: "text", text: summary }] }
  },
}

const nucleiUpdate = {
  name: "nuclei_update_templates",
  description: "Update nuclei templates to the latest version from the community repository.",
  schema: {},
  timeout: 120,
  execute: async (_args: any, ctx: ToolContext): Promise<ToolResult> => {
    const r = await ctx.exec("nuclei", ["-ut", "-silent"])
    return {
      content: [
        {
          type: "text",
          text: r.ok
            ? `Templates updated successfully.\n${r.stdout}`
            : `Update failed: ${r.stderr}`,
        },
      ],
    }
  },
}

export const plugin: PluginDef = {
  name: "nuclei",
  version: "0.1.0",
  tools: [nuclei, nucleiUpdate],
  check: async () => {
    try {
      const p = Bun.spawn(["nuclei", "-version"], { stdout: "pipe", stderr: "pipe" })
      const out = await new Response(p.stderr).text()
      const ok = (await p.exited) === 0
      const match = out.match(/v?([\d.]+)/)
      return { installed: ok, version: match?.[1] }
    } catch {
      return { installed: false }
    }
  },
}
