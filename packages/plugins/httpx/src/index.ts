import { z } from "zod"
import type { PluginDef, ToolContext, ToolResult } from "@cyberstrike-io/bolt"

const httpx = {
  name: "httpx",
  description:
    "Fast HTTP toolkit for probing web servers. Checks status codes, titles, tech stack, and takes screenshots.",
  schema: {
    targets: z
      .string()
      .describe("Target URL(s) or domain(s), one per line or comma-separated"),
    status_code: z.boolean().optional().describe("Show HTTP status codes"),
    title: z.boolean().optional().describe("Show page titles"),
    tech_detect: z.boolean().optional().describe("Detect technologies (Wappalyzer)"),
    follow_redirects: z.boolean().optional().describe("Follow HTTP redirects"),
    threads: z.number().optional().describe("Number of concurrent threads"),
    extra_args: z
      .string()
      .optional()
      .describe("Additional httpx arguments"),
  },
  timeout: 300,
  execute: async (args: any, ctx: ToolContext): Promise<ToolResult> => {
    const cmd = ["httpx", "-silent"]

    if (args.status_code) cmd.push("-sc")
    if (args.title) cmd.push("-title")
    if (args.tech_detect) cmd.push("-td")
    if (args.follow_redirects) cmd.push("-fr")
    if (args.threads) cmd.push("-threads", String(args.threads))
    if (args.extra_args) {
      cmd.push(...args.extra_args.split(/\s+/).filter(Boolean))
    }

    // httpx reads targets from stdin
    const targets = args.targets.includes(",")
      ? args.targets.split(",").map((t: string) => t.trim()).join("\n")
      : args.targets

    const r = await ctx.exec(cmd[0], cmd.slice(1), { stdin: targets })
    if (!r.ok && !r.stdout) {
      return { content: [{ type: "text", text: `Error (exit ${r.code}): ${r.stderr}` }] }
    }

    const lines = r.stdout.trim().split("\n").filter(Boolean)
    return {
      content: [
        {
          type: "text",
          text: `Probed ${lines.length} host(s):\n\n${r.stdout}`,
        },
      ],
    }
  },
}

export const plugin: PluginDef = {
  name: "httpx",
  version: "0.1.0",
  tools: [httpx],
  check: async () => {
    try {
      const p = Bun.spawn(["httpx", "-version"], { stdout: "pipe", stderr: "pipe" })
      const out = await new Response(p.stderr).text()
      const ok = (await p.exited) === 0
      const match = out.match(/v?([\d.]+)/)
      return { installed: ok, version: match?.[1] }
    } catch {
      return { installed: false }
    }
  },
}
