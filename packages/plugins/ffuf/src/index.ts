import { z } from "zod"
import type { PluginDef, ToolContext, ToolResult } from "@cyberstrike-io/bolt"

const ffuf = {
  name: "ffuf",
  description:
    "ffuf MCP server — fast web fuzzer for directory/file discovery, parameter fuzzing, and vhost enumeration. Use FUZZ as the placeholder in the URL, header, or POST data. Compared to gobuster: ffuf is more flexible (fuzzes any part of the request), gobuster is simpler for pure directory brute force.",
  schema: {
    url: z
      .string()
      .describe("Target URL with FUZZ keyword as the placeholder (e.g. https://example.com/FUZZ for directories, https://example.com/?id=FUZZ for parameters, https://FUZZ.example.com for vhosts)."),
    wordlist: z
      .string()
      .describe("Path to wordlist file (e.g. /usr/share/wordlists/dirb/common.txt). If unsure, use the wordlist plugin's tools — wordlist_recommend for purpose-based suggestions, wordlist_search to find technology-specific lists."),
    method: z
      .enum(["GET", "POST", "PUT", "DELETE", "PATCH"])
      .optional()
      .describe("HTTP method"),
    headers: z
      .string()
      .optional()
      .describe("Custom headers (format: 'Name: Value', comma-separated for multiple)"),
    data: z.string().optional().describe("POST data (use FUZZ keyword for fuzzing)"),
    filter_code: z
      .string()
      .optional()
      .describe("Filter HTTP status codes (e.g. '404,403')"),
    match_code: z
      .string()
      .optional()
      .describe("Match HTTP status codes (e.g. '200,301')"),
    threads: z.number().optional().describe("Number of concurrent threads (default 40)"),
    extra_args: z
      .string()
      .optional()
      .describe("Additional ffuf arguments"),
  },
  timeout: 600,
  execute: async (args: any, ctx: ToolContext): Promise<ToolResult> => {
    const cmd = ["ffuf", "-u", args.url, "-w", args.wordlist, "-noninteractive"]

    if (args.method) cmd.push("-X", args.method)
    if (args.data) cmd.push("-d", args.data)
    if (args.filter_code) cmd.push("-fc", args.filter_code)
    if (args.match_code) cmd.push("-mc", args.match_code)
    if (args.threads) cmd.push("-t", String(args.threads))
    if (args.headers) {
      for (const h of args.headers.split(",")) {
        cmd.push("-H", h.trim())
      }
    }
    if (args.extra_args) {
      cmd.push(...args.extra_args.split(/\s+/).filter(Boolean))
    }

    const r = await ctx.exec(cmd[0], cmd.slice(1))
    return {
      content: [
        {
          type: "text",
          text: r.ok ? r.stdout : `Error (exit ${r.code}):\n${r.stderr}\n${r.stdout}`,
        },
      ],
    }
  },
}

export const plugin: PluginDef = {
  name: "ffuf",
  version: "0.1.0",
  tools: [ffuf],
  check: async () => {
    try {
      const p = Bun.spawn(["ffuf", "-V"], { stdout: "pipe", stderr: "pipe" })
      const out = await new Response(p.stdout).text()
      const ok = (await p.exited) === 0
      const match = out.match(/v?([\d.]+)/)
      return { installed: ok, version: match?.[1] }
    } catch {
      return { installed: false }
    }
  },
}
