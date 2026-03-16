import { z } from "zod"
import type { PluginDef, ToolContext, ToolResult } from "@cyberstrike-io/bolt"

const nmap = {
  name: "nmap",
  description:
    "Network port scanner and service detection. Scans target hosts for open ports, running services, and OS fingerprinting.",
  schema: {
    target: z.string().describe("Target host, IP, or CIDR range"),
    ports: z
      .string()
      .optional()
      .describe("Port specification (e.g. '80,443', '1-1000', 'T:80,U:53')"),
    scan_type: z
      .enum(["syn", "connect", "udp", "version", "os"])
      .optional()
      .describe("Scan type: syn (-sS), connect (-sT), udp (-sU), version (-sV), os (-O)"),
    scripts: z
      .string()
      .optional()
      .describe("NSE scripts to run (e.g. 'vuln', 'http-headers')"),
    timing: z
      .enum(["0", "1", "2", "3", "4", "5"])
      .optional()
      .describe("Timing template T0-T5 (paranoid to insane)"),
    extra_args: z
      .string()
      .optional()
      .describe("Additional nmap arguments"),
  },
  timeout: 600,
  requiresRoot: true,
  execute: async (args: any, ctx: ToolContext): Promise<ToolResult> => {
    const cmd = ["nmap"]

    // Scan type
    const scanFlags: Record<string, string> = {
      syn: "-sS",
      connect: "-sT",
      udp: "-sU",
      version: "-sV",
      os: "-O",
    }
    if (args.scan_type) cmd.push(scanFlags[args.scan_type])

    if (args.ports) cmd.push("-p", args.ports)
    if (args.timing) cmd.push(`-T${args.timing}`)
    if (args.scripts) cmd.push("--script", args.scripts)
    if (args.extra_args) {
      cmd.push(...args.extra_args.split(/\s+/).filter(Boolean))
    }

    cmd.push(args.target)

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
  name: "nmap",
  version: "0.1.0",
  tools: [nmap],
  check: async () => {
    try {
      const p = Bun.spawn(["nmap", "--version"], { stdout: "pipe", stderr: "pipe" })
      const out = await new Response(p.stdout).text()
      const ok = (await p.exited) === 0
      const match = out.match(/Nmap version ([\d.]+)/)
      return { installed: ok, version: match?.[1] }
    } catch {
      return { installed: false }
    }
  },
}
