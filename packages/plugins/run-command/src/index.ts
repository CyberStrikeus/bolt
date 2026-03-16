import { z } from "zod"
import { parseCommand } from "@cyberstrike-io/bolt/executor"
import type { PluginDef, ToolContext, ToolResult } from "@cyberstrike-io/bolt"

const runCommand = {
  name: "run_command",
  description:
    "Execute any shell command on the bolt server. Use this as an escape hatch when no dedicated tool exists for the task.",
  schema: {
    command: z.string().describe("Shell command to execute (e.g. 'cat /etc/hosts')"),
    timeout: z.number().optional().describe("Timeout in seconds (default 300)"),
    sudo: z.boolean().optional().describe("Run with sudo"),
  },
  timeout: 300,
  execute: async (args: any, ctx: ToolContext): Promise<ToolResult> => {
    const parts = parseCommand(args.command)
    if (parts.length === 0) {
      return { content: [{ type: "text", text: "Error: empty command" }] }
    }

    const r = await ctx.exec(parts[0], parts.slice(1), {
      timeout: args.timeout,
      sudo: args.sudo,
    })

    const output = [r.stdout, r.stderr].filter(Boolean).join("\n")
    return {
      content: [
        {
          type: "text",
          text: r.ok
            ? output || "(no output)"
            : `Command failed (exit ${r.code}):\n${output}`,
        },
      ],
    }
  },
}

export const plugin: PluginDef = {
  name: "run-command",
  version: "0.1.0",
  tools: [runCommand],
}
