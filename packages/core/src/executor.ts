import type { ExecOpts, ExecResult } from "./types.js"

const MAX_OUTPUT = 100 * 1024 // 100KB

export async function exec(
  cmd: string,
  args: string[],
  opts?: ExecOpts,
): Promise<ExecResult> {
  const start = Date.now()
  const command = opts?.sudo ? ["sudo", cmd, ...args] : [cmd, ...args]

  const proc = Bun.spawn(command, {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, TERM: "dumb", LANG: "en_US.UTF-8", ...opts?.env },
    stdin: opts?.stdin ? new Response(opts.stdin) : undefined,
  })

  // Set timeout
  const timeout = (opts?.timeout ?? 300) * 1000
  const timer = setTimeout(() => {
    proc.kill("SIGTERM")
    setTimeout(() => proc.kill("SIGKILL"), 5000)
  }, timeout)

  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])

  clearTimeout(timer)
  const code = await proc.exited

  return {
    ok: code === 0,
    stdout: stdout.length > MAX_OUTPUT ? stdout.slice(0, MAX_OUTPUT) + "\n...(truncated)" : stdout,
    stderr: stderr.length > MAX_OUTPUT ? stderr.slice(0, MAX_OUTPUT) + "\n...(truncated)" : stderr,
    code,
    duration: Date.now() - start,
  }
}

/**
 * Parse command string into parts, respecting quotes
 */
export function parseCommand(command: string): string[] {
  const parts: string[] = []
  let current = ""
  let inQuote = false
  let quoteChar = ""

  for (const char of command) {
    if ((char === '"' || char === "'") && !inQuote) {
      inQuote = true
      quoteChar = char
    } else if (char === quoteChar && inQuote) {
      inQuote = false
      quoteChar = ""
    } else if (char === " " && !inQuote) {
      if (current) {
        parts.push(current)
        current = ""
      }
    } else {
      current += char
    }
  }

  if (current) parts.push(current)
  return parts
}
