import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"
import { spawn } from "child_process"

const args = process.argv.slice(2)
if (args.length === 0) {
  console.error("Usage: dnsx-mcp <dnsx-binary>")
  process.exit(1)
}

const binaryPath = args[0]

const RECORD_FLAG: Record<string, string> = {
  A:     "-a",
  AAAA:  "-aaaa",
  MX:    "-mx",
  NS:    "-ns",
  TXT:   "-txt",
  CNAME: "-cname",
  PTR:   "-ptr",
}

const server = new McpServer({ name: "dnsx", version: "1.0.0" })

server.tool(
  "dnsx_resolve",
  "Resolve DNS records for one or more domains using dnsx. " +
  "Use this to find IP addresses, mail servers, name servers, SPF/DKIM records, or CNAME aliases for a domain. " +
  "Useful for recon, infrastructure mapping, and verifying DNS configuration. " +
  "Can process a single domain or a large list (e.g. output from subfinder or amass).",
  {
    targets: z.string().describe(
      "One or more domains to resolve. " +
      "Can be a single domain (e.g. 'tesla.com'), a comma-separated list (e.g. 'tesla.com,spacex.com'), " +
      "or a newline-separated list for bulk resolution (e.g. output from subfinder)."
    ),
    record_types: z
      .array(z.enum(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR"]))
      .optional()
      .describe(
        "DNS record types to query. Defaults to ['A']. " +
        "A: IPv4 address of the domain. " +
        "AAAA: IPv6 address. " +
        "MX: Mail servers — useful for email security research. " +
        "NS: Name servers — useful for DNS takeover and delegation analysis. " +
        "TXT: Text records — contains SPF, DKIM, domain verification tokens. " +
        "CNAME: Canonical name alias — useful for subdomain takeover detection. " +
        "PTR: Reverse DNS — resolves an IP back to a hostname."
      ),
    resolvers: z
      .string()
      .optional()
      .describe(
        "Custom DNS resolver IPs, comma separated. " +
        "Use when default resolvers are rate-limited or you want to test against a specific DNS server. " +
        "Example: '1.1.1.1,8.8.8.8'"
      ),
    json_output: z
      .boolean()
      .optional()
      .describe("Return results in JSON format. Useful when output will be parsed programmatically. Default: false"),
  },
  async ({ targets, record_types, resolvers, json_output }) => {
    const types = record_types && record_types.length > 0 ? record_types : ["A"]

    const domains = targets
      .split(/[\n,]+/)
      .map((d) => d.trim())
      .filter(Boolean)

    if (domains.length === 0) {
      return { content: [{ type: "text", text: "No valid targets provided." }] }
    }

    const cmdArgs: string[] = ["-silent", "-resp"]

    for (const t of types) {
      cmdArgs.push(RECORD_FLAG[t])
    }

    if (resolvers) {
      cmdArgs.push("-r", resolvers)
    }

    if (json_output) {
      cmdArgs.push("-json")
    }

    return new Promise((resolve) => {
      const proc = spawn(binaryPath, cmdArgs)
      let output = ""
      let errOutput = ""

      proc.stdout.on("data", (d) => { output += d.toString() })
      proc.stderr.on("data", (d) => { errOutput += d.toString() })

      proc.stdin.write(domains.join("\n"))
      proc.stdin.end()

      proc.on("close", (code) => {
        if (output.trim()) {
          resolve({ content: [{ type: "text", text: output.trim() }] })
        } else {
          const msg = errOutput.trim() || "No results returned."
          resolve({
            content: [{ type: "text", text: `Exit ${code}: ${msg}` }],
          })
        }
      })

      proc.on("error", (err) => {
        resolve({
          content: [{ type: "text", text: `Failed to start dnsx: ${err.message}` }],
        })
      })
    })
  }
)

const transport = new StdioServerTransport()
await server.connect(transport)
