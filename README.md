# Bolt

Plugin-based security tool server via MCP. Each tool is a plugin — all directly callable in a single LLM turn.

## Quick Start

```bash
# Docker (recommended)
curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh

# Or manually
docker run -d --name bolt -p 3001:3001 \
  -e MCP_ADMIN_TOKEN=$(openssl rand -hex 32) \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v bolt-data:/data \
  ghcr.io/cyberstrikeus/bolt:latest
```

## Architecture

Bolt supports two types of tools: **native plugins** (TypeScript, runs in-process) and **MCP servers** (external processes connected via stdio or HTTP).

```
bolt/
├── packages/
│   ├── core/              # MCP server, plugin loader, mcp-client, executor
│   ├── plugins/           # Native bolt plugins
│   │   ├── subfinder/
│   │   ├── nmap/
│   │   ├── nuclei/
│   │   ├── httpx/
│   │   ├── ffuf/
│   │   └── run-command/
│   └── mcp-servers/       # External MCP servers (stdio, aggregated at runtime)
│       ├── alterx-mcp/
│       ├── amass-mcp/
│       ├── sqlmap-mcp/
│       └── ...            # Add your own here
├── bolt.config.json       # Plugins + mcpServers configuration
├── Dockerfile             # Production: Ubuntu 24.04 + all binaries
├── Dockerfile.dev         # Dev base image (binaries only, no mcp-servers)
├── docker-compose.yml     # Production
└── docker-compose.dev.yml # Development (fast iteration)
```

**Tool loading flow:**

```
bolt.config.json
  ├── plugins[]     → loaded as native TypeScript plugins
  └── mcpServers{}  → each spawned as stdio subprocess, tools aggregated
```

**mcpServers** entries in `bolt.config.json` follow the standard MCP config format:

```json
{
  "mcpServers": {
    "my-tool": {
      "command": "node",
      "args": ["/app/packages/mcp-servers/my-tool/build/index.js", "/usr/local/bin/my-tool"]
    },
    "remote-api": {
      "url": "https://my-mcp-server.com/mcp",
      "headers": { "Authorization": "Bearer xxx" }
    }
  }
}
```

Tool names are automatically namespaced as `{serverName}_{toolName}` to avoid conflicts.

## Tools (32)

| Tool | Category | Type | Description |
|------|----------|------|-------------|
| `subfinder` | Recon & OSINT | Plugin | subfinder MCP server — passive subdomain enumeration via 40+ sources (Shodan, VirusTotal, crt.sh, and more) |
| `assetfinder` | Recon & OSINT | MCP | assetfinder MCP server — fast passive subdomain discovery using certificate transparency and web archives |
| `amass` | Recon & OSINT | MCP | amass MCP server — deep OSINT-driven subdomain enumeration with DNS and scraping techniques |
| `crtsh` | Recon & OSINT | MCP | crt.sh MCP server — certificate transparency log lookup to find subdomains via issued TLS certificates |
| `waybackurls` | Recon & OSINT | MCP | waybackurls MCP server — extract archived URLs from Wayback Machine to surface old endpoints and forgotten parameters |
| `dnsx_resolve` | DNS | MCP | dnsx MCP server — bulk DNS resolution for A, MX, NS, TXT, CNAME, PTR records; infrastructure mapping and DNS takeover detection |
| `alterx` | DNS | MCP | alterx MCP server — subdomain permutation and wordlist generation based on patterns and input domains |
| `shuffledns` | DNS | MCP | shuffledns MCP server — wildcard-aware subdomain bruteforce using massdns for high-speed resolution |
| `nmap` | Port Scanning | Plugin | nmap MCP server — port scanning with service detection, OS fingerprinting, and NSE script support |
| `rustscan` | Port Scanning | MCP | rustscan MCP server — ultra-fast port scanner that discovers all open ports in seconds, then passes results to nmap for service detection |
| `masscan` | Port Scanning | MCP | masscan MCP server — internet-scale TCP port scanning at up to 10 million packets per second |
| `httpx` | Web Discovery | Plugin | httpx MCP server — HTTP probing with status codes, titles, tech fingerprinting, and response analysis |
| `katana` | Web Discovery | MCP | katana MCP server — fast web crawler for endpoint and JavaScript file discovery |
| `ffuf` | Web Discovery | Plugin | ffuf MCP server — directory, file, and virtual host fuzzing with flexible wordlist support |
| `gobuster` | Web Discovery | MCP | gobuster MCP server — directory/file brute force and DNS subdomain enumeration to discover hidden paths, admin panels, and subdomains |
| `arjun` | Web Discovery | MCP | arjun MCP server — hidden HTTP parameter discovery for GET, POST, JSON, and XML endpoints |
| `nuclei` | Vuln Scanning | Plugin | nuclei MCP server — template-based vulnerability scanner for CVEs, misconfigurations, exposed panels, and default credentials |
| `nuclei_update_templates` | Vuln Scanning | Plugin | nuclei MCP server — update nuclei templates to the latest community release |
| `wpscan` | Vuln Scanning | MCP | wpscan MCP server — WordPress vulnerability scanner for plugins, themes, users, and known CVEs |
| `sslscan` | Vuln Scanning | MCP | sslscan MCP server — SSL/TLS analysis for weak ciphers, expired certificates, BEAST, POODLE, and Heartbleed |
| `http_headers_analyze` | Vuln Scanning | MCP | http-headers MCP server — HTTP security headers audit for missing CSP, HSTS, X-Frame-Options, and more |
| `sqlmap` | Exploitation | MCP | sqlmap MCP server — automated SQL injection detection and exploitation with database enumeration |
| `commix` | Exploitation | MCP | commix MCP server — OS command injection testing for web applications |
| `smuggler` | Exploitation | MCP | smuggler MCP server — HTTP request smuggling detection for CL.TE, TE.CL, and TE.TE variants |
| `hydra` | Credential Attacks | MCP | hydra MCP server — fast parallel network login brute forcer for SSH, FTP, RDP, SMB, HTTP forms, and 50+ protocols |
| `medusa` | Credential Attacks | MCP | medusa MCP server — massively parallel network login brute forcer excelling at multi-host attacks across a subnet |
| `kerbrute` | Credential Attacks | MCP | kerbrute MCP server — Active Directory username enumeration and password spraying via Kerberos pre-authentication |
| `hashcat` | Password Cracking | MCP | hashcat MCP server — world's fastest password cracker supporting 300+ hash types with dictionary, mask, and rule-based attacks |
| `john` | Password Cracking | MCP | john MCP server — John the Ripper password cracker with auto hash-type detection for /etc/shadow, Windows SAM, zip files, and SSH keys |
| `cero` | TLS Recon | MCP | cero MCP server — extract subdomains from TLS certificate Subject Alternative Names |
| `scoutsuite` | Cloud Security | MCP | scoutsuite MCP server — multi-cloud security posture audit for AWS, GCP, and Azure |
| `run_command` | Utilities | Plugin | run-command MCP server — execute any shell command inside the container |

## Development

```bash
bun install
bun run dev          # HTTP server on :3001
bun run dev:stdio    # Stdio transport
```

### MCP Server Development with Docker

When adding new MCP servers to `packages/mcp-servers/`, doing a full production Docker build every time is slow. Use the dev workflow instead:

**Step 1 — Build the dev base image (once)**

```bash
docker build -f Dockerfile.dev -t bolt:dev .
```

This installs all binaries (Go tools, Python, Ruby, system tools) and bolt's core. Takes ~10 minutes, but only needs to be done once (or when a new binary is added).

**Step 2 — Start the dev container**

```bash
docker compose -f docker-compose.dev.yml up
```

On every start, the container:
1. Builds all MCP servers in `packages/mcp-servers/` from the mounted volume
2. Starts bolt with all tools loaded

**Step 3 — Add a new MCP server**

```bash
# 1. Add source to packages/mcp-servers/
mkdir -p packages/mcp-servers/my-tool/src

# 2. Add entry to bolt.config.json mcpServers
# 3. Restart — only the new server gets built (~30s)
docker compose -f docker-compose.dev.yml restart
```

`packages/mcp-servers/` and `bolt.config.json` are mounted as volumes — changes on the host are reflected immediately on restart without rebuilding the image.

## Writing Plugins

```typescript
import { z } from "zod"
import type { PluginDef, ToolContext, ToolResult } from "@cyberstrike-io/bolt"

export const plugin: PluginDef = {
  name: "my-tool",
  version: "0.1.0",
  tools: [{
    name: "my_tool",
    description: "Does something useful",
    schema: {
      target: z.string().describe("Target to scan"),
    },
    execute: async (args, ctx) => {
      const r = await ctx.exec("my-tool", [args.target])
      return { content: [{ type: "text", text: r.stdout }] }
    },
  }],
  check: async () => {
    // Return whether the binary is installed
    const p = Bun.spawn(["which", "my-tool"], { stdout: "pipe" })
    return { installed: (await p.exited) === 0 }
  },
}
```

Add to `bolt.config.json`:
```json
{ "plugins": ["@cyberstrike-io/bolt-my-tool"] }
```

## Writing MCP Servers

Any stdio-based MCP server can be added to bolt. Create a new directory under `packages/mcp-servers/`:

```typescript
// packages/mcp-servers/my-tool/src/index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"
import { spawn } from "child_process"

const args = process.argv.slice(2)
const binaryPath = args[0]

const server = new McpServer({ name: "my-tool", version: "1.0.0" })

server.tool(
  "do-my-tool",
  "Description of what this tool does",
  {
    target: z.string().describe("Target to scan"),
  },
  async ({ target }) => {
    const proc = spawn(binaryPath, [target])
    let output = ""
    proc.stdout.on("data", (d) => { output += d.toString() })
    proc.stderr.on("data", (d) => { output += d.toString() })
    return new Promise((resolve) => {
      proc.on("close", () => resolve({
        content: [{ type: "text", text: output }]
      }))
    })
  }
)

const transport = new StdioServerTransport()
await server.connect(transport)
```

```json
// packages/mcp-servers/my-tool/package.json
{
  "name": "my-tool",
  "version": "1.0.0",
  "scripts": { "build": "tsc" },
  "dependencies": { "@modelcontextprotocol/sdk": "^1.26.0", "zod": "^3.22.0" },
  "devDependencies": { "typescript": "^5.0.0", "@types/node": "^22.0.0" }
}
```

Register in `bolt.config.json`:

```json
{
  "mcpServers": {
    "my-tool": {
      "command": "node",
      "args": ["/app/packages/mcp-servers/my-tool/build/index.js", "/usr/local/bin/my-tool"]
    }
  }
}
```

## Security

- Ed25519 client pairing (no shared secrets)
- Middleware pipeline: rate limiting, connection throttling, request validation
- Optional TLS
- All tool executions logged

## License

AGPL-3.0-only
