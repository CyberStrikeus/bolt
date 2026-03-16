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

```
bolt/
├── packages/
│   ├── core/              # MCP server, plugin loader, executor
│   └── plugins/
│       ├── subfinder/     # Passive subdomain enumeration
│       ├── nmap/          # Port scanning + service detection
│       ├── nuclei/        # Vulnerability scanning (templates)
│       ├── httpx/         # HTTP probing + tech detection
│       ├── ffuf/          # Web fuzzing + directory discovery
│       └── run-command/   # Shell command escape hatch
├── bolt.config.json       # Plugin configuration
├── Dockerfile             # Ubuntu 24.04 + Bun + Go tools
└── docker-compose.yml
```

## Tools (7)

| Tool | Plugin | Description |
|------|--------|-------------|
| `subfinder` | subfinder | Passive subdomain enumeration |
| `nmap` | nmap | Port scanning, service/OS detection |
| `nuclei` | nuclei | CVE/misconfig scanning with templates |
| `nuclei_update_templates` | nuclei | Update nuclei templates |
| `httpx` | httpx | HTTP probing, status/title/tech detect |
| `ffuf` | ffuf | Directory/file/vhost fuzzing |
| `run_command` | run-command | Execute any shell command |

## Development

```bash
bun install
bun run dev          # HTTP server on :3001
bun run dev:stdio    # Stdio transport
```

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

## Security

- Ed25519 client pairing (no shared secrets)
- Middleware pipeline: rate limiting, connection throttling, request validation
- Optional TLS
- All tool executions logged

## License

AGPL-3.0-only
