# @cyberstrike/mcp-kali

MCP (Model Context Protocol) server that exposes Kali Linux penetration testing tools to AI agents.

## Overview

This package provides a standardized interface for AI agents to interact with security assessment tools commonly found in Kali Linux distributions. It follows the MCP specification to enable safe and controlled tool execution.

## Installation

```bash
cd packages/mcp-kali
bun install
bun run build
```

## Usage

### As an MCP Server

Add to your `cyberstrike.json`:

```json
{
  "mcp": {
    "kali": {
      "type": "local",
      "command": ["node", "./packages/mcp-kali/dist/index.js"],
      "timeout": 60000
    }
  }
}
```

### Development

```bash
bun run dev
```

## Available Tools

The MCP server exposes various penetration testing tools including:

- Network scanning and enumeration
- Web application testing
- Vulnerability assessment
- Information gathering

## Security Notes

- Tools are executed in a sandboxed environment when possible
- All tool executions are logged for audit purposes
- This package is intended for authorized security testing only

## License

MIT
