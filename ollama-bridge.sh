#!/usr/bin/env bash
# Bridge Ollama -> bolt MCP via mcphost.
# Usage:
#   ./ollama-bridge.sh                          # interactive chat with default model
#   ./ollama-bridge.sh -p "scan example.com"    # one-shot prompt
#   MODEL=qwen2.5:7b ./ollama-bridge.sh         # override Ollama model
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL="${MODEL:-qwen2.5:7b-bolt}"
BOLT_CONTAINER="${BOLT_CONTAINER:-bolt}"
BOLT_URL="${BOLT_URL:-http://localhost:3001/mcp}"
SYSTEM_PROMPT="${SYSTEM_PROMPT:-$DIR/prompts/recon-agent.md}"
MAX_STEPS="${MAX_STEPS:-30}"
TEMPERATURE="${TEMPERATURE:-0.2}"

if [ -z "${BOLT_ADMIN_TOKEN:-}" ]; then
  if ! docker ps --format '{{.Names}}' | grep -qx "$BOLT_CONTAINER"; then
    echo "error: bolt container '$BOLT_CONTAINER' not running. start it first." >&2
    exit 1
  fi
  BOLT_ADMIN_TOKEN="$(docker exec "$BOLT_CONTAINER" printenv MCP_ADMIN_TOKEN)"
fi

if ! curl -fsS -o /dev/null "${BOLT_URL%/mcp}/health"; then
  echo "error: bolt health check failed at ${BOLT_URL%/mcp}/health" >&2
  exit 1
fi

if ! curl -fsS http://localhost:11434/api/tags >/dev/null; then
  echo "error: ollama not reachable at http://localhost:11434" >&2
  exit 1
fi

export BOLT_ADMIN_TOKEN BOLT_URL
exec mcphost \
  --config "$DIR/.mcphost.json" \
  --model "ollama:$MODEL" \
  --system-prompt "$SYSTEM_PROMPT" \
  --max-steps "$MAX_STEPS" \
  --temperature "$TEMPERATURE" \
  "$@"
