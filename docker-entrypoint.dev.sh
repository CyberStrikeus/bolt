#!/bin/bash
set -e

echo "[dev] Building MCP servers from mounted volume..."

for dir in /app/packages/mcp-servers/*/; do
  [ -f "$dir/package.json" ] || continue
  name=$(basename "$dir")
  echo "[dev] building $name..."
  (cd "$dir" && npm install --include=dev --silent && npm run build --silent) || \
    echo "[dev] WARNING: $name build failed, skipping"
done

echo "[dev] MCP servers ready. Starting bolt..."
exec /entrypoint.sh "$@"
