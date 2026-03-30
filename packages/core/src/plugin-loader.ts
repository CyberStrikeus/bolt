import type { BoltConfig, PluginDef } from "./types.js"
import { readFileSync, existsSync } from "node:fs"
import { join, dirname } from "node:path"

/**
 * Resolve a plugin name to a file path.
 * Handles:
 *   1. Absolute/relative paths (./foo, /bar)
 *   2. Package names — resolves from workspace root
 */
function resolvePlugin(name: string, workspaceRoot: string): string {
  // Direct path
  if (name.startsWith(".") || name.startsWith("/")) {
    return name
  }

  // Try workspace root resolution first (Bun workspace packages)
  try {
    return Bun.resolveSync(name, workspaceRoot)
  } catch {
    // noop
  }

  // Fallback: scan packages/plugins/ for matching package name
  const pluginsDir = join(workspaceRoot, "packages", "plugins")
  if (existsSync(pluginsDir)) {
    const entries = Bun.spawnSync(["ls", pluginsDir]).stdout.toString().trim().split("\n")
    for (const dir of entries) {
      const pkgPath = join(pluginsDir, dir, "package.json")
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"))
        if (pkg.name === name) {
          const main = pkg.main || "src/index.ts"
          return join(pluginsDir, dir, main)
        }
      } catch {
        continue
      }
    }
  }

  // Last resort: bare import (may work in some environments)
  return name
}

/**
 * Find workspace root by walking up until we find root package.json with workspaces field.
 */
function findWorkspaceRoot(): string {
  let dir = process.cwd()
  for (let i = 0; i < 10; i++) {
    const pkgPath = join(dir, "package.json")
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"))
      if (pkg.workspaces) return dir
    } catch {
      // noop
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return process.cwd()
}

export async function loadPlugins(config: BoltConfig): Promise<PluginDef[]> {
  const plugins: PluginDef[] = []
  const workspaceRoot = findWorkspaceRoot()

  for (const name of config.plugins) {
    try {
      const resolved = resolvePlugin(name, workspaceRoot)
      const mod = await import(resolved)
      const plugin: PluginDef = mod.plugin ?? mod.default
      if (!plugin || !plugin.name || !Array.isArray(plugin.tools)) {
        console.error(`[bolt] plugin ${name}: invalid export (missing plugin.name or plugin.tools)`)
        continue
      }

      // Check if tool binaries are available
      if (plugin.check) {
        const status = await plugin.check().catch(() => ({ installed: false }))
        if (!status.installed) {
          console.warn(`[bolt] plugin ${plugin.name}: binary not found, tools may fail at runtime`)
        } else {
          console.log(`[bolt] plugin ${plugin.name}: ${plugin.tools.length} tool(s)${status.version ? ` (${status.version})` : ""}`)
        }
      } else {
        console.log(`[bolt] plugin ${plugin.name}: ${plugin.tools.length} tool(s)`)
      }

      plugins.push(plugin)
    } catch (err) {
      console.error(`[bolt] failed to load plugin ${name}:`, err)
    }
  }

  const totalTools = plugins.reduce((n, p) => n + p.tools.length, 0)
  console.log(`[bolt] loaded ${plugins.length} plugin(s), ${totalTools} tool(s)`)
  return plugins
}

export function loadConfig(path?: string): BoltConfig {
  // Try explicit path, then workspace root, then cwd
  const candidates = path
    ? [path]
    : [
        join(findWorkspaceRoot(), "bolt.config.json"),
        join(process.cwd(), "bolt.config.json"),
      ]

  for (const configPath of candidates) {
    try {
      const raw = JSON.parse(readFileSync(configPath, "utf-8"))
      return {
        port: raw.port ?? 3001,
        plugins: raw.plugins ?? [],
        mcpServers: raw.mcpServers ?? {},
      }
    } catch {
      continue
    }
  }

  return { port: 3001, plugins: [], mcpServers: {} }
}
