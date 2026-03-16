import { ToolDefinition, LazyToolInfo } from "./types.js"
import { logger } from "../logging/index.js"

/**
 * Dynamic Tool Registry
 *
 * Manages tool loading/unloading to minimize context usage.
 * Only loaded tools are exposed to the AI agent.
 *
 * Features:
 * - Dynamic loading/unloading
 * - Usage tracking for auto-unload
 * - Tool recommendations based on co-usage
 */
export class DynamicRegistry {
  // All available tools (full definitions in memory)
  private allTools: Map<string, ToolDefinition> = new Map()

  // Minimal index for searching (low memory footprint)
  private toolIndex: LazyToolInfo[] = []

  // Currently loaded tools (exposed to AI)
  private loadedTools: Set<string> = new Set()

  // Usage tracking for auto-unload
  private lastUsed: Map<string, number> = new Map()
  private useCount: Map<string, number> = new Map()

  // Co-usage tracking for recommendations
  private coUsage: Map<string, Map<string, number>> = new Map()
  private lastLoadedSet: string[] = []

  // Context budget tracking
  private readonly MAX_LOADED_TOOLS = 15
  private readonly ESTIMATED_TOKENS_PER_TOOL = 500
  private readonly AUTO_UNLOAD_AFTER_MS = 10 * 60 * 1000 // 10 minutes

  /**
   * Initialize registry with all tool definitions
   */
  initialize(tools: Map<string, ToolDefinition>): void {
    this.allTools = tools

    // Build minimal index for searching
    this.toolIndex = Array.from(tools.values()).map(tool => ({
      name: tool.name,
      category: tool.category,
      description: tool.description.slice(0, 100),
      keywords: tool.keywords,
    }))

    logger.info("Tool registry initialized", {
      metadata: {
        toolCount: tools.size,
        indexSize: JSON.stringify(this.toolIndex).length,
      },
    })
  }

  /**
   * Search tools by query (searches index, not full definitions)
   */
  search(query: string, limit = 10): LazyToolInfo[] {
    const queryLower = query.toLowerCase()
    const queryWords = queryLower.split(/\s+/)

    const scored: Array<{ info: LazyToolInfo; score: number }> = []

    for (const info of this.toolIndex) {
      let score = 0

      // Exact name match
      if (info.name.toLowerCase() === queryLower) {
        score += 100
      }

      // Name contains query
      if (info.name.toLowerCase().includes(queryLower)) {
        score += 50
      }

      // Description contains query
      if (info.description.toLowerCase().includes(queryLower)) {
        score += 30
      }

      // Keyword matches
      for (const word of queryWords) {
        for (const keyword of info.keywords) {
          if (keyword.toLowerCase().includes(word) || word.includes(keyword.toLowerCase())) {
            score += 20
          }
        }
      }

      // Category match
      if (info.category.toLowerCase().includes(queryLower)) {
        score += 25
      }

      if (score > 0) {
        scored.push({ info, score })
      }
    }

    scored.sort((a, b) => b.score - a.score)
    return scored.slice(0, limit).map(s => s.info)
  }

  /**
   * Load tools into context (makes them available to AI)
   */
  load(toolNames: string[]): { loaded: string[]; failed: string[]; warning?: string } {
    const loaded: string[] = []
    const failed: string[] = []

    for (const name of toolNames) {
      if (this.loadedTools.has(name)) {
        // Already loaded
        loaded.push(name)
        continue
      }

      if (!this.allTools.has(name)) {
        failed.push(name)
        continue
      }

      this.loadedTools.add(name)
      loaded.push(name)
    }

    let warning: string | undefined
    if (this.loadedTools.size > this.MAX_LOADED_TOOLS) {
      warning = `Warning: ${this.loadedTools.size} tools loaded. Consider unloading unused tools to save context.`
    }

    logger.audit({
      event: "tools_loaded",
      message: "Tools loaded into registry",
      metadata: { loaded, failed, totalLoaded: this.loadedTools.size },
    })
    return { loaded, failed, warning }
  }

  /**
   * Unload tools from context (frees context budget)
   */
  unload(toolNames: string[]): { unloaded: string[]; notLoaded: string[] } {
    const unloaded: string[] = []
    const notLoaded: string[] = []

    for (const name of toolNames) {
      if (this.loadedTools.has(name)) {
        this.loadedTools.delete(name)
        unloaded.push(name)
      } else {
        notLoaded.push(name)
      }
    }

    logger.audit({
      event: "tools_unloaded",
      message: "Tools unloaded from registry",
      metadata: { unloaded, notLoaded, remainingLoaded: this.loadedTools.size },
    })
    return { unloaded, notLoaded }
  }

  /**
   * Unload all tools
   */
  unloadAll(): number {
    const count = this.loadedTools.size
    this.loadedTools.clear()
    logger.audit({
      event: "tools_unloaded_all",
      message: "All tools unloaded from registry",
      metadata: { count },
    })
    return count
  }

  /**
   * Get currently loaded tools
   */
  getLoadedTools(): ToolDefinition[] {
    return Array.from(this.loadedTools)
      .map(name => this.allTools.get(name))
      .filter((t): t is ToolDefinition => t !== undefined)
  }

  /**
   * Get loaded tool names
   */
  getLoadedToolNames(): string[] {
    return Array.from(this.loadedTools)
  }

  /**
   * Check if a tool is loaded
   */
  isLoaded(name: string): boolean {
    return this.loadedTools.has(name)
  }

  /**
   * Get a specific tool definition (only if loaded)
   */
  getTool(name: string): ToolDefinition | undefined {
    if (!this.loadedTools.has(name)) {
      return undefined
    }
    return this.allTools.get(name)
  }

  /**
   * Get a tool definition regardless of loaded state (for execution)
   */
  getToolForExecution(name: string): ToolDefinition | undefined {
    return this.allTools.get(name)
  }

  /**
   * Get context usage stats
   */
  getStats(): {
    totalTools: number
    loadedTools: number
    maxTools: number
    estimatedTokens: number
    categories: Record<string, number>
  } {
    const categories: Record<string, number> = {}
    for (const tool of this.allTools.values()) {
      categories[tool.category] = (categories[tool.category] || 0) + 1
    }

    return {
      totalTools: this.allTools.size,
      loadedTools: this.loadedTools.size,
      maxTools: this.MAX_LOADED_TOOLS,
      estimatedTokens: this.loadedTools.size * this.ESTIMATED_TOKENS_PER_TOOL,
      categories,
    }
  }

  /**
   * Get all categories with tool counts
   */
  getCategories(): Array<{ name: string; count: number; tools: string[] }> {
    const categoryMap = new Map<string, string[]>()

    for (const tool of this.allTools.values()) {
      const tools = categoryMap.get(tool.category) || []
      tools.push(tool.name)
      categoryMap.set(tool.category, tools)
    }

    return Array.from(categoryMap.entries())
      .map(([name, tools]) => ({ name, count: tools.length, tools }))
      .sort((a, b) => b.count - a.count)
  }

  // ========== USAGE TRACKING ==========

  /**
   * Record tool usage (call when tool is executed)
   */
  recordUsage(toolName: string): void {
    this.lastUsed.set(toolName, Date.now())
    this.useCount.set(toolName, (this.useCount.get(toolName) || 0) + 1)

    // Track co-usage with other loaded tools
    for (const other of this.loadedTools) {
      if (other !== toolName) {
        if (!this.coUsage.has(toolName)) {
          this.coUsage.set(toolName, new Map())
        }
        const coMap = this.coUsage.get(toolName)!
        coMap.set(other, (coMap.get(other) || 0) + 1)
      }
    }

    logger.debug("Tool usage recorded", {
      metadata: {
        toolName,
        useCount: this.useCount.get(toolName),
        loadedTools: this.loadedTools.size,
      },
    })
  }

  /**
   * Get tools that haven't been used recently
   */
  getStaleTools(): string[] {
    const now = Date.now()
    const stale: string[] = []

    for (const toolName of this.loadedTools) {
      const lastUse = this.lastUsed.get(toolName)
      if (!lastUse || now - lastUse > this.AUTO_UNLOAD_AFTER_MS) {
        stale.push(toolName)
      }
    }

    return stale
  }

  /**
   * Auto-unload stale tools
   */
  autoUnload(): { unloaded: string[]; reason: string } {
    const stale = this.getStaleTools()

    if (stale.length === 0) {
      return { unloaded: [], reason: "No stale tools" }
    }

    // Keep at least the most recently used tools
    const sorted = stale.sort((a, b) => {
      const aTime = this.lastUsed.get(a) || 0
      const bTime = this.lastUsed.get(b) || 0
      return aTime - bTime // Oldest first
    })

    // Unload oldest half if over limit
    if (this.loadedTools.size > this.MAX_LOADED_TOOLS) {
      const toUnload = sorted.slice(0, Math.ceil(sorted.length / 2))
      this.unload(toUnload)
      return {
        unloaded: toUnload,
        reason: `Over limit (${this.loadedTools.size}/${this.MAX_LOADED_TOOLS})`,
      }
    }

    return { unloaded: [], reason: "Under limit" }
  }

  // ========== RECOMMENDATIONS ==========

  /**
   * Get recommended tools based on current context
   */
  getRecommendations(limit = 5): Array<{ name: string; reason: string; score: number }> {
    const recommendations: Array<{ name: string; reason: string; score: number }> = []
    const loadedNames = Array.from(this.loadedTools)

    if (loadedNames.length === 0) {
      // No tools loaded - recommend popular tools
      const popular = Array.from(this.useCount.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit)
        .map(([name, count]) => ({
          name,
          reason: `Used ${count} times`,
          score: count,
        }))

      if (popular.length > 0) return popular

      // No usage history - recommend starter tools
      return [
        { name: "nmap", reason: "Essential port scanner", score: 100 },
        { name: "ffuf", reason: "Fast web fuzzer", score: 90 },
        { name: "sqlmap", reason: "SQL injection tool", score: 85 },
        { name: "subfinder", reason: "Subdomain discovery", score: 80 },
        { name: "nuclei", reason: "Vulnerability scanner", score: 75 },
      ]
    }

    // Find tools commonly used with loaded tools
    const scores = new Map<string, number>()
    const reasons = new Map<string, string>()

    for (const loaded of loadedNames) {
      const coMap = this.coUsage.get(loaded)
      if (coMap) {
        for (const [other, count] of coMap.entries()) {
          if (!this.loadedTools.has(other)) {
            const current = scores.get(other) || 0
            scores.set(other, current + count)
            reasons.set(other, `Often used with ${loaded}`)
          }
        }
      }

      // Also recommend tools from same category
      const tool = this.allTools.get(loaded)
      if (tool) {
        for (const [name, def] of this.allTools.entries()) {
          if (def.category === tool.category && !this.loadedTools.has(name)) {
            const current = scores.get(name) || 0
            scores.set(name, current + 5)
            if (!reasons.has(name)) {
              reasons.set(name, `Same category as ${loaded}`)
            }
          }
        }
      }
    }

    // Sort by score
    const sorted = Array.from(scores.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)

    for (const [name, score] of sorted) {
      recommendations.push({
        name,
        reason: reasons.get(name) || "Recommended",
        score,
      })
    }

    return recommendations
  }

  /**
   * Get usage statistics
   */
  getUsageStats(): {
    mostUsed: Array<{ name: string; count: number }>
    recentlyUsed: Array<{ name: string; ago: string }>
  } {
    const now = Date.now()

    const mostUsed = Array.from(this.useCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, count]) => ({ name, count }))

    const recentlyUsed = Array.from(this.lastUsed.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, time]) => {
        const ago = Math.floor((now - time) / 1000)
        const agoStr =
          ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.floor(ago / 60)}m ago` : `${Math.floor(ago / 3600)}h ago`
        return { name, ago: agoStr }
      })

    return { mostUsed, recentlyUsed }
  }
}
