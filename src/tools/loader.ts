import fs from "fs/promises"
import path from "path"
import YAML from "yaml"
import { ToolDefinition, LazyToolInfo } from "./types.js"
import { logger } from "../logging/index.js"

/**
 * Load all tool definitions from the definitions directory
 */
export async function loadAllTools(definitionsDir: string): Promise<Map<string, ToolDefinition>> {
  const tools = new Map<string, ToolDefinition>()

  // Get all category directories
  const categories = await fs.readdir(definitionsDir, { withFileTypes: true })

  for (const category of categories) {
    if (!category.isDirectory()) continue

    const categoryPath = path.join(definitionsDir, category.name)
    const files = await fs.readdir(categoryPath)

    for (const file of files) {
      if (!file.endsWith(".yaml") && !file.endsWith(".yml")) continue

      const filePath = path.join(categoryPath, file)
      const content = await fs.readFile(filePath, "utf-8")

      try {
        const parsed = YAML.parse(content)
        const validated = ToolDefinition.parse(parsed)

        // Use category from directory if not specified
        if (!validated.category) {
          validated.category = category.name
        }

        tools.set(validated.name, validated)
        logger.debug("Tool definition loaded", {
          metadata: { toolName: validated.name, category: validated.category },
        })
      } catch (err) {
        logger.error(
          err instanceof Error ? err : new Error(String(err)),
          `Failed to parse tool definition: ${filePath}`
        )
      }
    }
  }

  logger.info("Tool definitions loaded", {
    metadata: { toolCount: tools.size },
  })
  return tools
}

/**
 * Get lazy tool info (minimal metadata for search)
 */
export function getLazyInfo(tool: ToolDefinition): LazyToolInfo {
  return {
    name: tool.name,
    category: tool.category,
    description: tool.description.slice(0, 100), // Truncate for efficiency
    keywords: tool.keywords,
  }
}

/**
 * Search tools by query
 */
export function searchTools(
  tools: Map<string, ToolDefinition>,
  query: string,
  limit = 10
): LazyToolInfo[] {
  const queryLower = query.toLowerCase()
  const queryWords = queryLower.split(/\s+/)

  const scored: Array<{ info: LazyToolInfo; score: number }> = []

  for (const tool of tools.values()) {
    let score = 0
    const info = getLazyInfo(tool)

    // Exact name match
    if (tool.name.toLowerCase() === queryLower) {
      score += 100
    }

    // Name contains query
    if (tool.name.toLowerCase().includes(queryLower)) {
      score += 50
    }

    // Description contains query
    if (tool.description.toLowerCase().includes(queryLower)) {
      score += 30
    }

    // Keyword matches
    for (const word of queryWords) {
      for (const keyword of tool.keywords) {
        if (keyword.toLowerCase().includes(word) || word.includes(keyword.toLowerCase())) {
          score += 20
        }
      }
    }

    // Category match
    if (tool.category.toLowerCase().includes(queryLower)) {
      score += 25
    }

    if (score > 0) {
      scored.push({ info, score })
    }
  }

  // Sort by score descending
  scored.sort((a, b) => b.score - a.score)

  return scored.slice(0, limit).map((s) => s.info)
}
