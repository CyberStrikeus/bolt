import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js"
import { executeTool, validateToolExists } from "./tools/executor.js"
import { toJsonSchema } from "./tools/types.js"
import { DynamicRegistry } from "./tools/registry.js"
import { PRESETS, getPreset, getPresetsByCategory } from "./tools/presets.js"
import { jobManager } from "./tools/jobs.js"
import { logger } from "./logging/index.js"

/**
 * Create a configured MCP Server instance with all handlers registered.
 * Accepts a DynamicRegistry so each session can have its own isolated state.
 */
export function createMcpServer(registry: DynamicRegistry): Server {
  const server = new Server(
    {
      name: "mcp-kali",
      version: "0.2.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  )

  // Handle list tools request
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const mcpTools: Tool[] = []

    // === META-TOOLS (Always Available) ===

    // 1. Search tool
    mcpTools.push({
      name: "kali_search",
      description:
        "Search for Kali Linux tools by capability. Returns tool names and descriptions. Use this FIRST to find tools, then use kali_load to load them.",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "Search query (e.g., 'sql injection', 'port scan', 'password crack', 'subdomain')",
          },
          limit: {
            type: "integer",
            description: "Maximum results (default: 10)",
            default: 10,
          },
        },
        required: ["query"],
      },
    })

    // 2. Load tools
    mcpTools.push({
      name: "kali_load",
      description:
        "Load tools into context to make them available for use. You MUST load a tool before you can use it. Recommend loading max 5-10 tools at a time.",
      inputSchema: {
        type: "object",
        properties: {
          tools: {
            type: "array",
            items: { type: "string" },
            description: "Tool names to load (e.g., ['nmap', 'sqlmap'])",
          },
        },
        required: ["tools"],
      },
    })

    // 3. Unload tools
    mcpTools.push({
      name: "kali_unload",
      description:
        "Unload tools from context to free up context budget. Use when done with a tool.",
      inputSchema: {
        type: "object",
        properties: {
          tools: {
            type: "array",
            items: { type: "string" },
            description: "Tool names to unload (e.g., ['nmap']). Use ['*'] to unload all.",
          },
        },
        required: ["tools"],
      },
    })

    // 4. List loaded tools
    mcpTools.push({
      name: "kali_status",
      description:
        "Show currently loaded tools and context usage statistics.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    })

    // 5. List categories
    mcpTools.push({
      name: "kali_categories",
      description:
        "List all tool categories with tool counts. Useful for exploring available tools.",
      inputSchema: {
        type: "object",
        properties: {
          category: {
            type: "string",
            description: "Optional: show tools in a specific category",
          },
        },
      },
    })

    // 6. Presets - load tool sets for common tasks
    mcpTools.push({
      name: "kali_preset",
      description:
        "Load a pre-defined set of tools for common pentest scenarios. Much faster than loading tools individually. Use 'list' to see available presets.",
      inputSchema: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Preset name (e.g., 'web-scan', 'ad-enum', 'recon-network') or 'list' to see all",
          },
        },
        required: ["name"],
      },
    })

    // 7. Recommendations
    mcpTools.push({
      name: "kali_recommend",
      description:
        "Get tool recommendations based on currently loaded tools and usage patterns.",
      inputSchema: {
        type: "object",
        properties: {
          limit: {
            type: "integer",
            description: "Number of recommendations (default: 5)",
            default: 5,
          },
        },
      },
    })

    // 8. Auto-cleanup
    mcpTools.push({
      name: "kali_cleanup",
      description:
        "Auto-unload tools that haven't been used recently to free context budget.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    })

    // === JOB MANAGEMENT META-TOOLS ===

    // 9. List jobs
    mcpTools.push({
      name: "kali_jobs",
      description:
        "List all background jobs. Interactive tools (metasploit, hashcat, wireshark, etc.) run as background jobs.",
      inputSchema: {
        type: "object",
        properties: {
          status: {
            type: "string",
            enum: ["running", "completed", "failed", "cancelled"],
            description: "Filter by job status (optional)",
          },
        },
      },
    })

    // 10. Job status
    mcpTools.push({
      name: "kali_job_status",
      description:
        "Get detailed status and output of a specific background job.",
      inputSchema: {
        type: "object",
        properties: {
          job_id: {
            type: "string",
            description: "Job ID returned from kali_job_start or interactive tool execution",
          },
        },
        required: ["job_id"],
      },
    })

    // 11. Job output
    mcpTools.push({
      name: "kali_job_output",
      description:
        "Get output from a background job, optionally from a specific line offset for streaming.",
      inputSchema: {
        type: "object",
        properties: {
          job_id: {
            type: "string",
            description: "Job ID",
          },
          from_line: {
            type: "integer",
            description: "Start from this line number (for streaming new output)",
            default: 0,
          },
        },
        required: ["job_id"],
      },
    })

    // 12. Cancel job
    mcpTools.push({
      name: "kali_job_cancel",
      description:
        "Cancel a running background job. Sends SIGTERM, then SIGKILL if needed.",
      inputSchema: {
        type: "object",
        properties: {
          job_id: {
            type: "string",
            description: "Job ID to cancel",
          },
        },
        required: ["job_id"],
      },
    })

    // === LOADED TOOLS (Dynamic) ===
    for (const tool of registry.getLoadedTools()) {
      mcpTools.push({
        name: `kali_${tool.name.replace(/-/g, "_")}`,
        description: tool.description,
        inputSchema: toJsonSchema(tool) as Tool["inputSchema"],
      })
    }

    const loadedCount = registry.getLoadedToolNames().length
    logger.debug("MCP tools list requested", {
      metadata: { totalTools: mcpTools.length, metaTools: 8, loadedTools: loadedCount },
    })

    return { tools: mcpTools }
  })

  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params

    logger.debug("MCP tool call received", {
      metadata: { toolName: name },
    })

    // === META-TOOL: Search ===
    if (name === "kali_search") {
      const query = (args?.query as string) || ""
      const limit = (args?.limit as number) || 10

      const results = registry.search(query, limit)

      if (results.length === 0) {
        return {
          content: [{
            type: "text",
            text: `No tools found for "${query}". Try different keywords like: port scan, sql injection, password, subdomain, wifi, etc.`,
          }],
        }
      }

      const formatted = results
        .map((t, i) => {
          const loaded = registry.isLoaded(t.name) ? " ✓ LOADED" : ""
          return `${i + 1}. **${t.name}**${loaded} (${t.category})\n   ${t.description}`
        })
        .join("\n\n")

      return {
        content: [{
          type: "text",
          text: `Found ${results.length} tools for "${query}":\n\n${formatted}\n\n**Next step:** Use \`kali_load\` to load the tools you need, then use them with \`kali_<tool_name>\``,
        }],
      }
    }

    // === META-TOOL: Load ===
    if (name === "kali_load") {
      const toolNames = (args?.tools as string[]) || []

      if (toolNames.length === 0) {
        return {
          content: [{ type: "text", text: "No tools specified. Provide tool names to load." }],
          isError: true,
        }
      }

      const result = registry.load(toolNames)

      let response = ""
      if (result.loaded.length > 0) {
        response += `✓ Loaded: ${result.loaded.join(", ")}\n`
      }
      if (result.failed.length > 0) {
        response += `✗ Not found: ${result.failed.join(", ")}\n`
      }
      if (result.warning) {
        response += `\n⚠️ ${result.warning}`
      }

      const stats = registry.getStats()
      response += `\n\n**Status:** ${stats.loadedTools}/${stats.maxTools} tools loaded (~${stats.estimatedTokens} tokens)`
      response += `\n\n**Loaded tools can now be used as:** ${result.loaded.map(t => `kali_${t.replace(/-/g, "_")}`).join(", ")}`

      return {
        content: [{ type: "text", text: response }],
      }
    }

    // === META-TOOL: Unload ===
    if (name === "kali_unload") {
      const toolNames = (args?.tools as string[]) || []

      if (toolNames.length === 0) {
        return {
          content: [{ type: "text", text: "No tools specified." }],
          isError: true,
        }
      }

      // Handle unload all
      if (toolNames.includes("*")) {
        const count = registry.unloadAll()
        return {
          content: [{
            type: "text",
            text: `✓ Unloaded all ${count} tools. Context freed: ~${count * 500} tokens`,
          }],
        }
      }

      const result = registry.unload(toolNames)

      let response = ""
      if (result.unloaded.length > 0) {
        response += `✓ Unloaded: ${result.unloaded.join(", ")}\n`
        response += `Context freed: ~${result.unloaded.length * 500} tokens`
      }
      if (result.notLoaded.length > 0) {
        response += `\nNot loaded: ${result.notLoaded.join(", ")}`
      }

      return {
        content: [{ type: "text", text: response }],
      }
    }

    // === META-TOOL: Status ===
    if (name === "kali_status") {
      const stats = registry.getStats()
      const loadedNames = registry.getLoadedToolNames()

      let response = `## Kali Tools Status\n\n`
      response += `**Available:** ${stats.totalTools} tools\n`
      response += `**Loaded:** ${stats.loadedTools}/${stats.maxTools}\n`
      response += `**Context usage:** ~${stats.estimatedTokens} tokens\n\n`

      if (loadedNames.length > 0) {
        response += `**Loaded tools:**\n`
        response += loadedNames.map(n => `- kali_${n.replace(/-/g, "_")}`).join("\n")
      } else {
        response += `_No tools loaded. Use kali_search to find tools, then kali_load to load them._`
      }

      return {
        content: [{ type: "text", text: response }],
      }
    }

    // === META-TOOL: Categories ===
    if (name === "kali_categories") {
      const categoryName = args?.category as string | undefined
      const categories = registry.getCategories()
      const stats = registry.getStats()

      if (categoryName) {
        const category = categories.find(c => c.name.toLowerCase() === categoryName.toLowerCase())
        if (!category) {
          return {
            content: [{
              type: "text",
              text: `Category "${categoryName}" not found. Available: ${categories.map(c => c.name).join(", ")}`,
            }],
            isError: true,
          }
        }

        const toolList = category.tools
          .map(t => {
            const loaded = registry.isLoaded(t) ? " ✓" : ""
            return `- ${t}${loaded}`
          })
          .join("\n")

        return {
          content: [{
            type: "text",
            text: `## ${category.name} (${category.count} tools)\n\n${toolList}\n\n_Use kali_load to load tools_`,
          }],
        }
      }

      const formatted = categories
        .map(c => `- **${c.name}**: ${c.count} tools`)
        .join("\n")

      return {
        content: [{
          type: "text",
          text: `## Available Categories\n\n${formatted}\n\n**Total:** ${stats.totalTools} tools\n\n_Use \`kali_categories\` with a category name to see tools in that category_`,
        }],
      }
    }

    // === META-TOOL: Preset ===
    if (name === "kali_preset") {
      const presetName = (args?.name as string) || ""

      // List all presets
      if (presetName === "list" || presetName === "") {
        const categories = getPresetsByCategory()
        let response = "## Available Presets\n\n"

        for (const [category, presets] of Object.entries(categories)) {
          if (presets.length === 0) continue
          response += `### ${category}\n`
          for (const preset of presets) {
            const key = Object.entries(PRESETS).find(([_, v]) => v === preset)?.[0]
            response += `- **${key}**: ${preset.description} (${preset.tools.length} tools)\n`
          }
          response += "\n"
        }

        response += "\n_Use `kali_preset` with a preset name to load tools_"
        return { content: [{ type: "text", text: response }] }
      }

      // Load specific preset
      const preset = getPreset(presetName)
      if (!preset) {
        const available = Object.keys(PRESETS).join(", ")
        return {
          content: [{
            type: "text",
            text: `Preset "${presetName}" not found.\n\nAvailable: ${available}`,
          }],
          isError: true,
        }
      }

      // Load the preset tools
      const result = registry.load(preset.tools)

      let response = `## ${preset.name}\n\n`
      response += `${preset.description}\n\n`

      if (result.loaded.length > 0) {
        response += `✓ Loaded: ${result.loaded.join(", ")}\n`
      }
      if (result.failed.length > 0) {
        response += `✗ Not found: ${result.failed.join(", ")}\n`
      }

      if (preset.workflow) {
        response += `\n### Recommended Workflow\n\`\`\`\n${preset.workflow}\n\`\`\`\n`
      }

      const stats = registry.getStats()
      response += `\n**Status:** ${stats.loadedTools}/${stats.maxTools} tools loaded`

      return { content: [{ type: "text", text: response }] }
    }

    // === META-TOOL: Recommend ===
    if (name === "kali_recommend") {
      const limit = (args?.limit as number) || 5
      const recommendations = registry.getRecommendations(limit)

      if (recommendations.length === 0) {
        return {
          content: [{
            type: "text",
            text: "No recommendations available. Start by loading some tools with `kali_preset` or `kali_load`.",
          }],
        }
      }

      let response = "## Recommended Tools\n\n"
      response += "Based on your current context and usage patterns:\n\n"

      for (const rec of recommendations) {
        response += `- **${rec.name}** - ${rec.reason}\n`
      }

      response += `\n_Use \`kali_load\` to load recommended tools_`

      return { content: [{ type: "text", text: response }] }
    }

    // === META-TOOL: Cleanup ===
    if (name === "kali_cleanup") {
      const stale = registry.getStaleTools()

      if (stale.length === 0) {
        const stats = registry.getStats()
        return {
          content: [{
            type: "text",
            text: `No stale tools to unload. Currently loaded: ${stats.loadedTools} tools.`,
          }],
        }
      }

      const result = registry.autoUnload()

      if (result.unloaded.length === 0) {
        return {
          content: [{
            type: "text",
            text: `Found ${stale.length} stale tools but kept them (under limit). Stale: ${stale.join(", ")}`,
          }],
        }
      }

      const stats = registry.getStats()
      return {
        content: [{
          type: "text",
          text: `✓ Auto-unloaded ${result.unloaded.length} stale tools: ${result.unloaded.join(", ")}\n\nReason: ${result.reason}\nContext freed: ~${result.unloaded.length * 500} tokens\nNow loaded: ${stats.loadedTools} tools`,
        }],
      }
    }

    // === META-TOOL: List Jobs ===
    if (name === "kali_jobs") {
      const statusFilter = args?.status as "running" | "completed" | "failed" | "cancelled" | undefined
      const jobs = jobManager.list(statusFilter)

      if (jobs.length === 0) {
        return {
          content: [{
            type: "text",
            text: statusFilter
              ? `No ${statusFilter} jobs found.`
              : "No background jobs. Interactive tools like metasploit, hashcat, wireshark run as jobs.",
          }],
        }
      }

      const formatted = jobs.map((job) => {
        const duration = job.endTime
          ? `${((job.endTime - job.startTime) / 1000).toFixed(1)}s`
          : `${((Date.now() - job.startTime) / 1000).toFixed(0)}s (running)`
        const status = job.status === "running" ? "🟢 running" :
                      job.status === "completed" ? "✓ completed" :
                      job.status === "cancelled" ? "⊘ cancelled" : "✗ failed"
        return `**${job.id}** - ${job.toolName} [${status}] (${duration})\n   \`${job.command.slice(0, 60)}${job.command.length > 60 ? "..." : ""}\``
      }).join("\n\n")

      return {
        content: [{
          type: "text",
          text: `## Background Jobs\n\n${formatted}\n\n_Use \`kali_job_status\` or \`kali_job_output\` to see details_`,
        }],
      }
    }

    // === META-TOOL: Job Status ===
    if (name === "kali_job_status") {
      const jobId = args?.job_id as string
      if (!jobId) {
        return {
          content: [{ type: "text", text: "Missing job_id parameter" }],
          isError: true,
        }
      }

      const job = jobManager.getStatus(jobId)
      if (!job) {
        return {
          content: [{ type: "text", text: `Job ${jobId} not found` }],
          isError: true,
        }
      }

      const duration = job.endTime
        ? `${((job.endTime - job.startTime) / 1000).toFixed(1)}s`
        : `${((Date.now() - job.startTime) / 1000).toFixed(0)}s (running)`

      let response = `## Job ${job.id}\n\n`
      response += `**Tool:** ${job.toolName}\n`
      response += `**Status:** ${job.status}\n`
      response += `**Duration:** ${duration}\n`
      response += `**PID:** ${job.pid || "N/A"}\n`
      response += `**Command:** \`${job.command}\`\n`

      if (job.exitCode !== undefined) {
        response += `**Exit Code:** ${job.exitCode}\n`
      }

      if (job.error) {
        response += `\n**Error:** ${job.error}\n`
      }

      // Show last 20 lines of output
      const outputLines = job.output.split("\n")
      const lastLines = outputLines.slice(-20).join("\n")
      if (lastLines) {
        response += `\n### Output (last 20 lines)\n\`\`\`\n${lastLines}\n\`\`\``
      }

      return {
        content: [{ type: "text", text: response }],
      }
    }

    // === META-TOOL: Job Output ===
    if (name === "kali_job_output") {
      const jobId = args?.job_id as string
      const fromLine = (args?.from_line as number) || 0

      if (!jobId) {
        return {
          content: [{ type: "text", text: "Missing job_id parameter" }],
          isError: true,
        }
      }

      const result = jobManager.getOutput(jobId, fromLine)
      if (!result) {
        return {
          content: [{ type: "text", text: `Job ${jobId} not found` }],
          isError: true,
        }
      }

      return {
        content: [{
          type: "text",
          text: `## Job ${jobId} Output (lines ${fromLine}-${result.totalLines})\n\n\`\`\`\n${result.output || "(no new output)"}\n\`\`\`\n\n_Total lines: ${result.totalLines}_`,
        }],
      }
    }

    // === META-TOOL: Cancel Job ===
    if (name === "kali_job_cancel") {
      const jobId = args?.job_id as string
      if (!jobId) {
        return {
          content: [{ type: "text", text: "Missing job_id parameter" }],
          isError: true,
        }
      }

      const result = jobManager.cancel(jobId)

      return {
        content: [{
          type: "text",
          text: result.success ? `✓ ${result.message}` : `✗ ${result.message}`,
        }],
        isError: !result.success,
      }
    }

    // === KALI TOOL EXECUTION ===
    if (name.startsWith("kali_")) {
      const toolName = name.replace("kali_", "").replace(/_/g, "-")

      // Check if tool is loaded
      if (!registry.isLoaded(toolName)) {
        // Try to help the user
        const searchResults = registry.search(toolName, 3)
        const suggestions = searchResults.length > 0
          ? `\n\nDid you mean: ${searchResults.map(t => t.name).join(", ")}?\nUse kali_load to load the tool first.`
          : "\n\nUse kali_search to find tools, then kali_load to load them."

        return {
          content: [{
            type: "text",
            text: `Tool "${toolName}" is not loaded.${suggestions}`,
          }],
          isError: true,
        }
      }

      const tool = registry.getToolForExecution(toolName)
      if (!tool) {
        return {
          content: [{ type: "text", text: `Tool "${toolName}" not found.` }],
          isError: true,
        }
      }

      // Check if tool exists on system
      const exists = await validateToolExists(tool.name)
      if (!exists) {
        return {
          content: [{
            type: "text",
            text: `Tool "${tool.name}" is not installed. Install with: sudo apt install ${tool.name}`,
          }],
          isError: true,
        }
      }

      // Record usage for recommendations
      registry.recordUsage(toolName)

      // Interactive tools run as background jobs
      if (tool.interactive) {
        const jobResult = await jobManager.start(tool, (args as Record<string, unknown>) || {})

        return {
          content: [{
            type: "text",
            text: `## ${tool.name} - Started as Background Job\n\n${jobResult.message}\n\n**This is an interactive/long-running tool.** Use these commands to manage it:\n- \`kali_job_status\` - Check job status and output\n- \`kali_job_output\` - Get streaming output\n- \`kali_job_cancel\` - Stop the job\n- \`kali_jobs\` - List all jobs`,
          }],
        }
      }

      // Execute the tool normally
      const result = await executeTool(tool, (args as Record<string, unknown>) || {})

      const status = result.success ? "✓ Success" : "✗ Failed"
      const duration = result.duration ? ` (${(result.duration / 1000).toFixed(1)}s)` : ""

      return {
        content: [{
          type: "text",
          text: `## ${tool.name} ${status}${duration}\n\n\`\`\`\n${result.output}\n\`\`\`${result.error ? `\n\n**Error:** ${result.error}` : ""}`,
        }],
        isError: !result.success,
      }
    }

    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    }
  })

  return server
}
