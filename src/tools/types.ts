import { z } from "zod"

/**
 * Parameter types for tool definitions
 */
export const ParameterType = z.enum(["string", "integer", "boolean", "enum", "array"])

/**
 * Enum option with value and description
 */
export const EnumOption = z.union([
  z.string(),
  z.object({
    value: z.string(),
    description: z.string().optional(),
  }),
])

/**
 * Parameter definition
 */
export const ParameterDef = z.object({
  type: ParameterType,
  required: z.boolean().optional().default(false),
  default: z.any().optional(),
  description: z.string(),
  flag: z.string().optional(), // CLI flag (e.g., "-p", "--port")
  options: z.array(EnumOption).optional(), // For enum type
  items: z.object({ type: ParameterType }).optional(), // For array type
})
export type ParameterDef = z.infer<typeof ParameterDef>

/**
 * Tool definition schema (YAML format)
 */
export const ToolDefinition = z.object({
  name: z.string(),
  category: z.string(),
  description: z.string(),
  keywords: z.array(z.string()),
  parameters: z.record(z.string(), ParameterDef),
  command_template: z.string().optional(), // Template for building command
  examples: z.array(z.string()).optional(),
  notes: z.string().optional(),
  requires_root: z.boolean().optional().default(false),
  timeout: z.number().optional().default(300), // Default 5 minutes
  output_parser: z.string().optional(), // Optional parser for structured output
  interactive: z.boolean().optional().default(false), // Interactive/long-running tools run as background jobs
})
export type ToolDefinition = z.infer<typeof ToolDefinition>

/**
 * Minimal tool info for lazy loading (low context cost)
 */
export interface LazyToolInfo {
  name: string
  category: string
  description: string // Short summary
  keywords: string[]
}

/**
 * Tool execution result
 */
export interface ToolResult {
  success: boolean
  output: string
  error?: string
  exitCode?: number
  duration?: number
}

/**
 * Build command from tool definition and parameters
 */
export function buildCommand(tool: ToolDefinition, args: Record<string, unknown>): string {
  // If command_template is provided, use it
  if (tool.command_template) {
    let cmd = tool.command_template

    // Replace {param} and {param?} placeholders
    for (const [key, value] of Object.entries(args)) {
      if (value !== undefined && value !== null && value !== "") {
        cmd = cmd.replace(`{${key}}`, String(value))
        cmd = cmd.replace(`{${key}?}`, String(value))
      } else {
        // Remove optional placeholders
        cmd = cmd.replace(`{${key}?}`, "")
      }
    }

    // Remove unreplaced optional placeholders
    cmd = cmd.replace(/\{[^}]+\?\}/g, "")

    return cmd.replace(/\s+/g, " ").trim()
  }

  // Build command from parameters
  const parts: string[] = [tool.name]

  for (const [key, paramDef] of Object.entries(tool.parameters)) {
    const value = args[key]

    if (value === undefined || value === null || value === "") {
      continue
    }

    if (paramDef.type === "boolean") {
      if (value === true && paramDef.flag) {
        parts.push(paramDef.flag)
      }
    } else if (paramDef.flag) {
      // Flag with value
      if (paramDef.flag.startsWith("--")) {
        parts.push(`${paramDef.flag}=${value}`)
      } else {
        parts.push(paramDef.flag, String(value))
      }
    } else if (key === "target" || paramDef.required) {
      // Positional argument
      parts.push(String(value))
    }
  }

  return parts.join(" ")
}

/**
 * JSON Schema type for MCP tool input
 */
export interface JsonSchema {
  type: "object"
  properties?: Record<string, unknown>
  required?: string[]
}

/**
 * Convert tool definition to JSON Schema for MCP
 */
export function toJsonSchema(tool: ToolDefinition): JsonSchema {
  const properties: Record<string, unknown> = {}
  const required: string[] = []

  for (const [key, param] of Object.entries(tool.parameters)) {
    const prop: Record<string, unknown> = {
      description: param.description,
    }

    switch (param.type) {
      case "string":
        prop.type = "string"
        break
      case "integer":
        prop.type = "integer"
        break
      case "boolean":
        prop.type = "boolean"
        break
      case "enum":
        prop.type = "string"
        if (param.options) {
          prop.enum = param.options.map((o) => (typeof o === "string" ? o : o.value))
        }
        break
      case "array":
        prop.type = "array"
        if (param.items) {
          prop.items = { type: param.items.type }
        }
        break
    }

    if (param.default !== undefined) {
      prop.default = param.default
    }

    properties[key] = prop

    if (param.required) {
      required.push(key)
    }
  }

  const schema: JsonSchema = {
    type: "object",
    properties,
  }

  if (required.length > 0) {
    schema.required = required
  }

  return schema
}
