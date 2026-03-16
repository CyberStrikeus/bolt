import { z } from "zod"

/**
 * Convert a Record<string, z.ZodType> to JSON Schema for MCP tool registration
 */
export function zodToJsonSchema(schema: Record<string, z.ZodType>): Record<string, unknown> {
  const properties: Record<string, unknown> = {}
  const required: string[] = []

  for (const [key, zodType] of Object.entries(schema)) {
    properties[key] = zodTypeToJson(key, zodType)
    if (!isOptional(zodType)) {
      required.push(key)
    }
  }

  return {
    type: "object",
    properties,
    required: required.length > 0 ? required : undefined,
    additionalProperties: false,
  }
}

function isOptional(schema: z.ZodType): boolean {
  if (schema instanceof z.ZodOptional) return true
  if (schema instanceof z.ZodDefault) return true
  if (schema instanceof z.ZodNullable) return true
  return false
}

function zodTypeToJson(name: string, schema: z.ZodType): Record<string, unknown> {
  // Unwrap optional/default
  let inner = schema
  if (inner instanceof z.ZodOptional) inner = inner._def.innerType
  if (inner instanceof z.ZodDefault) inner = inner._def.innerType

  const desc = inner._def.description ?? inner.description

  if (inner instanceof z.ZodString) {
    return { type: "string", ...(desc ? { description: desc } : {}) }
  }

  if (inner instanceof z.ZodNumber) {
    return { type: "number", ...(desc ? { description: desc } : {}) }
  }

  if (inner instanceof z.ZodBoolean) {
    return { type: "boolean", ...(desc ? { description: desc } : {}) }
  }

  if (inner instanceof z.ZodEnum) {
    return { type: "string", enum: inner._def.values, ...(desc ? { description: desc } : {}) }
  }

  if (inner instanceof z.ZodArray) {
    return {
      type: "array",
      items: zodTypeToJson("item", inner._def.type),
      ...(desc ? { description: desc } : {}),
    }
  }

  // Fallback
  return { type: "string", ...(desc ? { description: desc } : {}) }
}
