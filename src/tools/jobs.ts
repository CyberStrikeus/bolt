import { spawn, ChildProcess } from "child_process"
import { ToolDefinition, ToolResult, buildCommand } from "./types.js"
import crypto from "crypto"
import { logger } from "../logging/index.js"

/**
 * Job status enum
 */
export type JobStatus = "running" | "completed" | "failed" | "cancelled"

/**
 * Job information
 */
export interface Job {
  id: string
  toolName: string
  command: string
  status: JobStatus
  startTime: number
  endTime?: number
  exitCode?: number
  output: string
  error?: string
  pid?: number
}

/**
 * Job Manager - handles background execution of long-running/interactive tools
 *
 * Features:
 * - Start tools as background jobs
 * - Query job status
 * - Get job output (with streaming support)
 * - Cancel running jobs
 * - Auto-cleanup of old completed jobs
 */
export class JobManager {
  private jobs: Map<string, Job> = new Map()
  private processes: Map<string, ChildProcess> = new Map()
  private outputBuffers: Map<string, string[]> = new Map()

  // Cleanup jobs older than 1 hour
  private readonly JOB_RETENTION_MS = 60 * 60 * 1000

  // Max output buffer per job (1MB)
  private readonly MAX_OUTPUT_SIZE = 1024 * 1024

  constructor() {
    // Periodic cleanup of old jobs
    setInterval(() => this.cleanup(), 5 * 60 * 1000)
  }

  /**
   * Start a tool as a background job
   */
  async start(
    tool: ToolDefinition,
    args: Record<string, unknown>
  ): Promise<{ jobId: string; message: string }> {
    const command = buildCommand(tool, args)
    const jobId = this.generateJobId()

    logger.audit({
      event: "job_started",
      message: "Background job started",
      metadata: { jobId, toolName: tool.name, command },
    })

    const job: Job = {
      id: jobId,
      toolName: tool.name,
      command,
      status: "running",
      startTime: Date.now(),
      output: "",
    }

    this.jobs.set(jobId, job)
    this.outputBuffers.set(jobId, [])

    // Parse command
    const parts = this.parseCommand(command)
    const [cmd, ...cmdArgs] = parts

    // Determine if we need sudo
    const needsSudo = tool.requires_root && process.getuid?.() !== 0
    const finalCmd = needsSudo ? "sudo" : cmd
    const finalArgs = needsSudo ? [cmd, ...cmdArgs] : cmdArgs

    try {
      const proc = spawn(finalCmd, finalArgs, {
        shell: false,
        detached: true, // Run in background
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          TERM: "dumb",
          LANG: "en_US.UTF-8",
        },
      })

      job.pid = proc.pid
      this.processes.set(jobId, proc)

      // Capture stdout
      proc.stdout?.on("data", (data: Buffer) => {
        this.appendOutput(jobId, data.toString())
      })

      // Capture stderr
      proc.stderr?.on("data", (data: Buffer) => {
        this.appendOutput(jobId, data.toString())
      })

      // Handle process exit
      proc.on("close", (code) => {
        const job = this.jobs.get(jobId)
        if (job && job.status === "running") {
          job.status = code === 0 ? "completed" : "failed"
          job.exitCode = code ?? undefined
          job.endTime = Date.now()
          job.output = this.getFullOutput(jobId)

          if (code !== 0) {
            job.error = `Process exited with code ${code}`
          }

          logger.audit({
            event: code === 0 ? "job_completed" : "job_failed",
            message: `Background job ${job.status}`,
            metadata: {
              jobId,
              exitCode: code,
              duration: job.endTime - job.startTime,
              toolName: job.toolName,
            },
          })
        }
        this.processes.delete(jobId)
      })

      proc.on("error", (err) => {
        const job = this.jobs.get(jobId)
        if (job) {
          job.status = "failed"
          job.error = err.message
          job.endTime = Date.now()
          job.output = this.getFullOutput(jobId)

          logger.error(err, "Background job error")
        }
        this.processes.delete(jobId)
      })

      // Unref to allow parent process to exit independently
      proc.unref()

      return {
        jobId,
        message: `Job started: ${jobId}\nTool: ${tool.name}\nCommand: ${command}\nPID: ${proc.pid}`,
      }
    } catch (err) {
      job.status = "failed"
      job.error = err instanceof Error ? err.message : String(err)
      job.endTime = Date.now()

      return {
        jobId,
        message: `Failed to start job: ${job.error}`,
      }
    }
  }

  /**
   * Get job status
   */
  getStatus(jobId: string): Job | undefined {
    const job = this.jobs.get(jobId)
    if (!job) return undefined

    // Update output for running jobs
    if (job.status === "running") {
      job.output = this.getFullOutput(jobId)
    }

    return { ...job }
  }

  /**
   * Get job output (optionally from a specific offset)
   */
  getOutput(jobId: string, fromLine = 0): { output: string; totalLines: number } | undefined {
    const buffer = this.outputBuffers.get(jobId)
    if (!buffer) {
      const job = this.jobs.get(jobId)
      if (job) {
        const lines = job.output.split("\n")
        return {
          output: lines.slice(fromLine).join("\n"),
          totalLines: lines.length,
        }
      }
      return undefined
    }

    return {
      output: buffer.slice(fromLine).join("\n"),
      totalLines: buffer.length,
    }
  }

  /**
   * Cancel a running job
   */
  cancel(jobId: string): { success: boolean; message: string } {
    const job = this.jobs.get(jobId)
    if (!job) {
      return { success: false, message: `Job ${jobId} not found` }
    }

    if (job.status !== "running") {
      return { success: false, message: `Job ${jobId} is not running (status: ${job.status})` }
    }

    const proc = this.processes.get(jobId)
    if (!proc) {
      return { success: false, message: `Process for job ${jobId} not found` }
    }

    // Try SIGTERM first, then SIGKILL
    proc.kill("SIGTERM")

    setTimeout(() => {
      if (!proc.killed) {
        proc.kill("SIGKILL")
      }
    }, 5000)

    job.status = "cancelled"
    job.endTime = Date.now()
    job.output = this.getFullOutput(jobId)

    logger.audit({
      event: "job_cancelled",
      message: "Background job cancelled",
      metadata: { jobId, toolName: job.toolName },
    })

    return { success: true, message: `Job ${jobId} cancelled` }
  }

  /**
   * List all jobs (optionally filter by status)
   */
  list(status?: JobStatus): Job[] {
    const jobs = Array.from(this.jobs.values())

    if (status) {
      return jobs.filter((j) => j.status === status)
    }

    return jobs.sort((a, b) => b.startTime - a.startTime)
  }

  /**
   * Get running job count
   */
  getRunningCount(): number {
    return this.list("running").length
  }

  // === Private methods ===

  private generateJobId(): string {
    return crypto.randomBytes(4).toString("hex")
  }

  private parseCommand(command: string): string[] {
    const parts: string[] = []
    let current = ""
    let inQuote = false
    let quoteChar = ""

    for (const char of command) {
      if ((char === '"' || char === "'") && !inQuote) {
        inQuote = true
        quoteChar = char
      } else if (char === quoteChar && inQuote) {
        inQuote = false
        quoteChar = ""
      } else if (char === " " && !inQuote) {
        if (current) {
          parts.push(current)
          current = ""
        }
      } else {
        current += char
      }
    }

    if (current) {
      parts.push(current)
    }

    return parts
  }

  private appendOutput(jobId: string, data: string): void {
    const buffer = this.outputBuffers.get(jobId)
    if (!buffer) return

    // Split into lines and append
    const lines = data.split("\n")
    for (const line of lines) {
      if (line) buffer.push(line)
    }

    // Enforce max size (remove oldest lines)
    const totalSize = buffer.join("\n").length
    if (totalSize > this.MAX_OUTPUT_SIZE) {
      const toRemove = Math.ceil(buffer.length * 0.2) // Remove 20%
      buffer.splice(0, toRemove)
    }
  }

  private getFullOutput(jobId: string): string {
    const buffer = this.outputBuffers.get(jobId)
    return buffer ? buffer.join("\n") : ""
  }

  private cleanup(): void {
    const now = Date.now()
    const toDelete: string[] = []

    for (const [jobId, job] of this.jobs.entries()) {
      // Don't cleanup running jobs
      if (job.status === "running") continue

      // Cleanup jobs older than retention period
      if (job.endTime && now - job.endTime > this.JOB_RETENTION_MS) {
        toDelete.push(jobId)
      }
    }

    for (const jobId of toDelete) {
      this.jobs.delete(jobId)
      this.outputBuffers.delete(jobId)
    }

    if (toDelete.length > 0) {
      logger.info("Cleaned up old background jobs", {
        metadata: { count: toDelete.length, jobIds: toDelete },
      })
    }
  }
}

// Singleton instance
export const jobManager = new JobManager()
