import type { MiddlewareContext, MiddlewareHandler } from "./types.js"

/**
 * Middleware pipeline for request processing
 * Composes multiple middleware handlers into a single execution flow
 */
export class MiddlewarePipeline {
  private handlers: MiddlewareHandler[] = []

  /**
   * Add a middleware handler to the pipeline
   */
  use(handler: MiddlewareHandler): this {
    this.handlers.push(handler)
    return this
  }

  /**
   * Execute the middleware pipeline
   * @param ctx - Request context
   * @returns Promise that resolves when pipeline completes
   */
  async execute(ctx: MiddlewareContext): Promise<void> {
    let index = 0

    const dispatch = async (): Promise<void> => {
      // If we've reached the end of the pipeline, we're done
      if (index >= this.handlers.length) {
        return
      }

      // Get the next handler and increment index
      const handler = this.handlers[index++]

      // Execute the handler, passing the dispatch function as next()
      // This allows the handler to control when the next middleware runs
      await handler(ctx, dispatch)
    }

    // Start the pipeline execution
    await dispatch()
  }

  /**
   * Compose multiple middleware handlers into a single handler
   * This is useful for creating reusable middleware groups
   */
  static compose(handlers: MiddlewareHandler[]): MiddlewareHandler {
    return async (ctx: MiddlewareContext, next: () => Promise<void>) => {
      let index = 0

      const dispatch = async (): Promise<void> => {
        // If we've executed all handlers in the group, call the outer next()
        if (index >= handlers.length) {
          return next()
        }

        // Get the next handler and increment index
        const handler = handlers[index++]

        // Execute the handler
        await handler(ctx, dispatch)
      }

      // Start execution of the composed handlers
      await dispatch()
    }
  }

  /**
   * Get the number of middleware handlers in the pipeline
   */
  get length(): number {
    return this.handlers.length
  }

  /**
   * Clear all middleware handlers from the pipeline
   */
  clear(): void {
    this.handlers = []
  }
}
