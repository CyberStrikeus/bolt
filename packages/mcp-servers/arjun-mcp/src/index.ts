import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn } from 'child_process';

const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: arjun-mcp <arjun binary or python3 arjun>");
    process.exit(1);
}

// Create server instance
const server = new McpServer({
    name: "arjun",
    version: "1.0.0",
});

server.tool(
    "do-arjun",
    "Run Arjun to discover hidden HTTP parameters",
    {
        url: z.string().url().describe("Target URL to scan for hidden parameters"),
        textFile: z.string().optional().describe("Path to file containing multiple URLs"),
        wordlist: z.string().optional().describe("Path to custom wordlist file"),
        method: z.enum(["GET", "POST", "JSON", "HEADERS"]).optional().describe("HTTP method to use for scanning (default: GET)"),
        rateLimit: z.number().optional().describe("Maximum requests per second (default: 9999)"),
        chunkSize: z.number().optional().describe("Chunk size. The number of parameters to be sent at once"),

    },
    async ({ url, textFile, wordlist, method, rateLimit,chunkSize }) => {
        // Build command arguments
        const arjunArgs = []

        if (!url && !textFile) {
            throw new Error("url or textfile parameter required");
        }
        if (url) {
            arjunArgs.push('-u', url);
        }
        if (textFile) {
            arjunArgs.push('-f', textFile);
        }
        if (wordlist) {
            arjunArgs.push('-w', wordlist);
        }
        if (method) {
            arjunArgs.push('-m', method);
        }
        if (rateLimit) {
            arjunArgs.push('--rate-limit', rateLimit.toString());
        }
        if (chunkSize){
            arjunArgs.push('--rate-limit', chunkSize.toString());
        }
        

        const arjun = spawn(args[0], arjunArgs);
        let output = '';
        // Handle stdout
        arjun.stdout.on('data', (data) => {
            output += data.toString();
        });

        // Handle stderr
        arjun.stderr.on('data', (data) => {
            output += data.toString();
        });

        // Handle process completion
        return new Promise((resolve, reject) => {
            arjun.on('close', (code) => {
                if (code === 0) {
                    resolve({
                        content: [{
                            type: "text",
                            text: output
                        }]
                    });
                } else {
                    reject(new Error(`arjun exited with code ${code}`));
                }
            });

            arjun.on('error', (error) => {
                reject(new Error(`Failed to start arjun: ${error.message}`));
            });
        });
    },
);

// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("arjun MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});