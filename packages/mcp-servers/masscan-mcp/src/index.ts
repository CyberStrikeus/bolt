import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn } from 'child_process';

const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: masscan <masscan binary>");
    process.exit(1);
}

// Create server instance
const server = new McpServer({
    name: "masscan",
    version: "1.0.0",
});

server.tool(
    "do-masscan",
    "Run masscan with specified target MASSCAN is a fast port scanner. The primary input parameters are the IP addresses/ranges you want to scan, and the port numbers.",
    {
        target: z.string().describe(`Target information. Example: 1.1.1.1
            1.1.1.1
            `),
        port: z.string().describe(`Target port. Example: 1234
               0-65535
                `),
        masscan_args: z.array(z.string()).describe(`Additional masscan arguments 
            --max-rate 
            `),
    },
    async ({ target, port,masscan_args }) => {
        const masscan = spawn(args[0], ["-p" + port, target, ...masscan_args]);
        let output = '';

        // Handle stdout
        masscan.stdout.on('data', (data) => {
            output += data.toString();
        });

        // Handle stderr
        masscan.stderr.on('data', (data) => {
            output += data.toString();
        });

        // Handle process completion
        return new Promise((resolve, reject) => {
            masscan.on('close', (code) => {
                if (code === 0) {
                    resolve({
                        content: [{
                            type: "text",
                            text: output + "\n masscan completed successfully"
                        }]
                    });
                } else {
                    reject(new Error(`masscan exited with code ${code}`));
                }
            });

            masscan.on('error', (error) => {
                reject(new Error(`Failed to start masscan: ${error.message}`));
            });
        });
    },
);

// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Masscan MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});