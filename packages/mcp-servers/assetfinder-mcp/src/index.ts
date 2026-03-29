import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
const z = require('zod');
const pty = require('node-pty');
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: assetfinder-mcp <assetfinder binary>");
    process.exit(1);
}

// Create server instance
const server = new McpServer({
    name: "assetfinder",
    version: "1.0.0",
});

server.tool(
    "do-assetfinder",
    "Find related domains and subdomains using assetfinder for a given target.",
    {
        target: z.string().describe("The root domain (e.g., example.com) to discover associated subdomains and related domains."),
    },
    async ({ target }) => {

        const assetfinderArgs = ["-subs-only", target];
        let output = "";
        const assetfinder = pty.spawn(args[0], assetfinderArgs, {
            name: 'xterm-color',
            cols: 80,
            rows: 30,
            cwd: process.cwd(),
            env: process.env
        });

        assetfinder.on('data', function (data: string) {
            output += data.toString();
        });

        // Handle process completion
        return new Promise((resolve, reject) => {
            assetfinder.on('close', function (code: number) {
                if (code === 0 || typeof code === "undefined") {
                    output = removeAnsiCodes(output)
                    const resolveData: any = {
                        content: [{
                            type: "text",
                            text: output
                        }]
                    };
                    resolve(resolveData);
                } else {
                    reject(new Error(`assetfinder exited with code ${code}`));
                }
            });
            assetfinder.on('error', function (error: Error) {
                if (typeof error.cause !== "undefined") {
                    reject(new Error(`Error to start assetfinder: ${error.cause}`));
                }
            });
        });
    },
);

function removeAnsiCodes(input: string): string {
    return input.replace(/\x1B\[[0-9;]*m/g, '');
}

// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("assetfinder MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});