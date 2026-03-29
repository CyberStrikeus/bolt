import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { GetCrtSh } from './crtsh'

const args = process.argv.slice(1);
if (args.length === 0) {
    console.error("Usage: crtsh-mcp");
    process.exit(1);
}

// Create server instance
const server = new McpServer({
    name: "crtsh",
    version: "1.0.0",
});

server.tool(
    "crtsh",
    "Discovers subdomains from SSL certificate logs",
    {
        target: z.string().describe("Target domain to analyze (e.g., example.com)."),
    },
    async ({ target }) => {
        return new Promise((resolve, reject) => {
            GetCrtSh(target)
                .then(async domains => {
                    const resolveData: any = {
                        content: [{
                            type: "text",
                            text: JSON.stringify(domains, null, 2)
                        }]
                    }
                    resolve(resolveData);
                })
                .catch(error => {
                    reject(error);
                });
        });
    }
);

// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("crtsh MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});