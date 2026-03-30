"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const crtsh_1 = require("./crtsh");
const args = process.argv.slice(1);
if (args.length === 0) {
    console.error("Usage: crtsh-mcp");
    process.exit(1);
}
// Create server instance
const server = new mcp_js_1.McpServer({
    name: "crtsh",
    version: "1.0.0",
});
server.tool("crtsh", "Discovers subdomains from SSL certificate logs", {
    target: zod_1.z.string().describe("Target domain to analyze (e.g., example.com)."),
}, async ({ target }) => {
    return new Promise((resolve, reject) => {
        (0, crtsh_1.GetCrtSh)(target)
            .then(async (domains) => {
            const resolveData = {
                content: [{
                        type: "text",
                        text: JSON.stringify(domains, null, 2)
                    }]
            };
            resolve(resolveData);
        })
            .catch(error => {
            reject(error);
        });
    });
});
// Start the server
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("crtsh MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
