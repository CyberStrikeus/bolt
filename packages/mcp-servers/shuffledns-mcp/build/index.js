"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const pty = require('node-pty');
const args = process.argv.slice(2);
if (args.length < 2) {
    console.error("Usage: shuffledns-mcp <shuffledns binary> <massdns binary>");
    process.exit(1);
}
// Create server instance
const server = new mcp_js_1.McpServer({
    name: "shuffledns",
    version: "1.0.0",
});
server.tool("shuffledns", "DNS Brute force", {
    target: zod_1.z.string().describe("A list of domain names (e.g., example.com) to scan for HTTP and HTTPS services."),
    resolver: zod_1.z.string().describe("Resolver file path"),
    mode: zod_1.z.enum(["bruteforce", "resolve", "filter"]).describe("Mode"),
    wordlist: zod_1.z.string().describe("wordlist"),
    rateLimit: zod_1.z.number().optional().describe("ratelimit")
}, async ({ target, resolver, mode, wordlist, rateLimit }) => {
    const shufflednsArgs = ["-d", target, "-r", resolver, "-mode", mode, "-w", wordlist, "-m", args[1], "-silent"];
    if (rateLimit) {
        shufflednsArgs.push("-t", rateLimit.toString());
    }
    let output = '';
    const shuffledns = pty.spawn(args[0], shufflednsArgs, {
        name: 'xterm-color',
        cols: 80,
        rows: 30,
        cwd: process.cwd(),
        env: process.env
    });
    shuffledns.on('data', function (data) {
        output += data.toString();
    });
    // Handle process completion
    return new Promise((resolve, reject) => {
        shuffledns.on('close', function (code) {
            if (code === 0 || typeof code === "undefined") {
                output = removeAnsiCodes(output);
                const resolveData = {
                    content: [{
                            type: "text",
                            text: output
                        }]
                };
                resolve(resolveData);
            }
            else {
                reject(new Error(`shuffledns exited with code ${code}`));
            }
        });
        shuffledns.on('error', function (error) {
            if (typeof error.cause !== "undefined") {
                reject(new Error(`Error to start shuffledns: ${error.cause}`));
            }
        });
    });
});
function removeAnsiCodes(input) {
    return input.replace(/\x1B\[[0-9;]*m/g, '');
}
// Start the server
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("shuffledns MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
