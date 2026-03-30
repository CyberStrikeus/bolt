"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const pty = require('node-pty');
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: cero-mcp <cero binary>");
    process.exit(1);
}
// Create server instance
const server = new mcp_js_1.McpServer({
    name: "cero",
    version: "1.0.0",
});
server.tool("do-cero", "Execute Cero, a high-performance certificate-based subdomain enumeration tool. It connects to specified targets over TLS, extracts domain names from certificates (e.g., SAN fields), and outputs discovered hostnames. Useful for reconnaissance and OSINT tasks.", {
    target: zod_1.z.string().describe("The target host or IP address to scan. Can be a single hostname, IPv4/IPv6 address, or a CIDR range (e.g., 192.168.0.0/24)."),
    concurrency: zod_1.z.number().optional().describe("Maximum number of concurrent TLS connections to use during scanning. Higher values increase speed but consume more system resources."),
    ports: zod_1.z.array(zod_1.z.string()).optional().describe("List of TLS ports to scan for certificate information. If omitted, the default port 443 is used. Accepts multiple ports (e.g., ['443', '8443'])."),
    timeOut: zod_1.z.number().optional().describe("Maximum time (in seconds) to wait for a TLS handshake with a target. Used to prevent long delays on unresponsive hosts. Default is 4 seconds.")
}, async ({ target, concurrency, ports, timeOut }) => {
    const ceroArgs = [target];
    if (concurrency) {
        ceroArgs.push("-c", concurrency.toString());
    }
    if (ports && ports.length > 0) {
        ceroArgs.push("-p", ports.join(","));
    }
    if (timeOut) {
        ceroArgs.push("-t", timeOut.toString());
    }
    let output = '';
    const cero = pty.spawn(args[0], ceroArgs, {
        name: 'xterm-color',
        cols: 80,
        rows: 30,
        cwd: process.cwd(),
        env: process.env
    });
    cero.on('data', function (data) {
        output += data.toString();
        console.log(data.toString());
    });
    // Handle process completion
    return new Promise((resolve, reject) => {
        cero.on('close', function (code) {
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
                reject(new Error(`cero exited with code ${code}`));
            }
        });
        cero.on('error', function (error) {
            if (typeof error.cause !== "undefined") {
                reject(new Error(`Error to start cero: ${error.cause}`));
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
    console.error("cero MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
