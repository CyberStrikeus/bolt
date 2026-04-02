"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const child_process_1 = require("child_process");
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: rustscan-mcp <rustscan binary>");
    process.exit(1);
}
const binaryPath = args[0];
const server = new mcp_js_1.McpServer({ name: "rustscan", version: "1.0.0" });
server.tool("rustscan", `rustscan MCP server — ultra-fast port scanner that discovers open ports in seconds, then automatically passes results to nmap for service/version detection.

Use this tool when you need to:
- Quickly find all open ports on a target before deeper enumeration (rustscan is 100x faster than a full nmap scan)
- Scan large IP ranges or many hosts efficiently
- Get service/version info (nmap runs automatically on discovered ports)

Compared to other port scanners:
- nmap: thorough but slow for full port range — use after rustscan narrows open ports
- masscan: faster at internet scale but no service detection — use for /16 or larger ranges
- rustscan: best for single hosts or small ranges when you want speed + service info in one step

Typical workflow:
1. rustscan(addresses=["10.0.0.1"], ports="1-65535") → finds open ports fast, runs nmap on them
2. Use nmap directly only for advanced scripts/OS detection on already-known ports`, {
    addresses: zod_1.z.array(zod_1.z.string()).describe("Target IP addresses, hostnames, or CIDR ranges to scan (e.g., ['192.168.1.1'], ['10.0.0.0/24'], ['example.com', '10.0.0.1']). Multiple targets supported."),
    ports: zod_1.z.string().optional().describe("Ports or ranges to scan. Examples: '80,443,8080' (specific), '1-1000' (range), '1-65535' (all). Default: top 1000 common ports. Scanning 1-65535 is still fast with rustscan (~3s per host)."),
    batch_size: zod_1.z.number().optional().describe("Number of ports scanned simultaneously per batch (default: 4500). Higher = faster but may cause packet loss on unstable networks. Lower (500–1000) for slow/remote targets."),
    timeout: zod_1.z.number().optional().describe("Milliseconds to wait for a port response before marking it closed (default: 1500ms). Increase to 3000–5000 for high-latency or remote targets to avoid false negatives."),
    tries: zod_1.z.number().optional().describe("Number of times to try each port before giving up (default: 1). Increase to 2–3 for unreliable networks to reduce false negatives."),
    nmap_args: zod_1.z.array(zod_1.z.string()).optional().describe("Extra arguments passed directly to nmap after rustscan discovers open ports (e.g., ['-sV', '-sC'] for service+script scan, ['-A'] for aggressive, ['-sV', '--version-intensity', '9'] for deep version detection). Nmap runs automatically — use this to control what it does."),
    ulimit: zod_1.z.number().optional().describe("Override the system open file descriptor limit for this scan. Set to 5000+ for large scans. Low ulimit is the most common cause of missed ports."),
}, async ({ addresses, ports, batch_size, timeout, tries, nmap_args, ulimit }) => {
    const rustScanArgs = [
        "--addresses", addresses.join(","),
    ];
    if (ports) {
        // rustscan uses --range for start-end format, --ports for comma-separated
        if (ports.includes("-") && !ports.includes(",")) {
            rustScanArgs.push("--range", ports);
        }
        else {
            rustScanArgs.push("--ports", ports);
        }
    }
    if (batch_size)
        rustScanArgs.push("--batch-size", batch_size.toString());
    if (timeout)
        rustScanArgs.push("--timeout", timeout.toString());
    if (tries)
        rustScanArgs.push("--tries", tries.toString());
    if (ulimit)
        rustScanArgs.push("--ulimit", ulimit.toString());
    // Pass extra nmap args after --
    if (nmap_args && nmap_args.length > 0) {
        rustScanArgs.push("--", ...nmap_args);
    }
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(binaryPath, rustScanArgs);
        let output = "";
        proc.stdout.on("data", (d) => { output += d.toString(); });
        proc.stderr.on("data", (d) => { output += d.toString(); });
        proc.on("close", (code) => {
            resolve({ content: [{ type: "text", text: output || `rustscan exited with code ${code}` }] });
        });
        proc.on("error", (error) => reject(new Error(`Failed to start rustscan: ${error.message}`)));
    });
});
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("rustscan MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
