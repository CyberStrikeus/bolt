import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn } from "child_process";

const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: medusa-mcp <medusa binary>");
    process.exit(1);
}

const binaryPath = args[0];

const server = new McpServer({ name: "medusa", version: "1.0.0" });

server.tool(
    "medusa",
    `medusa MCP server — speedy, massively parallel network login brute forcer.

Use this tool when you need to:
- Brute force multiple hosts simultaneously (medusa excels at multi-host attacks)
- Test the same credentials across many services/targets at once
- Attack SSH, FTP, HTTP, RDP, SMB, Telnet, VNC, and database services

Compared to hydra:
- medusa is better for multi-host attacks (use hosts_file for bulk targeting)
- hydra has broader protocol support including HTTP form attacks
- Both are effective for single-host attacks; prefer medusa when scanning a subnet

Supported modules: ssh, ftp, http, rdp, smb, telnet, vnc, mysql, mssql, postgres, imap, smtp, pop3, smbnt, web-form
`,
    {
        host: z.string().optional().describe("Single target host IP or hostname. Use hosts_file for multiple targets."),
        hosts_file: z.string().optional().describe("Path to file with one target host per line. Medusa scans all hosts in parallel — ideal for subnet-wide attacks."),
        username: z.string().optional().describe("Single username to test (e.g., 'root', 'admin')."),
        username_file: z.string().optional().describe("Path to username list file (e.g., /usr/share/seclists/Usernames/top-usernames-shortlist.txt)."),
        password: z.string().optional().describe("Single password to test."),
        password_file: z.string().optional().describe("Path to password wordlist (e.g., /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt)."),
        module: z.enum([
            "ssh", "ftp", "http", "rdp", "smb", "smbnt", "telnet", "vnc",
            "mysql", "mssql", "postgres", "imap", "smtp", "pop3", "web-form",
        ]).describe("Target service module to use for the attack."),
        port: z.number().optional().describe("Target port if non-default."),
        threads: z.number().optional().describe("Number of parallel login attempts per host (default: 1). Increase to 4-16 for faster attacks."),
        stop_on_success: z.boolean().optional().describe("Stop testing a host once valid credentials are found (default: false)."),
        extra_args: z.array(z.string()).optional().describe("Additional medusa arguments passed directly."),
    },
    async ({ host, hosts_file, username, username_file, password, password_file, module, port, threads, stop_on_success, extra_args }) => {
        const medusaArgs: string[] = [];

        if (host) medusaArgs.push("-h", host);
        else if (hosts_file) medusaArgs.push("-H", hosts_file);

        if (username) medusaArgs.push("-u", username);
        else if (username_file) medusaArgs.push("-U", username_file);

        if (password) medusaArgs.push("-p", password);
        else if (password_file) medusaArgs.push("-P", password_file);

        medusaArgs.push("-M", module);

        if (port) medusaArgs.push("-n", port.toString());
        if (threads) medusaArgs.push("-t", threads.toString());
        if (stop_on_success) medusaArgs.push("-f");
        if (extra_args) medusaArgs.push(...extra_args);

        return new Promise((resolve, reject) => {
            const proc = spawn(binaryPath, medusaArgs);
            let output = "";
            proc.stdout.on("data", (d) => { output += d.toString(); });
            proc.stderr.on("data", (d) => { output += d.toString(); });
            proc.on("close", (code) => {
                resolve({ content: [{ type: "text", text: output || `medusa exited with code ${code}` }] });
            });
            proc.on("error", (error) => reject(new Error(`Failed to start medusa: ${error.message}`)));
        });
    }
);

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("medusa MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
