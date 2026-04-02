import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn } from "child_process";

const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: kerbrute-mcp <kerbrute binary>");
    process.exit(1);
}

const binaryPath = args[0];

const server = new McpServer({ name: "kerbrute", version: "1.0.0" });

function runKerbrute(kerbruteArgs: string[]): Promise<{ content: Array<{ type: "text"; text: string }> }> {
    return new Promise((resolve, reject) => {
        const proc = spawn(binaryPath, kerbruteArgs);
        let output = "";
        proc.stdout.on("data", (d) => { output += d.toString(); });
        proc.stderr.on("data", (d) => { output += d.toString(); });
        proc.on("close", (code) => {
            resolve({ content: [{ type: "text", text: output || `kerbrute exited with code ${code}` }] });
        });
        proc.on("error", (error) => reject(new Error(`Failed to start kerbrute: ${error.message}`)));
    });
}

// Tool 1: Username enumeration via Kerberos
server.tool(
    "kerbrute_userenum",
    `kerbrute MCP server — enumerate valid Active Directory usernames via Kerberos pre-authentication.

Use this tool when you need to:
- Discover valid usernames in an Active Directory domain without triggering account lockout
- Build a confirmed username list before running password attacks
- Perform reconnaissance against AD environments

This is a low-noise technique — Kerberos AS-REQ enumeration does not trigger logon failure events (Event ID 4625) in most configurations, only 4768 (Kerberos pre-auth).
`,
    {
        dc: z.string().describe("Domain Controller IP or hostname (e.g., '10.0.0.1' or 'dc01.corp.local')."),
        domain: z.string().describe("Active Directory domain name (e.g., 'corp.local', 'company.com')."),
        wordlist: z.string().describe("Path to username wordlist inside the container (e.g., /usr/share/seclists/Usernames/top-usernames-shortlist.txt)."),
        threads: z.number().optional().describe("Number of concurrent Kerberos requests (default: 10). Keep low to avoid detection."),
        output_file: z.string().optional().describe("Save valid usernames to this file path (e.g., /data/valid_users.txt)."),
        safe: z.boolean().optional().describe("Enable safe mode — abort on account lockout detection to avoid locking accounts."),
    },
    async ({ dc, domain, wordlist, threads, output_file, safe }) => {
        const kerbruteArgs = ["userenum", "--dc", dc, "-d", domain, wordlist];
        if (threads) kerbruteArgs.push("--threads", threads.toString());
        if (output_file) kerbruteArgs.push("-o", output_file);
        if (safe) kerbruteArgs.push("--safe");
        return runKerbrute(kerbruteArgs);
    }
);

// Tool 2: Password spray
server.tool(
    "kerbrute_passwordspray",
    `kerbrute MCP server — perform a Kerberos password spray against Active Directory.

Use this tool when you need to:
- Test one password against many users to avoid account lockout (spray, not brute force)
- Find accounts using common/default passwords (Welcome1!, Password1, Season+Year)
- Escalate access after enumerating valid usernames with kerbrute_userenum

Password spraying tests ONE password against ALL users — this avoids lockout policies that trigger after N failed attempts per user.
Always check the domain's lockout threshold before spraying. Recommended: 1 attempt per user per 30 minutes.`,
    {
        dc: z.string().describe("Domain Controller IP or hostname."),
        domain: z.string().describe("Active Directory domain name (e.g., 'corp.local')."),
        users_file: z.string().describe("Path to file with valid usernames to spray (one per line). Use kerbrute_userenum output."),
        password: z.string().describe("Single password to spray against all users (e.g., 'Welcome1!', 'Password123', 'Summer2024!')."),
        threads: z.number().optional().describe("Concurrent requests (default: 10). Keep low to avoid detection and lockouts."),
        output_file: z.string().optional().describe("Save successful credential pairs to this file."),
        safe: z.boolean().optional().describe("Enable safe mode — abort on account lockout detection."),
    },
    async ({ dc, domain, users_file, password, threads, output_file, safe }) => {
        const kerbruteArgs = ["passwordspray", "--dc", dc, "-d", domain, users_file, password];
        if (threads) kerbruteArgs.push("--threads", threads.toString());
        if (output_file) kerbruteArgs.push("-o", output_file);
        if (safe) kerbruteArgs.push("--safe");
        return runKerbrute(kerbruteArgs);
    }
);

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("kerbrute MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
