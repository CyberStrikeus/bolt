import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn } from "child_process";

const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: hydra-mcp <hydra binary>");
    process.exit(1);
}

const binaryPath = args[0];

const server = new McpServer({ name: "hydra", version: "1.0.0" });

server.tool(
    "hydra",
    `hydra MCP server — fast and parallel network login brute forcer supporting 50+ protocols.

Use this tool when you need to:
- Brute force login credentials for network services: SSH, FTP, RDP, SMB, Telnet, VNC, MySQL, MSSQL, PostgreSQL, IMAP, SMTP, POP3
- Test HTTP/HTTPS form-based authentication (login pages, APIs)
- Perform credential stuffing with a username/password list
- Validate default credentials on discovered services

Supported services: ssh, ftp, rdp, smb, telnet, vnc, mysql, mssql, postgres, imap, smtp, pop3, ldap, snmp, http-get, http-post-form, https-post-form, http-head

For HTTP form attacks, http_form_params format is: "/path:user_field=^USER^&pass_field=^PASS^:failure_string"
Example: "/login.php:username=^USER^&password=^PASS^:Login failed"
`,
    {
        target: z.string().describe("Target hostname or IP address (e.g., '192.168.1.1', 'example.com'). For multiple targets, use medusa with hosts_file instead."),
        service: z.enum([
            "ssh", "ftp", "rdp", "smb", "telnet", "vnc",
            "mysql", "mssql", "postgres",
            "imap", "smtp", "pop3", "ldap",
            "http-get", "http-post-form", "https-get", "https-post-form", "http-head",
            "snmp", "sip", "vnc", "teamspeak",
        ]).describe("Target service/protocol to attack."),
        login: z.string().optional().describe("Single username to test (e.g., 'admin', 'root'). Use login_file to test multiple usernames."),
        login_file: z.string().optional().describe("Path to file containing usernames to test, one per line. If unsure, use the wordlist plugin's tools — wordlist_recommend(purpose='username enumeration') for a recommended path, wordlist_search to find specific lists."),
        password: z.string().optional().describe("Single password to test. Use password_file to test a wordlist."),
        password_file: z.string().optional().describe("Path to password wordlist, one per line. If unsure, use the wordlist plugin's tools — wordlist_recommend(purpose='password attack') for a recommended path, wordlist_search to find specific lists."),
        port: z.number().optional().describe("Target port if non-default (e.g., 2222 for SSH on a non-standard port)."),
        threads: z.number().optional().describe("Number of parallel tasks/threads (default: 16). Reduce to 4-8 for rate-limited or unstable services."),
        http_form_params: z.string().optional().describe("Required for http-post-form / https-post-form. Format: '/path:user_param=^USER^&pass_param=^PASS^:failure_indicator'. Example: '/login:user=^USER^&pass=^PASS^:Invalid credentials'"),
        stop_on_success: z.boolean().optional().describe("Stop attack as soon as the first valid credential is found (default: false)."),
        verbose: z.boolean().optional().describe("Show attempted login pairs in output. Useful for debugging but generates a lot of output."),
        extra_args: z.array(z.string()).optional().describe("Additional hydra arguments passed directly (e.g., ['-e', 'nsr'] to also test empty password, login-as-password, and reverse login)."),
    },
    async ({ target, service, login, login_file, password, password_file, port, threads, http_form_params, stop_on_success, verbose, extra_args }) => {
        const hydraArgs: string[] = [];

        if (login) hydraArgs.push("-l", login);
        else if (login_file) hydraArgs.push("-L", login_file);

        if (password) hydraArgs.push("-p", password);
        else if (password_file) hydraArgs.push("-P", password_file);

        if (port) hydraArgs.push("-s", port.toString());
        if (threads) hydraArgs.push("-t", threads.toString());
        if (stop_on_success) hydraArgs.push("-f");
        if (verbose) hydraArgs.push("-V");
        if (extra_args) hydraArgs.push(...extra_args);

        hydraArgs.push(target);

        if (http_form_params) {
            hydraArgs.push(service, http_form_params);
        } else {
            hydraArgs.push(service);
        }

        return new Promise((resolve, reject) => {
            const proc = spawn(binaryPath, hydraArgs);
            let output = "";
            proc.stdout.on("data", (d) => { output += d.toString(); });
            proc.stderr.on("data", (d) => { output += d.toString(); });
            proc.on("close", (code) => {
                resolve({ content: [{ type: "text", text: output || `hydra exited with code ${code}` }] });
            });
            proc.on("error", (error) => reject(new Error(`Failed to start hydra: ${error.message}`)));
        });
    }
);

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("hydra MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
