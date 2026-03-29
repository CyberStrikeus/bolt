import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
const { getFindingsFromScoutSuite, extractReportJsPath } = require('./parser');
const z = require('zod');
const pty = require('node-pty');
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: scoutsuite-mcp <scoutsuite binary>");
    process.exit(1);
}

// Create server instance
const server = new McpServer({
    name: "scoutsuite",
    version: "1.0.0",
});

server.tool(
    "do-scoutsuite-aws",
    "Performs an AWS cloud security audit using Scout Suite for the given target settings, allowing service/region filtering and multiple authentication methods.",
    {
        full_report: z.boolean().default(false).optional().describe(""),
        max_workers: z.number().optional().describe("Maximum number of parallel worker threads used by Scout Suite (default: 10)"),
        services: z.array(z.string()).optional().describe("A list of AWS service names to include in scope (default: all services)"),
        skip_services: z.array(z.string()).optional().describe("A list of AWS service names to exclude from scope"),
        profile: z.string().optional().describe("Use a named AWS CLI profile for authentication"),
        acces_keys: z.string().optional().describe("Run using access keys instead of profile (use access_key_id, secret_access_key, and optionally session_token)"),
        access_key_id: z.string().optional().describe("AWS Access Key ID used for authentication"),
        secret_acces_key: z.string().optional().describe("AWS Secret Access Key used for authentication"),
        session_token: z.string().optional().describe("Temporary AWS session token (if using temporary credentials)"),
        regions: z.string().optional().describe("Comma-separated list of AWS regions to include in the scan (default: all regions)"),
        exclude_regions: z.string().optional().describe("Comma-separated list of AWS regions to exclude from the scan"),
        ip_ranges: z.string().optional().describe("Path to JSON file(s) containing known IP ranges to match findings against"),
        ip_ranges_name_key: z.string().optional().describe("Key in the IP ranges file that maps to the display name of a known CIDR")
    },
    async ({ full_report, max_workers, services, skip_services, profile, acces_keys, access_key_id, secret_acces_key, session_token, regions, exclude_regions, ip_ranges, ip_ranges_name_key }) => {

        const scoutSuiteArgs = ["aws", "--force", "--no-browser"];

        if (max_workers) scoutSuiteArgs.push("--max-workers", max_workers.toString());
        if (services?.length) {
            scoutSuiteArgs.push("--services");
            for (var i = 0; i < services.length; i++) {
                scoutSuiteArgs.push(services[i])
            }
        }

        if (skip_services?.length) {
            scoutSuiteArgs.push("--skip");
            for (var i = 0; i < skip_services.length; i++) {
                scoutSuiteArgs.push(skip_services[i])
            }
        }
        if (profile) scoutSuiteArgs.push("--profile", profile);
        if (acces_keys) scoutSuiteArgs.push("--access-keys"); // This is a flag, presence indicates manual credentials
        if (access_key_id) scoutSuiteArgs.push("--access-key-id", access_key_id);
        if (secret_acces_key) scoutSuiteArgs.push("--secret-access-key", secret_acces_key);
        if (session_token) scoutSuiteArgs.push("--session-token", session_token);
        if (regions) scoutSuiteArgs.push("--regions", regions);
        if (exclude_regions) scoutSuiteArgs.push("--exclude-regions", exclude_regions);
        if (ip_ranges) scoutSuiteArgs.push("--ip-ranges", ip_ranges);
        if (ip_ranges_name_key) scoutSuiteArgs.push("--ip-ranges-name-key", ip_ranges_name_key);

        let output = "";


        const scoutSuite = pty.spawn(args[0], scoutSuiteArgs, {
            name: 'xterm-color',
            cols: 80,
            rows: 30,
            cwd: process.cwd(),
            env: process.env
        });

        scoutSuite.on('data', function (data: string) {
            output += data.toString();
        });

        // Handle process completion
        return new Promise((resolve, reject) => {
            scoutSuite.on('close', function (code: number) {
                if (code === 0 || typeof code === "undefined") {
                    let findings = getFindingsFromScoutSuite(extractReportJsPath(output), full_report)

                    const resolveData: any = {
                        content: [{
                            type: "text",
                            text: JSON.stringify(findings, null, 2)
                        }]
                    };
                    resolve(resolveData);
                } else {
                    reject(new Error(`scoutsuite exited with code ${code}`));
                }
            });
            scoutSuite.on('error', function (error: Error) {
                if (typeof error.cause !== "undefined") {
                    reject(new Error(`Error to start scoutsuite: ${error.cause}`));
                }
            });
        });
    },
);

// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("scoutsuite MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});