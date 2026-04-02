"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const child_process_1 = require("child_process");
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: gobuster-mcp <gobuster binary>");
    process.exit(1);
}
const binaryPath = args[0];
const server = new mcp_js_1.McpServer({ name: "gobuster", version: "1.0.0" });
function runGobuster(gobusterArgs) {
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(binaryPath, gobusterArgs);
        let output = "";
        proc.stdout.on("data", (d) => { output += d.toString(); });
        proc.stderr.on("data", (d) => { output += d.toString(); });
        proc.on("close", (code) => {
            resolve({ content: [{ type: "text", text: output || `gobuster exited with code ${code}` }] });
        });
        proc.on("error", (error) => reject(new Error(`Failed to start gobuster: ${error.message}`)));
    });
}
// Tool 1: Directory and file brute forcing
server.tool("gobuster_dir", `gobuster MCP server — brute force directories and files on a web server using a wordlist.

Use this tool when you need to:
- Discover hidden paths, admin panels (/admin, /dashboard, /manager), backup files (.bak, .old), config files, or unlinked endpoints on a web server
- Find technology-specific paths (e.g., /wp-admin for WordPress, /phpmyadmin, /.git, /api/v1)
- Enumerate a web application's surface area before vulnerability testing
`, {
    url: zod_1.z.string().describe("Target URL including scheme (e.g., https://example.com or http://10.0.0.1:8080). Must be reachable from the container."),
    wordlist: zod_1.z.string().optional().describe("Absolute path to wordlist file inside the container. Default: /usr/share/seclists/Discovery/Web-Content/common.txt (4.7k entries, fast). If unsure, use the wordlist plugin's tools — wordlist_recommend for purpose-based suggestions, wordlist_search to find technology-specific lists."),
    extensions: zod_1.z.array(zod_1.z.string()).optional().describe("File extensions to append to each wordlist entry (e.g., ['php', 'html', 'txt', 'bak', 'zip']). Do not include dots. Significantly increases scan time but finds more files. Tip: match extensions to the target stack (php for PHP apps, aspx for .NET, jsp for Java)."),
    threads: zod_1.z.number().optional().describe("Concurrent threads (default: 10). Higher = faster but more detectable and may trigger rate limiting. Recommended: 10–50 for stealth, up to 200 for speed on permissive targets."),
    status_codes: zod_1.z.string().optional().describe("Comma-separated HTTP status codes to include in results (default: all non-404). Example: '200,301,302,403'. Use to filter noise or focus on accessible paths."),
    follow_redirect: zod_1.z.boolean().optional().describe("Follow HTTP redirects (default: false). Enable to discover the final destination of 301/302 responses."),
    no_tls_verify: zod_1.z.boolean().optional().describe("Skip TLS certificate verification (default: false). Enable for self-signed certificates or internal targets."),
    proxy: zod_1.z.string().optional().describe("Route requests through a proxy (e.g., http://127.0.0.1:8080 for Burp Suite). Useful for intercepting and inspecting gobuster traffic."),
    cookies: zod_1.z.string().optional().describe("Session cookies for authenticated scanning (e.g., 'PHPSESSID=abc123; auth_token=xyz'). Required to access paths behind a login."),
    headers: zod_1.z.array(zod_1.z.string()).optional().describe("Additional HTTP headers as 'Name: Value' strings (e.g., ['Authorization: Bearer eyJ...', 'X-Custom-Header: value']). Use for API keys, custom auth, or bypassing WAF rules."),
    username: zod_1.z.string().optional().describe("Username for HTTP Basic Authentication (used together with password)."),
    password: zod_1.z.string().optional().describe("Password for HTTP Basic Authentication (used together with username)."),
    add_slash: zod_1.z.boolean().optional().describe("Append a trailing slash to each request (e.g., /admin/). Helps discover directories that only respond to path/ not path."),
    expanded: zod_1.z.boolean().optional().describe("Print full URLs in output instead of relative paths. Useful when scanning multiple targets or sharing results."),
    timeout: zod_1.z.string().optional().describe("Per-request HTTP timeout (e.g., '10s', '30s'). Increase for slow targets, decrease to fail fast on unresponsive hosts."),
    user_agent: zod_1.z.string().optional().describe("Custom User-Agent string. Default is gobuster's own UA. Change to mimic a browser or bypass UA-based WAF rules."),
}, async ({ url, wordlist, extensions, threads, status_codes, follow_redirect, no_tls_verify, proxy, cookies, headers, username, password, add_slash, expanded, timeout, user_agent }) => {
    const gobusterArgs = [
        "dir",
        "-u", url,
        "-w", wordlist ?? "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "--no-progress",
    ];
    if (extensions && extensions.length > 0)
        gobusterArgs.push("-x", extensions.join(","));
    if (threads)
        gobusterArgs.push("-t", threads.toString());
    if (status_codes)
        gobusterArgs.push("-s", status_codes);
    if (follow_redirect)
        gobusterArgs.push("-r");
    if (no_tls_verify)
        gobusterArgs.push("-k");
    if (proxy)
        gobusterArgs.push("--proxy", proxy);
    if (cookies)
        gobusterArgs.push("-c", cookies);
    if (headers)
        headers.forEach((h) => gobusterArgs.push("-H", h));
    if (username)
        gobusterArgs.push("-U", username);
    if (password)
        gobusterArgs.push("-P", password);
    if (add_slash)
        gobusterArgs.push("--add-slash");
    if (expanded)
        gobusterArgs.push("-e");
    if (timeout)
        gobusterArgs.push("--timeout", timeout);
    if (user_agent)
        gobusterArgs.push("-a", user_agent);
    return runGobuster(gobusterArgs);
});
// Tool 2: DNS subdomain brute forcing
server.tool("gobuster_dns", `gobuster MCP server — discover subdomains by brute-forcing DNS with a wordlist.

Use this tool when you need to:
- Find subdomains that passive tools (subfinder, assetfinder, amass) may have missed
- Enumerate internal or recently created subdomains not indexed by certificate transparency
- Validate which subdomains from a wordlist actually resolve

Compared to other subdomain tools:
- subfinder / assetfinder: passive, no DNS brute force — use first for quick results
- shuffledns: faster at scale using massdns — prefer for large wordlists (1M+)
- gobuster_dns: simpler, reliable for small-medium wordlists up to ~100k entries
`, {
    domain: zod_1.z.string().describe("Target apex domain to brute force subdomains against (e.g., example.com). Do not include scheme or www prefix."),
    wordlist: zod_1.z.string().optional().describe("Absolute path to subdomain wordlist inside the container. Default: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt (5k entries, fast). If unsure, use the wordlist plugin's tools — wordlist_recommend for purpose-based suggestions, wordlist_search to find specific lists."),
    threads: zod_1.z.number().optional().describe("Concurrent DNS resolution threads (default: 10). Safe to increase significantly — DNS is lightweight. Recommended: 50–100 for speed."),
    resolver: zod_1.z.string().optional().describe("Custom DNS resolver IP (e.g., 8.8.8.8 for Google, 1.1.1.1 for Cloudflare). Useful when the default resolver returns inaccurate results or for testing against a specific nameserver."),
    show_ips: zod_1.z.boolean().optional().describe("Include resolved IP addresses alongside each discovered subdomain. Useful for quickly identifying cloud-hosted vs on-prem assets."),
    show_cname: zod_1.z.boolean().optional().describe("Show CNAME chain for each result. Useful for detecting subdomain takeover candidates (dangling CNAMEs pointing to unclaimed services)."),
    timeout: zod_1.z.string().optional().describe("DNS query timeout per entry (e.g., '1s', '2s'). Increase for slow or unreliable nameservers."),
    wildcard_forced: zod_1.z.boolean().optional().describe("Continue scanning even when wildcard DNS is detected (default: false). By default gobuster aborts on wildcard to avoid false positives. Enable only if you understand the target has wildcard DNS and want to proceed anyway."),
}, async ({ domain, wordlist, threads, resolver, show_ips, show_cname, timeout, wildcard_forced }) => {
    const gobusterArgs = [
        "dns",
        "-d", domain,
        "-w", wordlist ?? "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "--no-progress",
    ];
    if (threads)
        gobusterArgs.push("-t", threads.toString());
    if (resolver)
        gobusterArgs.push("-r", resolver);
    if (show_ips)
        gobusterArgs.push("-i");
    if (show_cname)
        gobusterArgs.push("--show-cname");
    if (timeout)
        gobusterArgs.push("--timeout", timeout);
    if (wildcard_forced)
        gobusterArgs.push("--wildcard");
    return runGobuster(gobusterArgs);
});
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("gobuster MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
