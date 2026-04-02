"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const child_process_1 = require("child_process");
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: john-mcp <john binary>");
    process.exit(1);
}
const binaryPath = args[0];
const server = new mcp_js_1.McpServer({ name: "john", version: "1.0.0" });
function runJohn(johnArgs) {
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(binaryPath, johnArgs);
        let output = "";
        proc.stdout.on("data", (d) => { output += d.toString(); });
        proc.stderr.on("data", (d) => { output += d.toString(); });
        proc.on("close", (code) => {
            resolve({ content: [{ type: "text", text: output || `john exited with code ${code}` }] });
        });
        proc.on("error", (error) => reject(new Error(`Failed to start john: ${error.message}`)));
    });
}
// Tool 1: Crack hashes
server.tool("john_crack", `john MCP server — John the Ripper password cracker, versatile hash cracker with auto-detection and built-in rules.

Use this tool when you need to:
- Crack password hashes from /etc/shadow, /etc/passwd, Windows SAM, zip files, SSH keys, and more
- Auto-detect hash format without knowing the type in advance (john does this automatically)
- Use rule-based mangling to extend a wordlist with common password mutations
- Crack formats not well-supported by hashcat in CPU mode

John excels at:
- Auto-detecting hash type (no need to specify -m like hashcat)
- Cracking /etc/shadow directly (run john /etc/shadow)
- Cracking protected files: zip2john, ssh2john, pdf2john convert files to crackable format
- Incremental mode — tries all combinations up to a length

Compared to hashcat:
- John: better auto-detection, easier for beginners, good CPU performance
- hashcat: faster with GPU, more attack modes, better for large hash sets

Common formats: auto (default), md5crypt, sha512crypt, bcrypt, nt, lm, raw-md5, raw-sha1, raw-sha256, zip, ssh`, {
    hash_file: zod_1.z.string().describe("Path to hash file to crack. Can be /etc/shadow directly, or output from *2john tools (zip2john, ssh2john, pdf2john, etc.)."),
    wordlist: zod_1.z.string().optional().describe("Path to wordlist for dictionary attack (e.g., /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt). If omitted, John uses incremental mode."),
    format: zod_1.z.string().optional().describe("Force a specific hash format (e.g., 'md5crypt', 'sha512crypt', 'bcrypt', 'nt', 'raw-md5', 'zip', 'ssh'). Leave empty for auto-detection."),
    rules: zod_1.z.string().optional().describe("Rule set name to apply to wordlist entries (e.g., 'best64', 'jumbo', 'KoreLogic'). Rules mutate passwords: append numbers, l33tspeak, capitalize, etc."),
    incremental: zod_1.z.boolean().optional().describe("Use incremental (brute force) mode instead of wordlist. Tries all character combinations up to a length. Slow but thorough."),
    extra_args: zod_1.z.array(zod_1.z.string()).optional().describe("Additional john arguments (e.g., ['--min-length=8', '--max-length=12'])."),
}, async ({ hash_file, wordlist, format, rules, incremental, extra_args }) => {
    const johnArgs = [];
    if (wordlist)
        johnArgs.push(`--wordlist=${wordlist}`);
    if (format)
        johnArgs.push(`--format=${format}`);
    if (rules)
        johnArgs.push(`--rules=${rules}`);
    if (incremental)
        johnArgs.push("--incremental");
    if (extra_args)
        johnArgs.push(...extra_args);
    johnArgs.push(hash_file);
    return runJohn(johnArgs);
});
// Tool 2: Show cracked passwords
server.tool("john_show", `john MCP server — display previously cracked passwords for a hash file.

Use this tool when you need to:
- Retrieve cracked plaintext passwords after a john_crack session completes
- John stores cracked results in ~/.john/john.pot — this tool reads from it
- Always run john_show after john_crack to see the plaintext passwords

Note: john_crack output alone may not show plaintext. Always follow up with john_show.`, {
    hash_file: zod_1.z.string().describe("Path to the hash file that was cracked (e.g., /data/hashes.txt or /etc/shadow)."),
    format: zod_1.z.string().optional().describe("Hash format if needed to disambiguate (e.g., 'nt', 'md5crypt'). Usually not required."),
}, async ({ hash_file, format }) => {
    const johnArgs = ["--show"];
    if (format)
        johnArgs.push(`--format=${format}`);
    johnArgs.push(hash_file);
    return runJohn(johnArgs);
});
// Tool 3: List supported formats
server.tool("john_list_formats", "john MCP server — list all hash formats supported by John the Ripper. Use to find the correct format name for john_crack.", {}, async () => {
    return runJohn(["--list=formats"]);
});
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("john MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
