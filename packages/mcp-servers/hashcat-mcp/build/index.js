"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const child_process_1 = require("child_process");
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: hashcat-mcp <hashcat binary>");
    process.exit(1);
}
const binaryPath = args[0];
const server = new mcp_js_1.McpServer({ name: "hashcat", version: "1.0.0" });
function runHashcat(hashcatArgs) {
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(binaryPath, hashcatArgs);
        let output = "";
        proc.stdout.on("data", (d) => { output += d.toString(); });
        proc.stderr.on("data", (d) => { output += d.toString(); });
        proc.on("close", (code) => {
            resolve({ content: [{ type: "text", text: output || `hashcat exited with code ${code}` }] });
        });
        proc.on("error", (error) => reject(new Error(`Failed to start hashcat: ${error.message}`)));
    });
}
// Tool 1: Crack hashes
server.tool("hashcat_crack", `hashcat MCP server — world's fastest password cracker supporting 300+ hash types.

Use this tool when you need to:
- Crack captured password hashes (from database dumps, /etc/shadow, NTLM captures, WPA handshakes)
- Perform dictionary, combinator, mask (brute force), or rule-based attacks
- Crack MD5, SHA1, SHA256, bcrypt, NTLM, NetNTLMv2, WPA2, and hundreds more

Common hash type codes (-m):
- 0     = MD5
- 100   = SHA1
- 1400  = SHA256
- 1800  = sha512crypt ($6$) — Linux shadow passwords
- 3200  = bcrypt — web app passwords
- 1000  = NTLM — Windows passwords
- 5600  = NetNTLMv2 — captured with Responder
- 2500  = WPA/WPA2 handshake
- 13100 = Kerberoast (TGS-REP)
- 18200 = AS-REP Roast

Attack modes (-a):
- 0 = Dictionary attack (wordlist) — fastest, use first
- 1 = Combinator (wordlist1 + wordlist2)
- 3 = Mask/Brute force (e.g., ?u?l?l?l?d?d for UpperLower x4 + 2 digits)
- 6 = Hybrid wordlist + mask
- 7 = Hybrid mask + wordlist

Note: GPU acceleration is not available in Docker without --gpus flag. CPU cracking is slower but functional.`, {
    hash_file: zod_1.z.string().describe("Path to file containing hashes to crack, one per line (e.g., /data/hashes.txt). Supports single hash values too — just put the hash in the file."),
    hash_type: zod_1.z.number().describe("Hash type code (-m). Common: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt, 5600=NetNTLMv2, 13100=Kerberoast, 18200=AS-REP. Use hashcat --help for full list."),
    attack_mode: zod_1.z.enum(["dictionary", "brute-force", "combinator", "hybrid-wordlist-mask", "hybrid-mask-wordlist"]).describe("Attack mode: dictionary (wordlist), brute-force (mask pattern), combinator (two wordlists), or hybrid variants."),
    wordlist: zod_1.z.string().optional().describe("Path to wordlist for dictionary/hybrid attacks (e.g., /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt)."),
    mask: zod_1.z.string().optional().describe("Mask pattern for brute-force/hybrid attacks. Charsets: ?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, ?a=all. Example: '?u?l?l?l?d?d?d' = Capital + 3 lower + 3 digits."),
    rules_file: zod_1.z.string().optional().describe("Path to rules file for dictionary attack augmentation (e.g., /usr/share/hashcat/rules/best64.rule). Rules mutate wordlist entries (l33tspeak, append numbers, etc.)."),
    output_file: zod_1.z.string().optional().describe("Save cracked hash:password pairs to this file (e.g., /data/cracked.txt)."),
    extra_args: zod_1.z.array(zod_1.z.string()).optional().describe("Additional hashcat arguments (e.g., ['--increment'] for incremental mask, ['--session', 'mysession'] to name the session)."),
}, async ({ hash_file, hash_type, attack_mode, wordlist, mask, rules_file, output_file, extra_args }) => {
    const modeMap = {
        "dictionary": "0",
        "combinator": "1",
        "brute-force": "3",
        "hybrid-wordlist-mask": "6",
        "hybrid-mask-wordlist": "7",
    };
    const hashcatArgs = [
        "-m", hash_type.toString(),
        "-a", modeMap[attack_mode],
        "--force", // needed in container environments
        "--potfile-path", "/data/hashcat.potfile",
        hash_file,
    ];
    if (wordlist)
        hashcatArgs.push(wordlist);
    if (mask)
        hashcatArgs.push(mask);
    if (rules_file)
        hashcatArgs.push("-r", rules_file);
    if (output_file)
        hashcatArgs.push("-o", output_file);
    if (extra_args)
        hashcatArgs.push(...extra_args);
    return runHashcat(hashcatArgs);
});
// Tool 2: Show cracked passwords
server.tool("hashcat_show", `hashcat MCP server — display previously cracked passwords from the potfile.

Use this tool when you need to:
- Retrieve cracked plaintext passwords after a hashcat_crack session completes
- Check which hashes from a file have already been cracked in previous sessions
- The potfile persists between runs at /data/hashcat.potfile — use this tool to query it

Always run hashcat_show after hashcat_crack to see the cracked results.`, {
    hash_file: zod_1.z.string().describe("Path to the hash file used during cracking (e.g., /data/hashes.txt)."),
    hash_type: zod_1.z.number().describe("Hash type code used during cracking (must match the -m value used in hashcat_crack)."),
}, async ({ hash_file, hash_type }) => {
    return runHashcat([
        "-m", hash_type.toString(),
        "--show",
        "--potfile-path", "/data/hashcat.potfile",
        hash_file,
    ]);
});
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("hashcat MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
