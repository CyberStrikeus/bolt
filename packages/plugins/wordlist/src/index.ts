import { z } from "zod"
import { readdirSync, statSync, existsSync } from "fs"
import { join } from "path"
import type { PluginDef, ToolResult } from "@cyberstrike-io/bolt"

// ── Category → filesystem path mapping ─────────────────────────────────────

const CATEGORY_PATHS: Record<string, string[]> = {
    "web-content": [
        "/usr/share/seclists/Discovery/Web-Content",
    ],
    "dns": [
        "/usr/share/seclists/Discovery/DNS",
    ],
    "passwords": [
        "/usr/share/seclists/Passwords/Common-Credentials",
        "/usr/share/seclists/Passwords/Leaked-Databases",
    ],
    "usernames": [
        "/usr/share/seclists/Usernames",
    ],
    "fuzzing": [
        "/usr/share/seclists/Fuzzing",
    ],
    "misc": [
        "/usr/share/wordlists/dirb",
        "/usr/share/wordlists/dirbuster",
    ],
}

// ── Intent metadata: tags for key wordlists to enable semantic search ────────
// Maps filename → { tags, note }
// Tags are free-form keywords an LLM or user might search for.

const WORDLIST_METADATA: Record<string, { tags: string[]; note: string }> = {
    // ── Passwords ──────────────────────────────────────────────────────────
    "xato-net-10-million-passwords-10.txt":     { tags: ["password", "brute force", "instant", "default credentials"], note: "Top 10 most common passwords — instant check" },
    "xato-net-10-million-passwords-100.txt":    { tags: ["password", "brute force", "quick", "ssh", "ftp", "rdp", "smb", "web login", "credential stuffing"], note: "Top 100 most common passwords — very fast" },
    "xato-net-10-million-passwords-1000.txt":   { tags: ["password", "brute force", "ssh", "ftp", "rdp", "smb", "web login", "credential stuffing", "hydra", "medusa"], note: "Top 1k most common passwords" },
    "xato-net-10-million-passwords-10000.txt":  { tags: ["password", "brute force", "ssh", "ftp", "rdp", "smb", "web login", "credential stuffing", "thorough", "hydra", "medusa"], note: "Top 10k most common passwords — thorough" },
    "xato-net-10-million-passwords-100000.txt": { tags: ["password", "brute force", "massive", "hashcat", "john", "offline cracking"], note: "Top 100k passwords — for offline cracking" },
    "xato-net-10-million-passwords.txt":        { tags: ["password", "brute force", "massive", "hashcat", "john", "offline cracking", "full list"], note: "Full 10M password list — offline cracking only" },
    "probable-v2_top-12000.txt":                { tags: ["password", "brute force", "probable", "hashcat", "john", "cracking", "breach analysis"], note: "Probable passwords derived from breach analysis" },
    "darkweb2017_top-10000.txt":                { tags: ["password", "brute force", "darkweb", "breach", "leaked", "hashcat"], note: "Top 10k passwords from dark web 2017 leaks" },
    "10k-most-common.txt":                      { tags: ["password", "brute force", "common", "quick"], note: "10k most common passwords" },
    "top-passwords-shortlist.txt":              { tags: ["password", "brute force", "quick", "default credentials", "short"], note: "Short curated high-value password list" },
    "top-20-common-SSH-passwords.txt":          { tags: ["password", "ssh", "quick", "default", "linux"], note: "20 most common SSH passwords" },
    "Pwdb_top-1000.txt":                        { tags: ["password", "brute force", "common"], note: "Top 1k passwords from Pwdb dataset" },
    "Pwdb_top-10000.txt":                       { tags: ["password", "brute force", "thorough"], note: "Top 10k passwords from Pwdb dataset" },
    "500-worst-passwords.txt":                  { tags: ["password", "brute force", "quick", "default", "worst passwords"], note: "500 historically worst passwords" },
    "2023-200_most_used_passwords.txt":         { tags: ["password", "brute force", "recent", "2023", "quick"], note: "200 most used passwords in 2023" },
    "2024-197_most_used_passwords.txt":         { tags: ["password", "brute force", "recent", "2024", "quick"], note: "197 most used passwords in 2024" },

    // ── Usernames ──────────────────────────────────────────────────────────
    "top-usernames-shortlist.txt":              { tags: ["username", "user enum", "kerbrute", "ad", "active directory", "brute force", "quick", "short"], note: "Short curated list of most common usernames" },
    "xato-net-10-million-usernames.txt":        { tags: ["username", "user enum", "massive", "thorough", "kerbrute", "ad enum"], note: "10M usernames from xato.net breach data" },

    // ── Web content / directory ────────────────────────────────────────────
    "common.txt":                               { tags: ["directory", "web", "dir brute force", "gobuster", "ffuf", "quick", "path discovery"], note: "~4.7k common web paths — fast directory scan" },
    "raft-medium-words.txt":                    { tags: ["directory", "web", "dir brute force", "gobuster", "ffuf", "balanced", "path discovery"], note: "~63k entries — good balance of coverage and speed" },
    "raft-large-words.txt":                     { tags: ["directory", "web", "dir brute force", "gobuster", "ffuf", "thorough", "path discovery"], note: "~119k entries — thorough directory scan" },
    "raft-medium-words-lowercase.txt":          { tags: ["directory", "web", "api", "gobuster", "ffuf", "lowercase"], note: "Medium wordlist in lowercase — good for APIs" },
    "raft-small-words.txt":                     { tags: ["directory", "web", "dir brute force", "gobuster", "ffuf", "quick", "small"], note: "Small raft wordlist — quick scan" },
    "web-extensions.txt":                       { tags: ["extension", "file type", "file extension", "gobuster", "ffuf", "php", "asp", "jsp"], note: "Common web file extensions" },
    "DirBuster-2007_directory-list-2.3-medium.txt": { tags: ["directory", "web", "owasp", "dirbuster", "classic", "gobuster", "ffuf", "thorough"], note: "Classic OWASP DirBuster medium list" },
    "DirBuster-2007_directory-list-2.3-big.txt":    { tags: ["directory", "web", "owasp", "dirbuster", "thorough", "heavy", "gobuster", "ffuf"], note: "Classic OWASP DirBuster big list" },
    "api-endpoints.txt":                        { tags: ["api", "rest", "endpoint", "gobuster", "ffuf", "api fuzzing", "api discovery"], note: "Common REST API endpoint names" },
    "directory-list-2.3-medium.txt":            { tags: ["directory", "web", "dir brute force", "classic", "gobuster", "ffuf"], note: "Classic medium directory list" },

    // ── DNS / subdomains ───────────────────────────────────────────────────
    "subdomains-top1million-5000.txt":          { tags: ["subdomain", "dns", "shuffledns", "gobuster", "amass", "quick", "domain enum"], note: "Top 5k subdomains — fast" },
    "subdomains-top1million-20000.txt":         { tags: ["subdomain", "dns", "shuffledns", "gobuster", "amass", "balanced", "domain enum"], note: "Top 20k subdomains — balanced" },
    "subdomains-top1million-110000.txt":        { tags: ["subdomain", "dns", "shuffledns", "gobuster", "amass", "thorough", "domain enum"], note: "Top 110k subdomains — thorough" },
    "dns-Jhaddix.txt":                          { tags: ["subdomain", "dns", "shuffledns", "curated", "quality", "bug bounty", "recon"], note: "Jhaddix curated DNS list — high signal to noise" },

    // ── Fuzzing ────────────────────────────────────────────────────────────
    "fuzz-Bo0oM.txt":                           { tags: ["fuzzing", "generic", "ffuf", "api", "weird input", "injection", "sqli", "xss"], note: "Generic fuzzing payloads — good for finding API quirks" },
}

// ── Purpose-based recommendations ──────────────────────────────────────────

type Intensity = "light" | "medium" | "heavy"

const RECOMMENDATIONS: Record<string, Record<Intensity, { path: string; rationale: string }[]>> = {
    "directory brute force": {
        light:  [{ path: "/usr/share/seclists/Discovery/Web-Content/common.txt",                                                    rationale: "~4.7k entries — fast scan, covers the most common web paths" }],
        medium: [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",                                         rationale: "~63k entries — good balance of coverage and speed" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",                                          rationale: "~119k entries — thorough, slower" }],
    },
    "file extension brute force": {
        light:  [{ path: "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt",                                            rationale: "common file extensions for quick discovery" }],
        medium: [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",                                         rationale: "combine with extensions list for medium coverage" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",                  rationale: "OWASP DirBuster medium list — classic heavy wordlist" }],
    },
    "subdomain enumeration": {
        light:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",                                       rationale: "top 5k subdomains — fast, catches most common ones" }],
        medium: [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",                                      rationale: "top 20k subdomains — good coverage for most targets" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",                                     rationale: "top 110k subdomains — comprehensive coverage" }],
    },
    "dns brute force": {
        light:  [{ path: "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",                                                       rationale: "Jhaddix curated DNS list — high signal to noise ratio" }],
        medium: [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",                                      rationale: "top 20k subdomains for medium-depth DNS brute force" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",                                     rationale: "top 110k subdomains — exhaustive DNS enumeration" }],
    },
    "password attack": {
        light:  [{ path: "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-100.txt",                  rationale: "top 100 passwords — catches weak credentials instantly" }],
        medium: [{ path: "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt",                 rationale: "top 1k passwords — covers most reused passwords" }],
        heavy:  [{ path: "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt",                rationale: "top 10k passwords — thorough credential testing" }],
    },
    "username enumeration": {
        light:  [{ path: "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",                                               rationale: "short curated list of the most common usernames" }],
        medium: [{ path: "/usr/share/seclists/Usernames/Names/names.txt",                                                           rationale: "common first/last names used as usernames" }],
        heavy:  [{ path: "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",                                         rationale: "10M username list from xato.net breach data" }],
    },
    "api fuzzing": {
        light:  [{ path: "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",                                         rationale: "common REST API endpoint names" }],
        medium: [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt",                               rationale: "medium wordlist in lowercase — suitable for API path discovery" }],
        heavy:  [{ path: "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt",                                                              rationale: "generic fuzzing payloads for finding API quirks" }],
    },
    "vhost discovery": {
        light:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",                                       rationale: "top 5k names — fast virtual host discovery" }],
        medium: [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",                                      rationale: "top 20k names for medium-depth vhost brute force" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",                                          rationale: "large word list covering uncommon vhost names" }],
    },
}

// Keyword → canonical purpose mapping for free-text matching
const PURPOSE_KEYWORDS: [string[], string][] = [
    [["dir", "directory", "path", "web content", "file discovery", "gobuster dir", "ffuf"], "directory brute force"],
    [["extension", "ext", "file type", "file ext", "suffix"],                               "file extension brute force"],
    [["subdomain", "sub domain", "subdomain enum", "domain enum", "asset discovery"],       "subdomain enumeration"],
    [["dns", "dns brute", "nameserver", "dns enum", "shuffledns"],                          "dns brute force"],
    [["password", "credential", "login", "ssh", "ftp", "rdp", "smb", "telnet", "auth",
      "brute force", "credential stuffing", "hydra", "medusa", "spray"],                   "password attack"],
    [["username", "user", "account", "ad user", "user enum", "kerbrute", "active directory",
      "userenum", "ldap user"],                                                             "username enumeration"],
    [["api", "rest", "endpoint", "parameter", "param", "api fuzz"],                        "api fuzzing"],
    [["vhost", "virtual host", "host header", "subdomain takeover"],                       "vhost discovery"],
]

function matchPurpose(input: string): string | null {
    const lower = input.toLowerCase()
    for (const [keywords, purpose] of PURPOSE_KEYWORDS) {
        if (keywords.some(k => lower.includes(k))) return purpose
    }
    return null
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes}B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)}KB`
    return `${(bytes / 1024 / 1024).toFixed(1)}MB`
}

interface WordlistEntry {
    path: string
    name: string
    size: string
}

function scanDir(dirPath: string, maxDepth = 2, depth = 0): WordlistEntry[] {
    if (!existsSync(dirPath)) return []
    const results: WordlistEntry[] = []
    try {
        for (const entry of readdirSync(dirPath)) {
            const fullPath = join(dirPath, entry)
            const stat = statSync(fullPath)
            if (stat.isFile() && (entry.endsWith(".txt") || entry.endsWith(".lst"))) {
                results.push({ path: fullPath, name: entry, size: formatSize(stat.size) })
            } else if (stat.isDirectory() && depth < maxDepth) {
                results.push(...scanDir(fullPath, maxDepth, depth + 1))
            }
        }
    } catch {
        // skip unreadable dirs
    }
    return results
}

// ── Tools ───────────────────────────────────────────────────────────────────

const wordlistList = {
    name: "wordlist_list",
    description: "wordlist plugin — list all available wordlists on the system, grouped by category (web-content, dns, passwords, usernames, fuzzing). Use this before calling tools like gobuster, ffuf, hydra, or shuffledns to discover valid wordlist paths.",
    schema: {
        category: z.enum(["web-content", "dns", "passwords", "usernames", "fuzzing", "misc", "all"])
            .optional()
            .describe("Filter by category. Omit or use 'all' to list everything. Options: web-content, dns, passwords, usernames, fuzzing, misc"),
    },
    execute: async (args: { category?: string }): Promise<ToolResult> => {
        const selected = (!args.category || args.category === "all")
            ? Object.entries(CATEGORY_PATHS)
            : Object.entries(CATEGORY_PATHS).filter(([k]) => k === args.category)

        const lines: string[] = []
        for (const [cat, paths] of selected) {
            const entries: WordlistEntry[] = []
            for (const p of paths) entries.push(...scanDir(p))
            if (entries.length === 0) continue
            lines.push(`\n[${cat}]`)
            for (const e of entries) {
                lines.push(`  ${e.path}  (${e.size})`)
            }
        }

        const text = lines.length > 0
            ? lines.join("\n")
            : "No wordlists found. SecLists may not be installed — check Dockerfile."

        return { content: [{ type: "text", text }] }
    },
}

const wordlistSearch = {
    name: "wordlist_search",
    description: "wordlist plugin — search available wordlists by intent or keyword. Understands natural language queries like 'ssh brute force', 'wordpress paths', 'active directory users', 'api endpoints'. Also searches filenames directly for technology-specific lists (e.g., 'iis', 'php', 'tomcat', 'oracle').",
    schema: {
        query: z.string().describe("What you're looking for — use natural language (e.g., 'ssh brute force passwords', 'wordpress directory scan', 'active directory username list', 'api endpoint fuzzing') or a technology keyword (e.g., 'php', 'tomcat', 'oracle', 'wordpress')."),
    },
    execute: async (args: { query: string }): Promise<ToolResult> => {
        const keyword = args.query.toLowerCase()
        const allRoots = ["/usr/share/seclists", "/usr/share/wordlists"]

        // 1. Scan filesystem for all wordlists
        const allEntries: WordlistEntry[] = []
        for (const root of allRoots) {
            allEntries.push(...scanDir(root, 4))
        }

        // 2. Score each entry: filename match + metadata tag/note match
        const scored: Array<{ entry: WordlistEntry; score: number; note?: string }> = []

        for (const e of allEntries) {
            let score = 0
            let note: string | undefined

            // Filename / path match (exact keyword in path)
            if (e.path.toLowerCase().includes(keyword) || e.name.toLowerCase().includes(keyword)) {
                score += 10
            }

            // Metadata match
            const meta = WORDLIST_METADATA[e.name]
            if (meta) {
                note = meta.note
                // Tag match
                for (const tag of meta.tags) {
                    if (keyword.split(" ").some(word => tag.includes(word) || word.includes(tag))) {
                        score += 5
                        break
                    }
                }
                // Full query match against tags
                if (meta.tags.some(tag => keyword.includes(tag))) score += 8
                // Note match
                if (meta.note.toLowerCase().includes(keyword)) score += 3
            }

            if (score > 0) scored.push({ entry: e, score, note })
        }

        // 3. Sort by score descending, limit to top 20
        scored.sort((a, b) => b.score - a.score)
        const top = scored.slice(0, 20)

        if (top.length === 0) {
            return { content: [{ type: "text", text: `No wordlists found matching: "${args.query}"\n\nTry wordlist_recommend for purpose-based suggestions, or wordlist_list to browse all available lists.` }] }
        }

        const lines = top.map(({ entry: e, note }) => {
            const desc = note ? `  → ${note}` : ""
            return `  ${e.path}  (${e.size})${desc}`
        })

        return { content: [{ type: "text", text: `Found ${top.length} wordlist(s) matching "${args.query}":\n\n${lines.join("\n")}` }] }
    },
}

const wordlistRecommend = {
    name: "wordlist_recommend",
    description: "wordlist plugin — recommend the best wordlist for a given attack type and intensity. Accepts natural language descriptions like 'ssh password attack', 'wordpress directory brute force', 'active directory user enumeration'. Use before calling gobuster, ffuf, shuffledns, hydra, medusa, kerbrute, or hashcat.",
    schema: {
        purpose: z.string().describe("Describe what you need the wordlist for in plain language (e.g., 'ssh brute force', 'directory scanning', 'subdomain enumeration', 'active directory users', 'api fuzzing', 'smb credential attack'). Does not need to be an exact phrase."),
        intensity: z.enum(["light", "medium", "heavy"])
            .optional()
            .describe("Scan intensity: 'light' (fast, small list), 'medium' (balanced, default), 'heavy' (thorough, slow). Default: medium"),
    },
    execute: async (args: { purpose: string; intensity?: string }): Promise<ToolResult> => {
        const intensity = (args.intensity ?? "medium") as Intensity

        // Try exact match first, then fuzzy keyword match
        const canonicalPurpose = RECOMMENDATIONS[args.purpose]
            ? args.purpose
            : matchPurpose(args.purpose)

        if (!canonicalPurpose) {
            const available = Object.keys(RECOMMENDATIONS).join(", ")
            return { content: [{ type: "text", text: `Could not match "${args.purpose}" to a known attack type.\n\nKnown types: ${available}\n\nOr try wordlist_search with a more specific keyword.` }] }
        }

        const recs = RECOMMENDATIONS[canonicalPurpose]?.[intensity] ?? []

        const lines = recs.map(r => {
            const exists = existsSync(r.path)
            const status = exists ? "✓" : "✗ NOT FOUND"
            return `${status}  ${r.path}\n    ${r.rationale}`
        })

        const header = canonicalPurpose !== args.purpose
            ? `Matched "${args.purpose}" → "${canonicalPurpose}" (${intensity})\n\n`
            : `${canonicalPurpose} / ${intensity}\n\n`

        return { content: [{ type: "text", text: header + lines.join("\n\n") }] }
    },
}

// ── Plugin export ───────────────────────────────────────────────────────────

export const plugin: PluginDef = {
    name: "wordlist",
    version: "0.2.0",
    tools: [wordlistList, wordlistSearch, wordlistRecommend],
    check: async () => {
        return { installed: existsSync("/usr/share/seclists") || existsSync("/usr/share/wordlists") }
    },
}
