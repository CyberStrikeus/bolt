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

// ── Purpose-based recommendations ──────────────────────────────────────────

type Intensity = "light" | "medium" | "heavy"

const RECOMMENDATIONS: Record<string, Record<Intensity, { path: string; rationale: string }[]>> = {
    "directory brute force": {
        light:  [{ path: "/usr/share/wordlists/dirb/common.txt",                                                       rationale: "~4k entries — fast scan, covers the most common web paths" }],
        medium: [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",                            rationale: "~63k entries — good balance of coverage and speed" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",                             rationale: "~119k entries — thorough, slower" }],
    },
    "file extension brute force": {
        light:  [{ path: "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt",                               rationale: "common file extensions for quick discovery" }],
        medium: [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",                            rationale: "combine with extensions list for medium coverage" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",                    rationale: "OWASP DirBuster medium list — classic heavy wordlist" }],
    },
    "subdomain enumeration": {
        light:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",                          rationale: "top 5k subdomains — fast, catches most common ones" }],
        medium: [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",                         rationale: "top 20k subdomains — good coverage for most targets" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million.txt",                               rationale: "full 1M subdomain list — comprehensive but slow" }],
    },
    "dns brute force": {
        light:  [{ path: "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",                                          rationale: "Jhaddix curated DNS list — high signal to noise ratio" }],
        medium: [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",                         rationale: "top 20k subdomains for medium-depth DNS brute force" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million.txt",                               rationale: "full 1M list for exhaustive DNS enumeration" }],
    },
    "password attack": {
        light:  [{ path: "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",      rationale: "top 100 passwords — catches weak credentials instantly" }],
        medium: [{ path: "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",     rationale: "top 1k passwords — covers most reused passwords" }],
        heavy:  [{ path: "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",    rationale: "top 10k passwords — thorough credential testing" }],
    },
    "username enumeration": {
        light:  [{ path: "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",                                  rationale: "short curated list of the most common usernames" }],
        medium: [{ path: "/usr/share/seclists/Usernames/Names/names.txt",                                              rationale: "common first/last names used as usernames" }],
        heavy:  [{ path: "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",                            rationale: "10M username list from xato.net breach data" }],
    },
    "api fuzzing": {
        light:  [{ path: "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",                            rationale: "common REST API endpoint names" }],
        medium: [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt",                  rationale: "medium wordlist in lowercase — suitable for API path discovery" }],
        heavy:  [{ path: "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt",                                                 rationale: "generic fuzzing payloads for finding API quirks" }],
    },
    "vhost discovery": {
        light:  [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",                          rationale: "top 5k names — fast virtual host discovery" }],
        medium: [{ path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",                         rationale: "top 20k names for medium-depth vhost brute force" }],
        heavy:  [{ path: "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",                             rationale: "large word list covering uncommon vhost names" }],
    },
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
    description: "wordlist MCP server — list all available wordlists on the system, grouped by category (web-content, dns, passwords, usernames, fuzzing). Use this before calling tools like gobuster, ffuf, hydra, or shuffledns to discover valid wordlist paths.",
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
    description: "wordlist MCP server — search available wordlists by keyword. Use this to find technology-specific wordlists (e.g., 'iis', 'php', 'tomcat', 'wordpress', 'oracle') or purpose-specific ones (e.g., 'password', 'user', 'backup', 'api').",
    schema: {
        query: z.string().describe("Keyword to search for in wordlist filenames and paths (e.g., 'iis', 'php', 'tomcat', 'password', 'user', 'backup', 'api', 'oracle')"),
    },
    execute: async (args: { query: string }): Promise<ToolResult> => {
        const keyword = args.query.toLowerCase()
        const allRoots = ["/usr/share/seclists", "/usr/share/wordlists"]
        const matches: WordlistEntry[] = []

        for (const root of allRoots) {
            const entries = scanDir(root, 4)
            for (const e of entries) {
                if (e.path.toLowerCase().includes(keyword) || e.name.toLowerCase().includes(keyword)) {
                    matches.push(e)
                }
            }
        }

        if (matches.length === 0) {
            return { content: [{ type: "text", text: `No wordlists found matching: "${args.query}"` }] }
        }

        const lines = matches.map(e => `  ${e.path}  (${e.size})`)
        return { content: [{ type: "text", text: `Found ${matches.length} wordlist(s) matching "${args.query}":\n\n${lines.join("\n")}` }] }
    },
}

const wordlistRecommend = {
    name: "wordlist_recommend",
    description: "wordlist MCP server — recommend the best wordlist path for a specific attack type and desired scan intensity. Use this to get the right wordlist before calling gobuster, ffuf, shuffledns, hydra, or medusa.",
    schema: {
        purpose: z.enum([
            "directory brute force",
            "file extension brute force",
            "subdomain enumeration",
            "dns brute force",
            "password attack",
            "username enumeration",
            "api fuzzing",
            "vhost discovery",
        ]).describe("The attack type you need a wordlist for"),
        intensity: z.enum(["light", "medium", "heavy"])
            .optional()
            .describe("Scan intensity: 'light' (fast, common entries), 'medium' (balanced, default), 'heavy' (thorough, slow). Default: medium"),
    },
    execute: async (args: { purpose: string; intensity?: string }): Promise<ToolResult> => {
        const intensity = (args.intensity ?? "medium") as Intensity
        const recs = RECOMMENDATIONS[args.purpose]?.[intensity] ?? []

        if (recs.length === 0) {
            return { content: [{ type: "text", text: `No recommendation available for: ${args.purpose} / ${intensity}` }] }
        }

        const lines = recs.map(r => {
            const exists = existsSync(r.path)
            const status = exists ? "✓" : "✗ NOT FOUND"
            return `${status}  ${r.path}\n    ${r.rationale}`
        })

        return { content: [{ type: "text", text: lines.join("\n\n") }] }
    },
}

// ── Plugin export ───────────────────────────────────────────────────────────

export const plugin: PluginDef = {
    name: "wordlist",
    version: "0.1.0",
    tools: [wordlistList, wordlistSearch, wordlistRecommend],
    check: async () => {
        return { installed: existsSync("/usr/share/seclists") || existsSync("/usr/share/wordlists") }
    },
}
