/**
 * Tool Presets - Pre-defined tool sets for common pentest scenarios
 *
 * Each preset loads a curated set of tools optimized for a specific task.
 * This saves time and ensures the right tools are available.
 */

export interface Preset {
  name: string
  description: string
  tools: string[]
  workflow?: string
}

export const PRESETS: Record<string, Preset> = {
  // === RECONNAISSANCE ===
  "recon-web": {
    name: "Web Reconnaissance",
    description: "Subdomain enumeration, tech detection, and URL discovery",
    tools: ["subfinder", "httpx", "whatweb", "waybackurls", "gau"],
    workflow: `1. subfinder → Find subdomains
2. httpx → Probe live hosts
3. whatweb → Detect technologies
4. waybackurls/gau → Find historical URLs`,
  },

  "recon-network": {
    name: "Network Reconnaissance",
    description: "Host discovery, port scanning, and service enumeration",
    tools: ["nmap", "masscan", "rustscan", "arp-scan", "netdiscover"],
    workflow: `1. arp-scan/netdiscover → Find hosts on LAN
2. masscan/rustscan → Fast port discovery
3. nmap → Detailed service enumeration`,
  },

  "recon-osint": {
    name: "OSINT Gathering",
    description: "Open source intelligence and information gathering",
    tools: ["theHarvester", "shodan", "recon-ng", "spiderfoot", "amass"],
    workflow: `1. theHarvester → Emails, names, hosts
2. shodan → Internet-facing devices
3. amass → Comprehensive subdomain enum
4. spiderfoot → Automated OSINT`,
  },

  // === WEB APPLICATION ===
  "web-scan": {
    name: "Web Vulnerability Scanning",
    description: "Automated web application vulnerability scanning",
    tools: ["nikto", "nuclei", "wapiti", "skipfish"],
    workflow: `1. nikto → Quick vulnerability scan
2. nuclei → Template-based scanning
3. wapiti → Active vulnerability testing`,
  },

  "web-fuzz": {
    name: "Web Fuzzing",
    description: "Directory brute-forcing and parameter fuzzing",
    tools: ["ffuf", "gobuster", "feroxbuster", "dirb", "wfuzz"],
    workflow: `1. feroxbuster → Recursive directory discovery
2. ffuf → Parameter and content fuzzing
3. wfuzz → Advanced fuzzing with filters`,
  },

  "web-injection": {
    name: "Injection Testing",
    description: "SQL injection, command injection, and XSS testing",
    tools: ["sqlmap", "commix", "xsser", "dalfox"],
    workflow: `1. sqlmap → SQL injection
2. commix → Command injection
3. dalfox/xsser → XSS testing`,
  },

  "web-api": {
    name: "API Testing",
    description: "REST API security testing and parameter discovery",
    tools: ["arjun", "ffuf", "nuclei", "paramspider"],
    workflow: `1. arjun → Hidden parameter discovery
2. paramspider → Archive parameter mining
3. ffuf → API endpoint fuzzing
4. nuclei → API vulnerability templates`,
  },

  // === NETWORK ATTACKS ===
  "network-smb": {
    name: "SMB/Windows Enumeration",
    description: "Windows and SMB service enumeration",
    tools: ["enum4linux-ng", "smbmap", "crackmapexec", "nbtscan"],
    workflow: `1. nbtscan → NetBIOS discovery
2. enum4linux-ng → Comprehensive SMB enum
3. smbmap → Share enumeration
4. crackmapexec → Multi-protocol testing`,
  },

  "network-sniff": {
    name: "Network Sniffing",
    description: "Packet capture and traffic analysis",
    tools: ["tcpdump", "tshark", "responder", "bettercap"],
    workflow: `1. tcpdump/tshark → Capture traffic
2. responder → Poison LLMNR/NBT-NS
3. bettercap → MITM attacks`,
  },

  // === ACTIVE DIRECTORY ===
  "ad-enum": {
    name: "AD Enumeration",
    description: "Active Directory reconnaissance and enumeration",
    tools: ["ldapsearch", "bloodhound-python", "kerbrute", "crackmapexec"],
    workflow: `1. ldapsearch → LDAP enumeration
2. kerbrute → User enumeration
3. bloodhound-python → AD mapping
4. crackmapexec → Multi-protocol recon`,
  },

  "ad-attack": {
    name: "AD Attacks",
    description: "Kerberos attacks and lateral movement",
    tools: ["impacket-secretsdump", "psexec.py", "wmiexec.py", "evil-winrm", "rubeus"],
    workflow: `1. Kerberoasting/AS-REP roasting
2. Pass-the-hash with psexec/wmiexec
3. evil-winrm for WinRM access
4. secretsdump for credential extraction`,
  },

  // === PASSWORD ATTACKS ===
  "password-crack": {
    name: "Password Cracking",
    description: "Offline password hash cracking",
    tools: ["hashcat", "john", "hashid", "ophcrack"],
    workflow: `1. hashid → Identify hash type
2. hashcat/john → Crack with wordlists
3. ophcrack → Rainbow table attacks`,
  },

  "password-brute": {
    name: "Online Brute Force",
    description: "Online password brute forcing",
    tools: ["hydra", "medusa", "crackmapexec"],
    workflow: `1. hydra → Multi-protocol brute force
2. medusa → Parallel login testing
3. crackmapexec → SMB/WinRM brute`,
  },

  "password-wordlist": {
    name: "Wordlist Generation",
    description: "Custom wordlist creation",
    tools: ["cewl", "crunch"],
    workflow: `1. cewl → Spider site for words
2. crunch → Generate patterns`,
  },

  // === WIRELESS ===
  "wireless-wifi": {
    name: "WiFi Attacks",
    description: "WiFi network assessment",
    tools: ["aircrack-ng", "airodump-ng", "wifite", "reaver", "bettercap"],
    workflow: `1. airodump-ng → Capture traffic
2. wifite → Automated attacks
3. aircrack-ng → Crack handshakes
4. reaver → WPS attacks`,
  },

  // === EXPLOITATION ===
  "exploit-web": {
    name: "Web Exploitation",
    description: "Web application exploitation",
    tools: ["sqlmap", "commix", "beef-xss", "xsser"],
    workflow: `1. sqlmap → SQL injection exploitation
2. commix → Command injection shells
3. beef-xss → Browser exploitation`,
  },

  "exploit-network": {
    name: "Network Exploitation",
    description: "Network service exploitation",
    tools: ["msfconsole", "searchsploit", "msfvenom", "routersploit"],
    workflow: `1. searchsploit → Find exploits
2. msfconsole → Exploit execution
3. msfvenom → Payload generation`,
  },

  // === FORENSICS ===
  "forensics-disk": {
    name: "Disk Forensics",
    description: "Disk image analysis and file recovery",
    tools: ["autopsy", "binwalk", "foremost", "strings", "exiftool"],
    workflow: `1. autopsy → Full disk analysis
2. binwalk → Firmware extraction
3. foremost → File carving
4. strings/exiftool → Metadata analysis`,
  },

  "forensics-memory": {
    name: "Memory Forensics",
    description: "RAM dump analysis",
    tools: ["volatility"],
    workflow: `1. volatility imageinfo → Identify profile
2. volatility pslist → Process list
3. volatility netscan → Network connections
4. volatility hashdump → Password hashes`,
  },

  // === CTF ===
  "ctf-stego": {
    name: "CTF Steganography",
    description: "Hidden data extraction for CTF challenges",
    tools: ["steghide", "zsteg", "stegsolve", "binwalk", "exiftool", "strings"],
    workflow: `1. exiftool → Check metadata
2. strings → Extract text
3. binwalk → Find embedded files
4. steghide/zsteg → Extract hidden data`,
  },

  "ctf-web": {
    name: "CTF Web Challenges",
    description: "Web exploitation for CTF",
    tools: ["sqlmap", "ffuf", "jwt_tool", "burpsuite"],
    workflow: `1. ffuf → Directory/parameter fuzzing
2. sqlmap → SQL injection
3. jwt_tool → JWT manipulation
4. burpsuite → Request manipulation`,
  },
}

/**
 * Get all preset names
 */
export function getPresetNames(): string[] {
  return Object.keys(PRESETS)
}

/**
 * Get preset by name
 */
export function getPreset(name: string): Preset | undefined {
  return PRESETS[name]
}

/**
 * Search presets by query
 */
export function searchPresets(query: string): Preset[] {
  const queryLower = query.toLowerCase()
  return Object.values(PRESETS).filter(
    (p) =>
      p.name.toLowerCase().includes(queryLower) ||
      p.description.toLowerCase().includes(queryLower)
  )
}

/**
 * Get presets grouped by category
 */
export function getPresetsByCategory(): Record<string, Preset[]> {
  const categories: Record<string, Preset[]> = {
    "Reconnaissance": [],
    "Web Application": [],
    "Network": [],
    "Active Directory": [],
    "Password": [],
    "Wireless": [],
    "Exploitation": [],
    "Forensics": [],
    "CTF": [],
  }

  for (const [key, preset] of Object.entries(PRESETS)) {
    if (key.startsWith("recon")) categories["Reconnaissance"].push(preset)
    else if (key.startsWith("web")) categories["Web Application"].push(preset)
    else if (key.startsWith("network")) categories["Network"].push(preset)
    else if (key.startsWith("ad")) categories["Active Directory"].push(preset)
    else if (key.startsWith("password")) categories["Password"].push(preset)
    else if (key.startsWith("wireless")) categories["Wireless"].push(preset)
    else if (key.startsWith("exploit")) categories["Exploitation"].push(preset)
    else if (key.startsWith("forensics")) categories["Forensics"].push(preset)
    else if (key.startsWith("ctf")) categories["CTF"].push(preset)
  }

  return categories
}
