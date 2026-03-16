# Bolt MCP Kali - Production Deployment Guide

## 🚨 Root Privileges Problem

Many penetration testing tools require root privileges for:
- **Raw socket access** (nmap SYN scans, masscan)
- **Promiscuous mode** (tcpdump, wireshark)
- **Wireless interface control** (aircrack-ng suite)
- **Network manipulation** (responder, bettercap)

**Default behavior:** MCP server runs as non-root user → tools requiring root will fail or hang waiting for password.

## 🔧 Solutions

### Option 1: Sudoers Configuration (Recommended for Production)

**Pros:**
- ✅ Granular control over which tools can run with sudo
- ✅ Easy to audit and maintain
- ✅ Works for all tools immediately
- ✅ Survives package updates

**Cons:**
- ❌ Requires system admin to configure
- ❌ Less secure than capabilities (but still safe with proper config)

**Setup:**

```bash
# 1. Install MCP server
npm install -g @cyberstrike-io/mcp-kali

# 2. Run sudoers setup script
sudo bash node_modules/@cyberstrike-io/mcp-kali/scripts/setup-sudoers.sh

# 3. Verify
sudo -l
# Should show: User kali may run the following commands on kali:
#     (ALL) NOPASSWD: /usr/bin/nmap, /usr/bin/masscan, ...

# 4. Test
mcp-kali-http
```

**Customization:**

Edit `/etc/sudoers.d/mcp-kali` to add/remove tools:

```bash
# Add new tool
sudo visudo -f /etc/sudoers.d/mcp-kali

# Add to appropriate Cmnd_Alias:
Cmnd_Alias MCP_NETWORK = \
    /usr/bin/nmap, \
    /usr/bin/masscan, \
    /usr/bin/YOUR_NEW_TOOL
```

### Option 2: Linux Capabilities (Most Secure)

**Pros:**
- ✅ Most secure (minimum privilege principle)
- ✅ No sudo required at runtime
- ✅ Granular per-binary permissions

**Cons:**
- ❌ Must be reapplied after package updates
- ❌ Not all tools support capabilities
- ❌ More complex to troubleshoot

**Setup:**

```bash
# 1. Install MCP server
npm install -g @cyberstrike-io/mcp-kali

# 2. Run capabilities setup
sudo bash node_modules/@cyberstrike-io/mcp-kali/scripts/setup-capabilities.sh

# 3. Verify
getcap /usr/bin/nmap
# Should show: /usr/bin/nmap cap_net_raw,cap_net_admin,cap_net_bind_service=eip

# 4. Test
mcp-kali-http
```

**Post-Update Hook:**

Create a script to re-apply after apt updates:

```bash
# /etc/apt/apt.conf.d/99-reapply-caps
DPkg::Post-Invoke {
    "bash /opt/mcp-kali/setup-capabilities.sh 2>&1 | logger -t apt-caps";
};
```

### Option 3: Run MCP Server as Root (NOT RECOMMENDED)

**⚠️ SECURITY RISK - Only for isolated test environments**

```bash
# DON'T DO THIS IN PRODUCTION!
sudo mcp-kali-http
```

**Why this is dangerous:**
- 🚫 Any command injection → full root access
- 🚫 Any MCP server bug → root compromise
- 🚫 No isolation or sandboxing

**Only acceptable for:**
- Isolated VM/container for testing
- Temporary local development
- Air-gapped penetration testing lab

## 🎯 Recommended Deployment Architectures

### Architecture 1: Dedicated Kali VM (Recommended)

```
┌─────────────────────────────────────┐
│  Kali Linux VM (Isolated Network)  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  MCP Server (non-root user)  │  │
│  │  + Sudoers config            │  │
│  │  Port: 3001                  │  │
│  └──────────────────────────────┘  │
│                                     │
│  Network: 10.0.50.0/24             │
│  Internet: Via proxy only          │
└─────────────────────────────────────┘
          ↓ Ed25519 Auth
┌─────────────────────────────────────┐
│  Client Machine                     │
│  CyberStrike CLI                    │
└─────────────────────────────────────┘
```

**Security:**
- ✅ Isolated VM
- ✅ Sudoers whitelist
- ✅ Ed25519 authentication
- ✅ No internet access (except via proxy)

### Architecture 2: Docker Container (Development)

```dockerfile
FROM kalilinux/kali-rolling

# Install tools
RUN apt-get update && apt-get install -y \
    nmap masscan tcpdump aircrack-ng \
    nodejs npm

# Install MCP server
RUN npm install -g @cyberstrike-io/mcp-kali

# Setup capabilities
COPY setup-capabilities.sh /opt/
RUN bash /opt/setup-capabilities.sh

# Non-root user
RUN useradd -m mcp
USER mcp

CMD ["mcp-kali-http"]
```

**Note:** Capabilities in containers require `--cap-add=NET_RAW --cap-add=NET_ADMIN`

### Architecture 3: Systemd Service (Production Server)

```ini
# /etc/systemd/system/mcp-kali.service
[Unit]
Description=Bolt MCP Kali Server
After=network.target

[Service]
Type=simple
User=mcp
Group=mcp
WorkingDirectory=/home/mcp
Environment=DATA_DIR=/var/lib/mcp-kali
Environment=MCP_ADMIN_TOKEN=your-secret-token
ExecStart=/usr/bin/mcp-kali-http
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mcp-kali

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable mcp-kali
sudo systemctl start mcp-kali
sudo systemctl status mcp-kali
```

## 📊 Tool Privilege Matrix

| Tool | Needs Root? | Why | Sudoers | Capabilities | Workaround |
|------|------------|-----|---------|--------------|------------|
| **nmap** (-sS) | ✅ Yes | Raw sockets | ✅ Works | ✅ Works | Use -sT instead |
| **nmap** (-sT) | ❌ No | TCP connect | N/A | N/A | - |
| **masscan** | ✅ Yes | Raw sockets | ✅ Works | ✅ Works | No workaround |
| **tcpdump** | ✅ Yes | Promiscuous mode | ✅ Works | ✅ Works | No workaround |
| **aircrack-ng** | ✅ Yes | Wireless control | ✅ Works | ✅ Works | No workaround |
| **wireshark** | ✅ Yes | Packet capture | ✅ Works | ✅ Works | Use tshark |
| **sqlmap** | ❌ No | HTTP requests | N/A | N/A | - |
| **nikto** | ❌ No | HTTP scanner | N/A | N/A | - |
| **hydra** | ❌ No | Network auth | N/A | N/A | - |
| **hashcat** | ❌ No | CPU/GPU compute | N/A | N/A | - |
| **metasploit** | ❌ No | Framework | N/A | N/A | - |

## 🧪 Testing After Setup

```bash
# 1. Test sudo (if using sudoers)
sudo nmap --version
# Should NOT ask for password

# 2. Test capabilities (if using capabilities)
getcap /usr/bin/nmap
# Should show: cap_net_raw,cap_net_admin,cap_net_bind_service=eip

# 3. Test MCP server
mcp-kali-http &
SERVER_PID=$!

# 4. Test tool execution from CLI
cyberstrike mcp list
# Should show kali-bolt connected

# 5. Test nmap through MCP
# Use cyberstrike CLI or test script

# 6. Check logs
tail -f ~/bolt-data/logs/current/tools.log

# 7. Cleanup
kill $SERVER_PID
```

## 🔒 Security Best Practices

1. **Principle of Least Privilege**
   - Only grant sudo/capabilities to tools that NEED it
   - Review sudoers file quarterly
   - Remove unused tools

2. **Audit Logging**
   - Enable sudo logging: `Defaults log_input, log_output`
   - Monitor MCP logs for suspicious activity
   - Set up alerts for repeated auth failures

3. **Network Isolation**
   - Run MCP server in isolated network segment
   - Use firewall to restrict outbound connections
   - Consider VPN/bastion host for remote access

4. **Regular Updates**
   - Keep Kali and tools updated
   - Re-apply capabilities after updates
   - Monitor CVEs for installed tools

5. **Credential Rotation**
   - Rotate Ed25519 keys quarterly
   - Revoke unused client credentials
   - Use MCP_ADMIN_TOKEN for sensitive operations

## 📝 Troubleshooting

### Problem: "sudo: no tty present and no askpass program specified"

**Cause:** Tool trying to run sudo but passwordless not configured

**Solution:**
```bash
sudo visudo -f /etc/sudoers.d/mcp-kali
# Verify NOPASSWD is set
```

### Problem: "Operation not permitted" with capabilities

**Cause:** Capabilities not set or reset after update

**Solution:**
```bash
sudo bash /opt/setup-capabilities.sh
getcap /usr/bin/nmap  # Verify
```

### Problem: Tool hangs for 30 seconds then fails

**Cause:** Waiting for sudo password

**Solution:** Check MCP server logs:
```bash
tail -f ~/bolt-data/logs/current/tools.log
# Look for "password for" in output
```

Then apply sudoers/capabilities fix.

## 📚 References

- [Sudoers Manual](https://www.sudo.ws/docs/man/sudoers.man/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Nmap Privilege Requirements](https://nmap.org/book/man-port-scanning-techniques.html)
