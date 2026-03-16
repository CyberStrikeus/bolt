#!/bin/sh
# Bolt v2 - Universal Installation Script
# Usage: curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh
# Platform: Linux (Debian/Ubuntu/Kali/RHEL/Alpine), macOS
#
# Auto-detects: Docker → container, no Docker → native (Bun + tools)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

BOLT_IMAGE="ghcr.io/cyberstrikeus/bolt:latest"
BOLT_PORT="${BOLT_PORT:-3001}"
BOLT_REPO="https://github.com/CyberStrikeus/bolt.git"

printf "${BLUE}"
cat << 'BANNER'
 ________  ________  ___   _________
|\   __  \|\   __  \|\  \ |\___   ___\
\ \  \|\ /\ \  \|\  \ \  \\|___ \  \_|
 \ \   __  \ \  \\\  \ \  \    \ \  \
  \ \  \|\  \ \  \\\  \ \  \____\ \  \
   \ \_______\ \_______\ \_______\ \__\
    \|_______|\|_______|\|_______|\|__|
BANNER
printf "${NC}\n"
printf "${CYAN}Bolt v2 — Plugin-based security tool server${NC}\n\n"

# ============================================================================
# STEP 1: Detect environment
# ============================================================================

printf "${YELLOW}[1/5]${NC} Detecting environment...\n"

PLATFORM=$(uname -s)
ARCH=$(uname -m)
OS_ID="unknown"
OS_NAME="Unknown"

case "$ARCH" in
    x86_64|amd64) ARCH_NAME="amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *) printf "${RED}Unsupported architecture: $ARCH${NC}\n"; exit 1 ;;
esac

if [ "$PLATFORM" = "Darwin" ]; then
    OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
    OS_ID="macos"
    BOLT_DATA="/usr/local/var/bolt"

    if ! command -v brew >/dev/null 2>&1; then
        printf "${RED}Homebrew not found. Install it first:${NC}\n"
        printf "   ${CYAN}/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"${NC}\n"
        exit 1
    fi
    PKG="brew"
    PKG_UPDATE="brew update"
    PKG_INSTALL="brew install"

    PRIMARY_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "127.0.0.1")
else
    BOLT_DATA="/var/lib/bolt"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_ID=$ID
    fi

    if command -v apt-get >/dev/null 2>&1; then
        PKG="apt-get"
        PKG_UPDATE="apt-get update -qq"
        PKG_INSTALL="apt-get install -y -qq"
    elif command -v yum >/dev/null 2>&1; then
        PKG="yum"
        PKG_UPDATE="yum check-update || true"
        PKG_INSTALL="yum install -y"
    elif command -v apk >/dev/null 2>&1; then
        PKG="apk"
        PKG_UPDATE="apk update"
        PKG_INSTALL="apk add"
    else
        printf "${RED}Unsupported package manager${NC}\n"
        exit 1
    fi

    PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
fi

if [ "$PLATFORM" != "Darwin" ] && [ "$(id -u)" -ne 0 ]; then
    printf "${RED}Please run as root:${NC}\n"
    printf "   ${CYAN}curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh${NC}\n"
    exit 1
fi

INSTALL_METHOD=""
if command -v docker >/dev/null 2>&1; then
    INSTALL_METHOD="docker"
else
    INSTALL_METHOD="native"
fi

printf "   ${GREEN}+${NC} OS: $OS_NAME ($PLATFORM)\n"
printf "   ${GREEN}+${NC} Arch: $ARCH ($ARCH_NAME)\n"
printf "   ${GREEN}+${NC} IP: $PRIMARY_IP\n"
printf "   ${GREEN}+${NC} Method: $INSTALL_METHOD\n"
printf "\n"

# ============================================================================
# STEP 2: Install dependencies
# ============================================================================

printf "${YELLOW}[2/5]${NC} Installing dependencies...\n"

$PKG_UPDATE >/dev/null 2>&1 || true

if [ "$PLATFORM" = "Darwin" ]; then
    for dep in openssl curl; do
        command -v "$dep" >/dev/null 2>&1 || $PKG_INSTALL "$dep" >/dev/null 2>&1 || true
    done
else
    for dep in curl openssl ca-certificates git; do
        command -v "$dep" >/dev/null 2>&1 || $PKG_INSTALL "$dep" >/dev/null 2>&1 || true
    done
fi

printf "   ${GREEN}+${NC} Base dependencies ready\n"

# Bun for native path
if [ "$INSTALL_METHOD" = "native" ] && ! command -v bun >/dev/null 2>&1; then
    printf "   ${CYAN}i${NC} Installing Bun...\n"
    curl -fsSL https://bun.sh/install | bash >/dev/null 2>&1
    export PATH="$HOME/.bun/bin:$PATH"
    printf "   ${GREEN}+${NC} Bun installed\n"
fi

printf "\n"

# ============================================================================
# STEP 3: Install Bolt
# ============================================================================

printf "${YELLOW}[3/5]${NC} Installing Bolt...\n"

ADMIN_TOKEN=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 64)

if [ "$INSTALL_METHOD" = "docker" ]; then
    # ===== DOCKER PATH =====
    docker rm -f bolt >/dev/null 2>&1 || true

    printf "   ${CYAN}i${NC} Pulling $BOLT_IMAGE...\n"
    docker pull "$BOLT_IMAGE" 2>&1 | tail -1

    docker run -d \
        --name bolt \
        --restart unless-stopped \
        -p "$BOLT_PORT:$BOLT_PORT" \
        -v bolt-data:/data \
        -e MCP_ADMIN_TOKEN="$ADMIN_TOKEN" \
        -e PORT="$BOLT_PORT" \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        "$BOLT_IMAGE" >/dev/null 2>&1

    printf "   ${GREEN}+${NC} Docker container started\n"

else
    # ===== NATIVE PATH =====

    # Install security tools
    printf "   ${CYAN}i${NC} Installing security tools...\n"

    if [ "$PLATFORM" = "Darwin" ]; then
        TOOLS="nmap"
        for tool in $TOOLS; do
            brew install "$tool" >/dev/null 2>&1 || true
        done
        # Go tools via brew
        if ! command -v go >/dev/null 2>&1; then
            brew install go >/dev/null 2>&1 || true
        fi
    else
        # Linux: base tools
        $PKG_INSTALL nmap openssl socat dnsutils >/dev/null 2>&1 || true

        # Go for ProjectDiscovery tools
        if ! command -v go >/dev/null 2>&1; then
            $PKG_INSTALL golang-go >/dev/null 2>&1 || true
        fi
    fi

    # Install Go-based security tools
    if command -v go >/dev/null 2>&1; then
        export GOPATH="${GOPATH:-$HOME/go}"
        export PATH="$GOPATH/bin:$PATH"
        printf "   ${CYAN}i${NC} Installing Go security tools...\n"
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >/dev/null 2>&1 || true
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1 || true
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1 || true
        go install -v github.com/ffuf/ffuf/v2@latest >/dev/null 2>&1 || true
        printf "   ${GREEN}+${NC} Go tools installed\n"
    fi

    printf "   ${GREEN}+${NC} Security tools installed\n"

    # Clone bolt repo
    printf "   ${CYAN}i${NC} Installing Bolt from git...\n"
    BOLT_INSTALL_DIR="$BOLT_DATA/bolt"
    mkdir -p "$BOLT_DATA"

    if [ -d "$BOLT_INSTALL_DIR" ]; then
        cd "$BOLT_INSTALL_DIR" && git pull --quiet
    else
        git clone --depth 1 "$BOLT_REPO" "$BOLT_INSTALL_DIR" >/dev/null 2>&1
    fi

    cd "$BOLT_INSTALL_DIR" && bun install --production >/dev/null 2>&1
    printf "   ${GREEN}+${NC} Bolt installed\n"

    BUN_BIN=$(command -v bun)
    BOLT_ENTRY="$BOLT_INSTALL_DIR/packages/core/src/http.ts"

    if [ "$PLATFORM" = "Darwin" ]; then
        # ===== macOS: launchd =====
        PLIST_PATH="$HOME/Library/LaunchAgents/io.cyberstrike.bolt.plist"
        mkdir -p "$HOME/Library/LaunchAgents"

        cat > "$PLIST_PATH" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.cyberstrike.bolt</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BUN_BIN</string>
        <string>run</string>
        <string>$BOLT_ENTRY</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DATA_DIR</key>
        <string>$BOLT_DATA</string>
        <key>PORT</key>
        <string>$BOLT_PORT</string>
        <key>MCP_ADMIN_TOKEN</key>
        <string>$ADMIN_TOKEN</string>
        <key>NODE_ENV</key>
        <string>production</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$BOLT_DATA/bolt.log</string>
    <key>StandardErrorPath</key>
    <string>$BOLT_DATA/bolt.err</string>
    <key>WorkingDirectory</key>
    <string>$BOLT_INSTALL_DIR</string>
</dict>
</plist>
PLIST

        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        launchctl load "$PLIST_PATH"
        printf "   ${GREEN}+${NC} launchd service started\n"

    else
        # ===== Linux: systemd =====

        if ! id "bolt" >/dev/null 2>&1; then
            useradd -r -s /bin/bash -m -d "$BOLT_DATA" bolt 2>/dev/null || \
            useradd -r -s /bin/sh -m -d "$BOLT_DATA" bolt 2>/dev/null || true
        fi
        chown -R bolt:bolt "$BOLT_DATA" 2>/dev/null || true

        if command -v setcap >/dev/null 2>&1; then
            for tool in nmap; do
                TOOL_PATH=$(command -v "$tool" 2>/dev/null || true)
                if [ -n "$TOOL_PATH" ] && [ -f "$TOOL_PATH" ]; then
                    setcap cap_net_raw,cap_net_admin+eip "$TOOL_PATH" 2>/dev/null || true
                fi
            done
        fi

        cat > /etc/sudoers.d/bolt << 'SUDOERS'
bolt ALL=(ALL) NOPASSWD: ALL
Defaults:bolt !requiretty
SUDOERS
        chmod 0440 /etc/sudoers.d/bolt

        cat > /etc/systemd/system/bolt.service << SERVICE
[Unit]
Description=Bolt MCP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bolt
Group=bolt
WorkingDirectory=$BOLT_INSTALL_DIR
Environment=DATA_DIR=$BOLT_DATA
Environment=PORT=$BOLT_PORT
Environment=MCP_ADMIN_TOKEN=$ADMIN_TOKEN
Environment=NODE_ENV=production
Environment=PATH=$GOPATH/bin:$HOME/.bun/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$BUN_BIN run $BOLT_ENTRY
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ReadWritePaths=$BOLT_DATA

[Install]
WantedBy=multi-user.target
SERVICE

        systemctl daemon-reload
        systemctl enable bolt.service >/dev/null 2>&1
        systemctl start bolt.service

        printf "   ${GREEN}+${NC} Systemd service started\n"
    fi
fi

printf "\n"

# ============================================================================
# STEP 4: Wait for health
# ============================================================================

printf "${YELLOW}[4/5]${NC} Waiting for server...\n"

RETRIES=15
while [ $RETRIES -gt 0 ]; do
    if curl -sf "http://localhost:$BOLT_PORT/health" >/dev/null 2>&1; then
        printf "   ${GREEN}+${NC} Server healthy\n"
        break
    fi
    RETRIES=$((RETRIES - 1))
    sleep 2
done

if [ $RETRIES -eq 0 ]; then
    printf "   ${YELLOW}!${NC} Server may still be starting...\n"
    if [ "$INSTALL_METHOD" = "docker" ]; then
        printf "      Check: ${CYAN}docker logs bolt${NC}\n"
    elif [ "$PLATFORM" = "Darwin" ]; then
        printf "      Check: ${CYAN}cat $BOLT_DATA/bolt.log${NC}\n"
    else
        printf "      Check: ${CYAN}journalctl -u bolt -n 50${NC}\n"
    fi
fi

printf "\n"

# ============================================================================
# STEP 5: Done
# ============================================================================

printf "${GREEN}=======================================================${NC}\n"
printf "${GREEN}  Bolt v2 installed successfully${NC}\n"
printf "${GREEN}=======================================================${NC}\n"
printf "\n"
printf "  ${CYAN}Server URL:${NC}    http://$PRIMARY_IP:$BOLT_PORT\n"
printf "  ${CYAN}Admin token:${NC}   $ADMIN_TOKEN\n"
printf "  ${CYAN}Method:${NC}        $INSTALL_METHOD\n"
printf "\n"
printf "  ${CYAN}Connect from CyberStrike:${NC}\n"
printf "     /bolt  ->  add  ->  paste URL + token\n"
printf "\n"

if [ "$INSTALL_METHOD" = "docker" ]; then
    printf "  ${CYAN}Management:${NC}\n"
    printf "     docker logs bolt        # logs\n"
    printf "     docker restart bolt     # restart\n"
    printf "     docker stop bolt        # stop\n"
elif [ "$PLATFORM" = "Darwin" ]; then
    printf "  ${CYAN}Management:${NC}\n"
    printf "     cat $BOLT_DATA/bolt.log                          # logs\n"
    printf "     launchctl stop io.cyberstrike.bolt               # stop\n"
    printf "     launchctl start io.cyberstrike.bolt              # start\n"
else
    printf "  ${CYAN}Management:${NC}\n"
    printf "     systemctl status bolt   # status\n"
    printf "     journalctl -u bolt -f   # logs\n"
    printf "     systemctl restart bolt  # restart\n"
    printf "     systemctl stop bolt     # stop\n"
fi

printf "\n"
printf "  ${CYAN}Health:${NC}  curl http://localhost:$BOLT_PORT/health\n"
printf "\n"
