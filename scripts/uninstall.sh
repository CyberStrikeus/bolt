#!/bin/sh
# Bolt - Uninstall Script
# Usage: curl -fsSL https://bolt.cyberstrike.io/uninstall.sh | sudo sh
# Platform: Linux (Debian/Ubuntu/Kali/RHEL/Alpine), macOS

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

printf "${CYAN}Uninstalling Bolt...${NC}\n\n"

PLATFORM=$(uname -s)

# Root check (macOS: allow non-root for user-level launchd)
if [ "$PLATFORM" != "Darwin" ] && [ "$(id -u)" -ne 0 ]; then
    printf "${RED}Please run as root: sudo sh uninstall.sh${NC}\n"
    exit 1
fi

# ============================================================================
# Docker install (both platforms)
# ============================================================================

if command -v docker >/dev/null 2>&1; then
    docker rm -f bolt >/dev/null 2>&1 && printf "   ${GREEN}+${NC} Docker container removed\n" || true
    docker volume rm bolt-data >/dev/null 2>&1 && printf "   ${GREEN}+${NC} Docker volume removed\n" || true
fi

# ============================================================================
# Platform-specific native uninstall
# ============================================================================

if [ "$PLATFORM" = "Darwin" ]; then
    # ===== macOS =====

    # launchd service
    PLIST_PATH="$HOME/Library/LaunchAgents/io.cyberstrike.bolt.plist"
    if [ -f "$PLIST_PATH" ]; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        rm -f "$PLIST_PATH"
        printf "   ${GREEN}+${NC} launchd service removed\n"
    fi

    # Legacy mcp-kali launchd
    LEGACY_PLIST="$HOME/Library/LaunchAgents/io.cyberstrike.mcp-kali.plist"
    if [ -f "$LEGACY_PLIST" ]; then
        launchctl unload "$LEGACY_PLIST" 2>/dev/null || true
        rm -f "$LEGACY_PLIST"
        printf "   ${GREEN}+${NC} Legacy mcp-kali launchd service removed\n"
    fi

    # npm packages
    if command -v npm >/dev/null 2>&1; then
        npm uninstall -g @cyberstrike/bolt >/dev/null 2>&1 && printf "   ${GREEN}+${NC} npm package removed\n" || true
        npm uninstall -g @cyberstrike-io/mcp-kali >/dev/null 2>&1 && printf "   ${GREEN}+${NC} Legacy npm package removed\n" || true
    fi

    # Data directories
    rm -rf /usr/local/var/bolt 2>/dev/null && printf "   ${GREEN}+${NC} /usr/local/var/bolt removed\n" || true
    rm -rf /usr/local/var/mcp-kali 2>/dev/null && printf "   ${GREEN}+${NC} /usr/local/var/mcp-kali removed\n" || true

else
    # ===== Linux =====

    # Systemd: bolt
    if [ -f /etc/systemd/system/bolt.service ]; then
        systemctl stop bolt >/dev/null 2>&1 || true
        systemctl disable bolt >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/bolt.service
        systemctl daemon-reload
        printf "   ${GREEN}+${NC} Systemd service removed\n"
    fi

    # Systemd: legacy mcp-kali
    if [ -f /etc/systemd/system/mcp-kali.service ]; then
        systemctl stop mcp-kali >/dev/null 2>&1 || true
        systemctl disable mcp-kali >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/mcp-kali.service
        systemctl daemon-reload
        printf "   ${GREEN}+${NC} Legacy mcp-kali service removed\n"
    fi

    # npm packages
    if command -v npm >/dev/null 2>&1; then
        npm uninstall -g @cyberstrike/bolt >/dev/null 2>&1 && printf "   ${GREEN}+${NC} npm package removed\n" || true
        npm uninstall -g @cyberstrike-io/mcp-kali >/dev/null 2>&1 && printf "   ${GREEN}+${NC} Legacy npm package removed\n" || true
    fi

    # Service users
    userdel -r bolt >/dev/null 2>&1 && printf "   ${GREEN}+${NC} bolt user removed\n" || true
    userdel -r mcp-kali >/dev/null 2>&1 && printf "   ${GREEN}+${NC} Legacy mcp-kali user removed\n" || true

    # Data directories
    rm -rf /var/lib/bolt 2>/dev/null && printf "   ${GREEN}+${NC} /var/lib/bolt removed\n" || true
    rm -rf /var/lib/mcp-kali 2>/dev/null && printf "   ${GREEN}+${NC} /var/lib/mcp-kali removed\n" || true

    # Sudoers
    rm -f /etc/sudoers.d/bolt 2>/dev/null || true
    rm -f /etc/sudoers.d/mcp-kali 2>/dev/null || true
fi

printf "\n${GREEN}Bolt uninstalled.${NC}\n"
