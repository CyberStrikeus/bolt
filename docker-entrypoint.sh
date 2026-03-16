#!/bin/bash
set -e

export TERM=${TERM:-xterm}

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              ⚡ Bolt - Starting Up ⚡                     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

DATA_DIR=${DATA_DIR:-/data}
PORT=${PORT:-3001}

mkdir -p "$DATA_DIR"

echo -e "${GREEN}[BOLT]${NC} Data directory: $DATA_DIR"
echo -e "${GREEN}[BOLT]${NC} Port: $PORT"

# Generate admin token if not set
if [ -z "$MCP_ADMIN_TOKEN" ]; then
    MCP_ADMIN_TOKEN=$(openssl rand -hex 32)
    export MCP_ADMIN_TOKEN
    echo ""
    echo -e "${YELLOW}[BOLT]${NC} Generated admin token (save this!):"
    echo -e "${CYAN}       $MCP_ADMIN_TOKEN${NC}"
fi

export DOCKER_CONTAINER="true"
echo ""

echo -e "${GREEN}[BOLT]${NC} Starting server..."

"$@" &
SERVER_PID=$!

sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}[BOLT]${NC} Server failed to start"
    exit 1
fi

echo -e "${GREEN}[BOLT]${NC} Server started (PID: $SERVER_PID)"
echo ""

cat << EOF
${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}
${BLUE}║              ✅ Bolt Server Running!                      ║${NC}
${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}

${CYAN}Server URL:${NC}  http://YOUR_IP:$PORT

${CYAN}Admin token:${NC}
   docker logs bolt 2>&1 | grep "admin token"

${CYAN}Connect from CyberStrike:${NC}
   /bolt → add → paste URL + token

${CYAN}Health check:${NC}
   curl http://localhost:$PORT/health

${GREEN}Ready — listening for connections...${NC}

EOF

wait $SERVER_PID
