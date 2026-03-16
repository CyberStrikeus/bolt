# ============================================================
# Stage 1: Build the TypeScript project
# ============================================================
FROM node:20-slim AS builder

WORKDIR /build

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install

# Copy source and build
COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# ============================================================
# Stage 2: Kali Linux runtime with Node.js and tools
# ============================================================
FROM kalilinux/kali-rolling AS runtime

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Node.js 20
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
  && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
  && apt-get install -y --no-install-recommends nodejs \
  && rm -rf /var/lib/apt/lists/*

# Install core Kali tools (grouped by category)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Reconnaissance & Scanning
    nmap \
    nikto \
    dirb \
    ffuf \
    gobuster \
    wfuzz \
    whatweb \
    wafw00f \
    sslscan \
    # Web Application
    sqlmap \
    # Subdomain / DNS
    subfinder \
    httpx-toolkit \
    amass \
    # Password Attacks
    john \
    hashcat \
    hydra \
    medusa \
    # Active Directory / Windows
    netexec \
    impacket-scripts \
    enum4linux-ng \
    responder \
    bloodhound \
    certipy-ad \
    # Exploitation
    exploitdb \
    metasploit-framework \
    # Vulnerability Scanning
    nuclei \
    # Utilities
    testssl.sh \
    openssl \
    socat \
  && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy built output and dependencies from builder
COPY --from=builder /build/dist/ ./dist/
COPY --from=builder /build/node_modules/ ./node_modules/
COPY --from=builder /build/package.json ./

# Copy tool definitions
COPY src/definitions/ ./src/definitions/

# Create data directory for keys and scan results
RUN mkdir -p /data

# Default environment
ENV PORT=3001
ENV HOST=0.0.0.0
ENV DATA_DIR=/data
ENV NODE_ENV=production

ENV DOCKER_CONTAINER=true

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT:-3001}/health || exit 1

# Copy entrypoint script
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "dist/http.js"]
