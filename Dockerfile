# ============================================================
# Bolt — MCP Security Tool Server
# Stage 1: Go tools builder
# Stage 2: Runtime (Ubuntu 24.04)
# ============================================================

FROM golang:1.24-bullseye AS go-builder

RUN go install -v \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/ffuf/ffuf/v2@latest \
    github.com/projectdiscovery/alterx/cmd/alterx@latest \
    github.com/owasp-amass/amass/v4/cmd/amass@latest \
    github.com/tomnomnom/assetfinder@latest \
    github.com/glebarez/cero@latest \
    github.com/sensepost/gowitness@latest \
    github.com/projectdiscovery/katana/cmd/katana@latest \
    github.com/tomnomnom/waybackurls@latest \
    github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest \
  && rm -rf /go/pkg /root/.cache/go-build

# ============================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System tools + build deps for node-pty native modules
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git unzip \
    nmap openssl socat dnsutils \
    masscan sslscan \
    python3 python3-pip python3-venv \
    ruby-full \
    nodejs npm \
    build-essential python3-dev \
  && rm -rf /var/lib/apt/lists/*

# massdns (required by shuffledns, not in apt)
RUN git clone --depth=1 https://github.com/blechschmidt/massdns /tmp/massdns \
  && make -C /tmp/massdns \
  && cp /tmp/massdns/bin/massdns /usr/local/bin/massdns \
  && rm -rf /tmp/massdns

# Go binaries
COPY --from=go-builder /go/bin/ /usr/local/bin/

# Bun
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:$PATH"

# Python tools
RUN python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir arjun scoutsuite \
  && git clone --depth=1 https://github.com/commixproject/commix /opt/commix \
  && git clone --depth=1 https://github.com/defparam/smuggler /opt/smuggler \
  && git clone --depth=1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap

ENV PATH="/opt/venv/bin:$PATH"

# Ruby tools
RUN gem install wpscan --no-document

# App
WORKDIR /app
COPY package.json bolt.config.json ./
COPY packages/ ./packages/

# Build Node.js MCP servers
RUN for dir in packages/mcp-servers/*/; do \
      [ -f "$dir/package.json" ] && \
      echo "[bolt] building $dir..." && \
      (cd "$dir" && npm install --silent && npm run build --silent) || true; \
    done

# Bolt dependencies
RUN bun install --production

# Data volume
RUN mkdir -p /data
VOLUME ["/data"]

ENV PORT=3001
ENV HOST=0.0.0.0
ENV DATA_DIR=/data
ENV NODE_ENV=production

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT:-3001}/health || exit 1

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bun", "run", "packages/core/src/http.ts"]
