# ============================================================
# Bolt v2 — Plugin-based security tool server
# Ubuntu 24.04 + Bun + Go tools (~800MB vs ~5GB Kali)
# ============================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git unzip \
    nmap openssl socat dnsutils \
    golang-go \
  && rm -rf /var/lib/apt/lists/*

# Bun
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:$PATH"

# Go tools (ProjectDiscovery suite + ffuf)
ENV GOPATH=/root/go
ENV PATH="/root/go/bin:$PATH"

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    rm -rf /root/go/pkg /root/.cache/go-build

# App
WORKDIR /app
COPY package.json bolt.config.json ./
COPY packages/ ./packages/
RUN bun install --production

# Data volume
RUN mkdir -p /data
VOLUME ["/data"]

# Environment
ENV PORT=3001
ENV HOST=0.0.0.0
ENV DATA_DIR=/data
ENV NODE_ENV=production
ENV DOCKER_CONTAINER=true

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT:-3001}/health || exit 1

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bun", "run", "packages/core/src/http.ts"]
