# Vigil v1.0 — Ubuntu 24.04 + Node.js 22 + Security Tools
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production

# System packages + security scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg ca-certificates unzip git openssh-client bash \
    python3 make g++ file \
    procps htop net-tools iproute2 lsb-release \
    nmap nikto dnsutils whois \
    openssl libssl-dev \
    cron \
    && rm -rf /var/lib/apt/lists/*

# PostgreSQL 17 client
RUN sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list' && \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg && \
    apt-get update && apt-get install -y --no-install-recommends postgresql-client-17 && \
    rm -rf /var/lib/apt/lists/*

# Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Docker CLI (for container security scanning)
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# GitHub CLI (for ephemeral proxy infrastructure / Codespace management)
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list && \
    apt-get update && apt-get install -y --no-install-recommends gh && \
    rm -rf /var/lib/apt/lists/*

# Nuclei scanner (pinned version with fallback)
RUN NUCLEI_VER=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4 | tr -d v) && \
    if [ -n "$NUCLEI_VER" ]; then \
      curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip && \
      unzip -qo /tmp/nuclei.zip -d /usr/local/bin/ && rm -f /tmp/nuclei.zip && \
      echo "Nuclei $NUCLEI_VER installed"; \
    else echo "WARNING: Could not install nuclei — API rate limited"; fi

# Trivy scanner
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    echo "Trivy installed" || echo "WARNING: Could not install trivy"

# Claude Code CLI (piggybacks off host's Max subscription via mounted credentials)
RUN npm install -g @anthropic-ai/claude-code && \
    echo "Claude Code CLI installed" || echo "WARNING: Could not install claude CLI"

# Non-root user (no sudo in production)
RUN useradd -m -s /bin/bash vigil

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --production

COPY server.js ./
COPY routes/ ./routes/
COPY lib/ ./lib/
COPY data/ ./data/
COPY docs/ ./docs/
COPY public/ ./public/

RUN mkdir -p /app/data/reports /app/data/backups /home/vigil/.config/gh /home/vigil/.claude && \
    chown -R vigil:vigil /app /home/vigil

# Entrypoint: fix ownership of mounted dirs then exec as vigil
RUN printf '#!/bin/bash\nchown -R vigil:vigil /home/vigil/.claude 2>/dev/null || true\nexec gosu vigil "$@"\n' > /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

# gosu for dropping root after fixing permissions
RUN curl -fsSL "https://github.com/tianon/gosu/releases/download/1.17/gosu-amd64" -o /usr/local/bin/gosu && \
    chmod +x /usr/local/bin/gosu

ENV VIGIL_PORT=4100
ENV HOME=/home/vigil

EXPOSE 4100

ENTRYPOINT ["entrypoint.sh"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -sf http://localhost:4100/api/health || exit 1

CMD ["node", "server.js"]
