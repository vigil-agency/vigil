FROM kalilinux/kali-rolling

LABEL maintainer="Vigil <hello@vigil.agency>"
LABEL description="Kali Linux security bridge — wraps CLI tools as REST API"

# Avoid interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# ── System packages + Kali tools ───────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    sqlmap \
    gobuster \
    dirb \
    hydra \
    whois \
    dnsrecon \
    dnsutils \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    curl \
    jq \
    ca-certificates \
    supervisor \
    mcp-kali-server \
    && rm -rf /var/lib/apt/lists/*

# ── Install Go-based tools (nuclei, subfinder, httpx) ──────────────
RUN curl -fsSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name' | sed 's/^v//')_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(curl -fsSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r '.tag_name' | sed 's/^v//')_linux_amd64.zip -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

RUN curl -fsSL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_$(curl -fsSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r '.tag_name' | sed 's/^v//')_linux_amd64.zip -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip

# ── Python OSINT dependencies ──────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages \
    phonenumbers \
    requests \
    dnspython \
    python-whois

# ── Update nuclei templates ───────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── App setup ──────────────────────────────────────────────────────
WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY bridge.js ./
COPY parsers/ ./parsers/
COPY supervisord.conf /etc/supervisor/conf.d/bridge.conf

# ── Runtime ────────────────────────────────────────────────────────
ENV PORT=9877
EXPOSE 9877

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -f http://localhost:9877/health || exit 1

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/bridge.conf"]
