#!/usr/bin/env bash
set -euo pipefail

# Vigil v1.0 — Quick Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/vigil-agency/vigil/main/install.sh | bash

REPO="https://github.com/vigil-agency/vigil.git"
DIR="vigil"
PORT="${VIGIL_PORT:-4100}"

echo ""
echo "  ╦  ╦╦╔═╗╦╦  "
echo "  ╚╗╔╝║║ ╦║║  "
echo "   ╚╝ ╩╚═╝╩╩═╝"
echo "  The Security Agency That Never Sleeps"
echo ""

# ── Check prerequisites ──────────────────────────────────────────
command -v node >/dev/null 2>&1 || {
  echo "Error: Node.js is required. Install from https://nodejs.org"
  exit 1
}

NODE_MAJOR=$(node -v | cut -d'.' -f1 | tr -d 'v')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Error: Node.js 18+ required (found $(node -v))"
  exit 1
fi

command -v npm >/dev/null 2>&1 || {
  echo "Error: npm is required"
  exit 1
}

command -v git >/dev/null 2>&1 || {
  echo "Error: git is required"
  exit 1
}

# ── Clone ─────────────────────────────────────────────────────────
if [ -d "$DIR" ]; then
  echo "Directory '$DIR' already exists. Pulling latest..."
  cd "$DIR"
  git pull --ff-only
else
  echo "Cloning Vigil..."
  git clone "$REPO" "$DIR"
  cd "$DIR"
fi

# ── Setup ─────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"

  # Generate random admin password
  ADMIN_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16)
  sed -i "s|VIGIL_PASS=admin|VIGIL_PASS=$ADMIN_PASS|" .env
  echo ""
  echo "  Generated admin password: $ADMIN_PASS"
  echo "  (saved in .env — change if desired)"
  echo ""
else
  echo ".env already exists — skipping setup"
fi

# ── Install ───────────────────────────────────────────────────────
echo "Installing dependencies..."
npm install --production || {
  echo "Error: npm install failed"
  exit 1
}

# ── Install scanners (Debian/Ubuntu/Kali) ─────────────────────────
if command -v apt-get >/dev/null 2>&1; then
  echo ""
  echo "Debian-based system detected. Install security scanners? [y/N]"
  read -r INSTALL_SCANNERS </dev/tty 2>/dev/null || INSTALL_SCANNERS="n"
  if [[ "$INSTALL_SCANNERS" =~ ^[Yy]$ ]]; then
    echo "Installing scanners (requires sudo)..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq nmap nikto dnsutils whois openssl >/dev/null 2>&1 && echo "  ✓ apt scanners installed"

    # Nuclei
    if ! command -v nuclei >/dev/null 2>&1; then
      echo "  Installing nuclei..."
      NUCLEI_VER=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4 | tr -d v)
      if [ -n "$NUCLEI_VER" ]; then
        curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip && \
          sudo unzip -qo /tmp/nuclei.zip -d /usr/local/bin/ && rm -f /tmp/nuclei.zip && echo "  ✓ nuclei $NUCLEI_VER"
      else
        echo "  ✗ nuclei (could not fetch version — install manually)"
      fi
    fi

    # Trivy
    if ! command -v trivy >/dev/null 2>&1; then
      echo "  Installing trivy..."
      curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin >/dev/null 2>&1 && echo "  ✓ trivy" || echo "  ✗ trivy (install manually: https://trivy.dev)"
    fi
  fi
fi

# ── Check scanner availability ────────────────────────────────────
echo ""
echo "Scanner availability:"
for tool in nmap nuclei trivy nikto openssl dig whois; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  ✓ $tool"
  else
    echo "  ✗ $tool (optional — install for full functionality)"
  fi
done

# ── Start ─────────────────────────────────────────────────────────
echo ""
echo "Starting Vigil on port $PORT..."
echo "  URL:  http://localhost:$PORT"
echo "  User: admin"
if [ -f .env ]; then
  PASS=$(grep '^VIGIL_PASS=' .env | cut -d'=' -f2-)
  echo "  Pass: $PASS"
fi
echo ""
echo "  Stop with Ctrl+C"
echo ""

node server.js
