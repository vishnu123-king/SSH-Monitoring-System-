#!/usr/bin/env bash
# ==============================================================================
# Linux SSH Security Monitor - Automated Production Installer
# Supported: Debian 12+, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}  Linux SSH Security Monitor - Production Installer  ${NC}"
echo -e "${CYAN}====================================================${NC}"

# 1. Root Check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This installer must be run as root (use: sudo ./scripts/install.sh)${NC}"
   exit 1
fi

# 2. Operating System Check
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_VERSION_ID=$VERSION_ID
    echo -e "${GREEN}[✓] Detected OS:${NC} $PRETTY_NAME"
    if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
        echo -e "${YELLOW}[WARNING] Target OS is not Debian/Ubuntu. Proceeding with caution...${NC}"
    fi
else
    echo -e "${RED}[ERROR] Cannot determine Linux distribution (/etc/os-release missing).${NC}"
    exit 1
fi

# 3. Python 3.12+ Verification
PYTHON_BIN=""
for candidate in python3.12 python3.13 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PY_VER=$($candidate -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$($candidate -c 'import sys; print(sys.version_info.major)')
        PY_MINOR=$($candidate -c 'import sys; print(sys.version_info.minor)')
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 12 ]; then
            PYTHON_BIN=$(command -v "$candidate")
            echo -e "${GREEN}[✓] Compatible Python found:${NC} $PYTHON_BIN (v$PY_VER)"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[ERROR] Python 3.12+ is required. Found older version or missing.${NC}"
    echo "Install Python 3.12+ via:"
    echo "  sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    exit 1
fi

# 4. Check systemd and journalctl
if ! command -v journalctl >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] journalctl utility is required but not found in PATH.${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] systemd journalctl is available.${NC}"

# 5. Create Dedicated Service User
APP_USER="sshmon"
APP_DIR="/opt/ssh-security-monitor"
CONFIG_DIR="/etc/ssh-security-monitor"
LOG_DIR="/var/log/ssh-security-monitor"

if ! id "$APP_USER" >/dev/null 2>&1; then
    echo -e "${CYAN}[*] Creating system service user '${APP_USER}'...${NC}"
    useradd -r -s /usr/sbin/nologin -d "$APP_DIR" "$APP_USER"
fi

# Add user to systemd-journal and adm groups to read journals without root
usermod -aG systemd-journal,adm "$APP_USER"
echo -e "${GREEN}[✓] Configured permissions:${NC} ${APP_USER} added to 'systemd-journal' group."

# 6. Create Target Directories
echo -e "${CYAN}[*] Creating directory structure...${NC}"
mkdir -p "$APP_DIR" "$APP_DIR/data" "$CONFIG_DIR" "$LOG_DIR"

# 7. Copy Project Files
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo -e "${CYAN}[*] Deploying application codebase to ${APP_DIR}...${NC}"
cp -r "$SOURCE_DIR/app" "$APP_DIR/"
cp -r "$SOURCE_DIR/frontend" "$APP_DIR/"
cp -r "$SOURCE_DIR/alembic" "$APP_DIR/"
cp "$SOURCE_DIR/alembic.ini" "$APP_DIR/"
cp "$SOURCE_DIR/pyproject.toml" "$APP_DIR/"
cp "$SOURCE_DIR/requirements.txt" "$APP_DIR/"
cp "$SOURCE_DIR/config.yaml" "$CONFIG_DIR/config.yaml"

if [ -f "$SOURCE_DIR/config.yaml" ]; then
    cp "$SOURCE_DIR/config.yaml" "$APP_DIR/config.yaml"
fi

# 8. Setup Virtualenv & Dependencies
echo -e "${CYAN}[*] Setting up Python virtual environment in ${APP_DIR}/.venv...${NC}"
"$PYTHON_BIN" -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip setuptools wheel
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
"$APP_DIR/.venv/bin/pip" install -e "$APP_DIR"

# 9. Environment File & Random JWT Secret
ENV_FILE="$CONFIG_DIR/ssh-security-monitor.env"
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${CYAN}[*] Generating cryptographically secure JWT secret...${NC}"
    JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    ADMIN_PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')

    cat <<EOF > "$ENV_FILE"
# Generated SSH Security Monitor Production Environment
API_HOST=0.0.0.0
API_PORT=8000
DATABASE_URL=sqlite:////opt/ssh-security-monitor/data/ssh_monitor.db
LOG_LEVEL=INFO
JWT_SECRET_KEY=${JWT_SECRET}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASS}
SSH_SERVICE=auto
RETENTION_DAYS=30
ALERT_RETENTION_DAYS=90
EOF
    chmod 600 "$ENV_FILE"
    echo -e "${GREEN}[✓] Environment configuration written to ${ENV_FILE}${NC}"
    echo -e "${YELLOW}[IMPORTANT] Default Admin Credentials generated:${NC}"
    echo -e "  Username: admin"
    echo -e "  Password: ${ADMIN_PASS}"
    echo -e "  (Save this password! You can change it anytime via: ssh-monitor create-user)"
fi

cp "$ENV_FILE" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

# 10. Database Schema Migrations & Initialization
echo -e "${CYAN}[*] Running database migrations...${NC}"
cd "$APP_DIR"
"$APP_DIR/.venv/bin/alembic" upgrade head || "$APP_DIR/.venv/bin/python" -c "from app.database.database import init_db; init_db()"

# Fix Ownership
chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR" "$CONFIG_DIR"
chmod 750 "$APP_DIR"
chmod 770 "$APP_DIR/data"

# Create symlink for CLI tool
ln -sf "$APP_DIR/.venv/bin/ssh-monitor" /usr/local/bin/ssh-monitor

# 11. Install Systemd Service
echo -e "${CYAN}[*] Installing systemd unit file...${NC}"
cp "$SOURCE_DIR/systemd/ssh-security-monitor.service" /etc/systemd/system/ssh-security-monitor.service
systemctl daemon-reload
systemctl enable ssh-security-monitor.service
systemctl restart ssh-security-monitor.service

# 12. Health Check Validation
echo -e "${CYAN}[*] Verifying service health...${NC}"
sleep 2

if systemctl is-active --quiet ssh-security-monitor.service; then
    echo -e "${GREEN}[SUCCESS] SSH Security Monitor is ACTIVE and RUNNING!${NC}"
    echo -e "Dashboard URL: ${CYAN}http://127.0.0.1:8000/${NC}"
    echo -e "API Health:    ${CYAN}http://127.0.0.1:8000/api/health${NC}"
    echo -e "CLI Diagnostic: run '${CYAN}ssh-monitor health${NC}'"
else
    echo -e "${RED}[WARNING] Service did not report active status. Checking journalctl logs:${NC}"
    journalctl -u ssh-security-monitor.service -n 20 --no-pager
    exit 1
fi
