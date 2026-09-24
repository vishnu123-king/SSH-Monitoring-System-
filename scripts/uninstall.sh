#!/usr/bin/env bash
# ==============================================================================
# Linux SSH Security Monitor - Uninstaller
# Safe removal of systemd service and application code (preserves database)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This uninstaller must be run as root (use: sudo ./scripts/uninstall.sh)${NC}"
   exit 1
fi

echo -e "${YELLOW}Stopping and disabling ssh-security-monitor.service...${NC}"
systemctl stop ssh-security-monitor.service 2>/dev/null || true
systemctl disable ssh-security-monitor.service 2>/dev/null || true

echo -e "${CYAN}Removing systemd service unit...${NC}"
rm -f /etc/systemd/system/ssh-security-monitor.service
systemctl daemon-reload

echo -e "${CYAN}Removing CLI symlink...${NC}"
rm -f /usr/local/bin/ssh-monitor

APP_DIR="/opt/ssh-security-monitor"
DATA_DIR="/opt/ssh-security-monitor/data"

echo -e "${GREEN}[NOTE] Data directory preserved at:${NC} ${DATA_DIR}"
echo "To permanently wipe all historical SQLite events and alerts, run:"
echo "  sudo rm -rf ${APP_DIR}"

echo -e "${GREEN}[SUCCESS] SSH Security Monitor service uninstalled.${NC}"
