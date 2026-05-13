#!/bin/bash
# APKShield-PT — Kali Linux Setup Script

set -e
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}"
echo "   █████╗ ██████╗ ██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ "
echo "  ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗"
echo "  ███████║██████╔╝█████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║"
echo "  ██╔══██║██╔═══╝ ██╔═██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║"
echo "  ██║  ██║██║     ██║  ██╗███████║██║  ██║██║███████╗███████╗██████╔╝"
echo "  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝"
echo -e "${NC}"
echo -e "${YELLOW}  Android PT Tool — Kali Setup${NC}"
echo ""

echo -e "${CYAN}[*] Updating package list...${NC}"
sudo apt-get update -qq

install_if_missing() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${YELLOW}[*] Installing $2...${NC}"
        sudo apt-get install -y "$2"
    else
        echo -e "${GREEN}[✔] $1 already installed${NC}"
    fi
}

install_if_missing apktool apktool
install_if_missing jadx jadx
install_if_missing adb adb

echo -e "${CYAN}[*] Installing Python packages...${NC}"
pip3 install rich anthropic frida-tools objection --break-system-packages 2>/dev/null || \
pip3 install rich anthropic frida-tools objection

chmod +x "$(dirname "$0")/apkshield.py"

echo ""
echo -e "${YELLOW}[?] Anthropic API key for AI analysis? (press Enter to skip — tool works without it):${NC}"
read -r API_KEY
if [ -n "$API_KEY" ]; then
    echo "export ANTHROPIC_API_KEY=$API_KEY" >> ~/.bashrc
    echo -e "${GREEN}[✔] Saved to ~/.bashrc. Run: source ~/.bashrc${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗"
echo -e "║              Setup complete!                     ║"
echo -e "║                                                  ║"
echo -e "║  python3 apkshield.py App.apk --no-ai           ║"
echo -e "║  python3 apkshield.py App.apk -o ./results      ║"
echo -e "║  python3 apkshield.py --check-deps              ║"
echo -e "╚══════════════════════════════════════════════════╝${NC}"
