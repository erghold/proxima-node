#!/usr/bin/env bash
#
# proxima-node — One-command VPN exit node setup
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/erghold/proxima-node/main/setup.sh | bash
#   or:
#   git clone https://github.com/erghold/proxima-node.git && cd proxima-node && bash setup.sh
#   or with component selection:
#   bash setup.sh --only harden
#
# Components installed:
#   1. System hardening (sysctl, SSH, UFW)
#   2. Outline Shadowsocks server (port 8388)
#   3. ssconf HTTPS server (port 8390)
#   4. Proxima speed test server (port 8999)
#   5. Zapret agent (management API, port 5050)
#   6. Zapret nfqws2 (DPI bypass, --zapret flag)
#
# AmneziaWG + Xray are NOT installed by this script.
# Use the AmneziaVPN client app to set up AWG + Xray on the server.
#

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

REPO_URL="https://github.com/erghold/proxima-node.git"
INSTALL_DIR="/opt/proxima-node"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Default: install everything
INSTALL_HARDEN=1
INSTALL_OUTLINE=1
INSTALL_SSCONF=1
INSTALL_SPEEDTEST=1
INSTALL_ZAPRET=0
INSTALL_ZAPRET_AGENT=0

banner() {
    echo -e "${CYAN}"
    echo "  ____                 _                                       _      "
    echo " |  _ \ _ __ _____  _(_)_ __ ___   __ _       _ __   ___   __| | ___ "
    echo " | |_) | '__/ _ \ \/ / | '_ \` _ \ / _\` |___  | '_ \ / _ \ / _\` |/ _ \\"
    echo " |  __/| | | (_) >  <| | | | | | | (_| |___| | | | | (_) | (_| |  __/"
    echo " |_|   |_|  \___/_/\_\_|_| |_| |_|\__,_|     |_| |_|\___/ \__,_|\___|"
    echo -e "${NC}"
    echo -e "${BOLD}  VPN Exit Node Setup${NC}"
    echo ""
}

# ─── Parse arguments ─────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-outline)
                INSTALL_OUTLINE=0; INSTALL_SSCONF=0; shift ;;
            --no-speedtest)
                INSTALL_SPEEDTEST=0; shift ;;
            --zapret)
                INSTALL_ZAPRET=1; INSTALL_ZAPRET_AGENT=1; shift ;;
            --only)
                # Reset all, then enable only the specified component
                INSTALL_HARDEN=0; INSTALL_OUTLINE=0; INSTALL_SSCONF=0
                INSTALL_SPEEDTEST=0
                INSTALL_ZAPRET=0; INSTALL_ZAPRET_AGENT=0
                case "${2:-}" in
                    harden)        INSTALL_HARDEN=1 ;;
                    outline)       INSTALL_OUTLINE=1; INSTALL_SSCONF=1 ;;
                    speedtest)     INSTALL_SPEEDTEST=1 ;;
                    zapret)        INSTALL_ZAPRET=1 ;;
                    zapret-agent)  INSTALL_ZAPRET_AGENT=1 ;;
                    zapret-all)    INSTALL_ZAPRET=1; INSTALL_ZAPRET_AGENT=1 ;;
                    *) echo -e "${RED}Unknown component: ${2:-}${NC}"; exit 1 ;;
                esac
                shift 2 ;;
            -h|--help)
                echo "Usage: bash setup.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --no-outline     Skip Outline SS + ssconf"
                echo "  --no-speedtest   Skip speed test server"
                echo "  --zapret         Include zapret (nfqws2) + agent"
                echo "  --only <comp>    Install only: harden, outline, speedtest,"
                echo "                   zapret, zapret-agent, zapret-all"
                echo "  -h, --help       Show this help"
                exit 0 ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
        esac
    done
}

# ─── Pre-flight checks ───────────────────────────────────────────────

preflight() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        exit 1
    fi

    if [[ ! -f /etc/os-release ]]; then
        echo -e "${RED}[ERROR]${NC} Cannot detect OS"
        exit 1
    fi

    # shellcheck disable=SC1091
    source /etc/os-release
    echo -e "${GREEN}[INFO]${NC} OS: $PRETTY_NAME"

    # Install git if needed
    if ! command -v git &>/dev/null; then
        echo -e "${GREEN}[INFO]${NC} Installing prerequisites..."
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y -qq git curl openssl > /dev/null 2>&1
    fi

    # Ensure required tools
    for cmd in curl openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            apt-get install -y -qq "$cmd" > /dev/null 2>&1
        fi
    done
}

# ─── Clone or update repo ────────────────────────────────────────────

setup_repo() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        echo -e "${GREEN}[INFO]${NC} Updating proxima-node..."
        git -C "$INSTALL_DIR" pull --quiet
    elif [[ -f "$(pwd)/scripts/common.sh" ]]; then
        # Running from cloned repo
        INSTALL_DIR="$(pwd)"
        echo -e "${GREEN}[INFO]${NC} Using local repo at $INSTALL_DIR"
    else
        echo -e "${GREEN}[INFO]${NC} Cloning proxima-node..."
        git clone --quiet "$REPO_URL" "$INSTALL_DIR"
    fi
}

# ─── Run setup ────────────────────────────────────────────────────────

run_setup() {
    echo ""

    # System update (fully non-interactive)
    echo -e "${BLUE}[STEP]${NC} ${BOLD}Updating system packages...${NC}"
    apt-get update -qq > /dev/null 2>&1
    apt-get upgrade -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" > /dev/null 2>&1
    apt-get install -y -qq python3 curl openssl > /dev/null 2>&1
    echo -e "${GREEN}[INFO]${NC} System packages updated"

    if [[ "${INSTALL_HARDEN}" -eq 1 ]]; then
        # shellcheck disable=SC1091
        source "$INSTALL_DIR/scripts/01-harden.sh"
        setup_harden
        echo ""
    fi

    if [[ "${INSTALL_OUTLINE}" -eq 1 ]]; then
        # shellcheck disable=SC1091
        source "$INSTALL_DIR/scripts/02-outline-ss.sh"
        setup_outline_ss
        echo ""
    fi

    if [[ "${INSTALL_SSCONF}" -eq 1 ]]; then
        # shellcheck disable=SC1091
        source "$INSTALL_DIR/scripts/03-ssconf.sh"
        setup_ssconf
        echo ""
    fi

    if [[ "${INSTALL_SPEEDTEST}" -eq 1 ]]; then
        # shellcheck disable=SC1091
        source "$INSTALL_DIR/scripts/04-speedtest.sh"
        setup_speedtest
        echo ""
    fi

    if [[ "${INSTALL_ZAPRET}" -eq 1 ]]; then
        # shellcheck disable=SC1091
        source "$INSTALL_DIR/scripts/07-zapret.sh"
        setup_zapret
        echo ""
    fi

    if [[ "${INSTALL_ZAPRET_AGENT}" -eq 1 ]]; then
        # shellcheck disable=SC1091
        source "$INSTALL_DIR/scripts/06-zapret-agent.sh"
        setup_zapret_agent
        echo ""
    fi
}

# ─── Summary ──────────────────────────────────────────────────────────

print_summary() {
    local server_ip node_id ss_password ss_prefix ssconf_token speedtest_key
    # shellcheck disable=SC1091
    source "$INSTALL_DIR/scripts/common.sh"

    server_ip=$(read_config "SERVER_IP")
    node_id=$(read_config "NODE_ID")
    ss_password=$(read_config "SS_PASSWORD")
    ss_prefix=$(read_config "SS_PREFIX")
    ssconf_token=$(read_config "SSCONF_TOKEN")
    speedtest_key=$(read_config "SPEEDTEST_API_KEY")

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  PROXIMA NODE — SETUP COMPLETE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}Server IP:${NC} ${server_ip}"
    echo -e "${BOLD}Node ID:${NC}   ${node_id}"
    echo ""

    if [[ "${INSTALL_OUTLINE}" -eq 1 ]]; then
        echo -e "${BOLD}── Outline Shadowsocks ──────────────────────────────────${NC}"
        echo -e "  Port:     8388 (TCP+UDP)"
        echo -e "  Cipher:   chacha20-ietf-poly1305"
        echo -e "  Password: ${ss_password}"
        echo -e "  Prefix:   ${ss_prefix}"
        echo ""
        echo -e "  SS URL:"
        local encoded_password
        encoded_password=$(echo -n "chacha20-ietf-poly1305:${ss_password}" | base64 -w0)
        echo -e "  ss://${encoded_password}@${server_ip}:8388#${node_id}"
        echo ""
    fi

    if [[ "${INSTALL_SSCONF}" -eq 1 ]]; then
        echo -e "${BOLD}── ssconf Server ───────────────────────────────────────${NC}"
        echo -e "  URL: https://${server_ip}:8390/${ssconf_token}"
        echo ""
    fi

    if [[ "${INSTALL_SPEEDTEST}" -eq 1 ]]; then
        echo -e "${BOLD}── Speed Test Server ───────────────────────────────────${NC}"
        echo -e "  URL:     https://${server_ip}:8999"
        echo -e "  API Key: ${speedtest_key}"
        echo -e "  Health:  curl -k https://${server_ip}:8999/speedtest/health"
        echo ""
    fi

    if [[ "${INSTALL_ZAPRET}" -eq 1 ]]; then
        echo -e "${BOLD}── Zapret (nfqws2) ─────────────────────────────────────${NC}"
        echo -e "  Binary:   /opt/zapret/bin/nfqws2"
        echo -e "  DPI Args: /etc/zapret/dpi-args.conf"
        echo -e "  Service:  zapret-nfqws2.service"
        echo ""
    fi

    if [[ "${INSTALL_ZAPRET_AGENT}" -eq 1 ]]; then
        local agent_sync_key
        agent_sync_key=$(read_config "ZAPRET_AGENT_SYNC_KEY")
        echo -e "${BOLD}── Zapret Agent ────────────────────────────────────────${NC}"
        echo -e "  URL:      http://${server_ip}:5050"
        echo -e "  Sync Key: ${agent_sync_key}"
        echo -e "  Health:   curl http://${server_ip}:5050/health"
        echo ""
    fi

    echo -e "${YELLOW}── Next Steps ──────────────────────────────────────────${NC}"
    echo -e "  1. Use AmneziaVPN client to set up AWG + Xray on this server"
    echo -e "  2. Add the SS key and speedtest credentials to your Proxima instance"
    echo ""
    echo -e "${CYAN}  Config saved to: /opt/proxima-node/config.env${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
}

# ─── Main ─────────────────────────────────────────────────────────────

main() {
    parse_args "$@"
    banner
    preflight
    setup_repo
    run_setup
    print_summary
}

main "$@"
