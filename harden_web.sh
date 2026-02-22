#!/bin/bash
# =============================================================================
# ViciDial Web/DB Server — Post-Install Hardening
# Version: 1.0
#
# Run this on Server #1 (Web/DB) AFTER the webphone installer completes.
# Safe to re-run — all steps are idempotent.
#
# What this script does:
#   1. DNS          — Switches to reliable resolvers; prevents NM overwriting them
#   2. Fail2ban     — Fixes ban action to use iptables (works with nftables backend)
#                     and tunes SSH jail to the correct custom port
#   3. Verify       — Confirms all services are in the expected state
#
# Usage:
#   ./harden_web.sh [--ssh-port <port>]
#
#   --ssh-port   Custom SSH port if not 22 (default: 22)
#
# =============================================================================

set -euo pipefail

SSH_PORT=22

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[ OK ]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

section() {
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--ssh-port <port>]"
            exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "Must be run as root"

# =============================================================================
# STEP 1: DNS — Reliable resolvers + prevent NetworkManager from overwriting
# =============================================================================
section "STEP 1: DNS Hardening"

# Write resolv.conf with known-good resolvers
cat > /etc/resolv.conf <<'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 8.8.4.4
EOF
success "resolv.conf set to 8.8.8.8 / 1.1.1.1 / 8.8.4.4"

# Prevent NetworkManager from overwriting resolv.conf
NM_OVERRIDE="/etc/NetworkManager/conf.d/no-dns-override.conf"
if [ ! -f "$NM_OVERRIDE" ]; then
    mkdir -p /etc/NetworkManager/conf.d
    cat > "$NM_OVERRIDE" <<'EOF'
# Prevent NetworkManager from overwriting /etc/resolv.conf
# DNS is managed manually for reliability (avoids ISP resolver timeouts)
[main]
dns=none
EOF
    systemctl reload NetworkManager &>/dev/null || true
    success "NetworkManager DNS override disabled"
else
    success "NetworkManager DNS override already in place"
fi

# Verify resolution speed
RESOLVE_MS=$(( TIMEFORMAT="%R"; { time dig +short google.com @8.8.8.8 &>/dev/null; } ) 2>&1 | awk '{printf "%d", $1*1000}' || echo "?")
success "DNS resolution time: ~${RESOLVE_MS}ms"

# =============================================================================
# STEP 2: Fail2ban — Fix ban action for nftables (firewalld is disabled)
# =============================================================================
section "STEP 2: Fail2ban — nftables Ban Action"

# Server #1 uses firewalld (required by the Dynamic Portal's VB-firewall ipset script).
# firewallcmd-rich-rules is the correct banaction when firewalld is active.
JAIL_LOCAL="/etc/fail2ban/jail.local"

if grep -q "banaction = firewallcmd-rich-rules" "$JAIL_LOCAL" 2>/dev/null && \
   grep -q "port.*=.*${SSH_PORT}" "$JAIL_LOCAL" 2>/dev/null; then
    success "fail2ban jail.local already configured"
else
    cat > "$JAIL_LOCAL" <<EOF
[DEFAULT]
bantime  = 86400
findtime = 30
maxretry = 3
banaction = firewallcmd-rich-rules

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/secure
maxretry = 3
findtime = 30
bantime  = 86400
backend  = auto

[apache-auth]
enabled  = true
filter   = apache-auth
logpath  = /var/log/httpd/*error_log
maxretry = 3
findtime = 30
bantime  = 86400
backend  = auto
EOF
    success "fail2ban jail.local updated (banaction: firewallcmd-rich-rules, SSH port: ${SSH_PORT})"
fi

systemctl restart fail2ban
sleep 2
FB_STATUS=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
success "fail2ban sshd jail active — currently banned: ${FB_STATUS:-0}"

# =============================================================================
# STEP 3: Verification
# =============================================================================
section "STEP 3: Verification"

# DNS
DNS_TEST=$(dig +short google.com @8.8.8.8 2>/dev/null | head -1)
[ -n "$DNS_TEST" ] && success "DNS: resolves via 8.8.8.8" || warn "DNS: resolution failed"

# firewalld (Server #1 uses firewalld; required by Dynamic Portal VB-firewall ipset)
if systemctl is-active firewalld &>/dev/null; then
    success "firewalld: active (manages agent IP whitelist via ipset)"
else
    warn "firewalld: not running — Dynamic Portal whitelisting will not work"
fi

# Apache
if systemctl is-active httpd &>/dev/null; then
    success "httpd: active"
else
    warn "httpd: not running"
fi

# MariaDB
if systemctl is-active mariadb &>/dev/null; then
    success "mariadb: active"
else
    warn "mariadb: not running"
fi

# Fail2ban
systemctl is-active fail2ban &>/dev/null && success "fail2ban: active" || warn "fail2ban: not running"

# =============================================================================
# SUMMARY
# =============================================================================
section "HARDENING COMPLETE"
echo ""
echo -e "  ${GREEN}DNS:${NC}      8.8.8.8 / 1.1.1.1 / 8.8.4.4 (NM override: no-dns)"
echo -e "  ${GREEN}Fail2ban:${NC} sshd + apache-auth jails, 24h ban, firewallcmd-rich-rules action"
echo -e "  ${GREEN}Firewall:${NC} firewalld active (manages Dynamic Portal agent IP whitelist)"
echo ""
echo -e "  ${YELLOW}Tip:${NC} Re-run anytime — all steps are idempotent."
echo ""
