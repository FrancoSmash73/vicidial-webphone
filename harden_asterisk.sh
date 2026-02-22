#!/bin/bash
# =============================================================================
# ViciDial Asterisk Server — Post-Install Hardening
# Version: 1.0
#
# Run this on Server #2 (Asterisk) AFTER the webphone installer completes.
# Safe to re-run — all steps are idempotent.
#
# What this script does:
#   1. DNS          — Switches to reliable resolvers; prevents NM overwriting them
#   2. SIP security — Reject guests, hide auth failures (alwaysauthreject)
#   3. SIP qualify  — qualifyfreq=10s so WebRTC phones mark REACHABLE quickly
#   4. UDP buffers  — Increases receive buffers to prevent RTP packet drops
#   5. Fail2ban     — Fixes ban action to use iptables (works with nftables backend)
#                     and tunes SSH jail to the correct custom port
#   6. Systemd      — Disables systemd asterisk unit (ViciDial uses screen session)
#   7. Verify       — Confirms all services are in the expected state
#
# Usage:
#   ./harden_asterisk.sh [--ssh-port <port>]
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
# STEP 2: SIP Security — Reject guests, hide authentication failures
# =============================================================================
section "STEP 2: SIP Security Hardening"

SIPCONF="/etc/asterisk/sip.conf"
[ -f "$SIPCONF" ] || fail "sip.conf not found at $SIPCONF"

# allowguest=no — reject all unauthenticated SIP calls
if grep -q "^allowguest=no" "$SIPCONF"; then
    success "allowguest=no already set"
else
    if grep -q "^allowguest=" "$SIPCONF"; then
        sed -i "s|^allowguest=.*|allowguest=no|" "$SIPCONF"
    else
        sed -i "/^\[general\]/a allowguest=no" "$SIPCONF"
    fi
    success "Set allowguest=no"
fi

# alwaysauthreject=yes — return 403 for invalid users instead of 404
# (prevents user enumeration by attackers)
if grep -q "^alwaysauthreject" "$SIPCONF"; then
    success "alwaysauthreject already set"
else
    if grep -qE "^;*alwaysauthreject" "$SIPCONF"; then
        sed -i "s|^;*alwaysauthreject.*|alwaysauthreject=yes|" "$SIPCONF"
    else
        sed -i "/^\[general\]/a alwaysauthreject=yes" "$SIPCONF"
    fi
    success "Set alwaysauthreject=yes"
fi

# =============================================================================
# STEP 3: SIP Qualify Tuning — Fast reachability for WebRTC agents
# =============================================================================
section "STEP 3: SIP Qualify Tuning"

# qualifyfreq=10 — re-qualify every 10s so phones show REACHABLE within
# seconds of logging in (default 60s caused 20s+ delay for WebRTC agents)
if grep -q "^qualifyfreq=10" "$SIPCONF"; then
    success "qualifyfreq=10 already set"
else
    # Remove any existing qualifyfreq and add after qualify=yes
    sed -i '/^qualifyfreq=/d' "$SIPCONF"
    if grep -q "^qualify=yes" "$SIPCONF"; then
        sed -i '/^qualify=yes/a qualifyfreq=10' "$SIPCONF"
    else
        sed -i "/^\[general\]/a qualify=yes\nqualifyfreq=10" "$SIPCONF"
    fi
    success "Set qualifyfreq=10 (10-second qualify interval)"
fi

# Apply SIP changes
asterisk -rx "sip reload" &>/dev/null || true
success "SIP configuration reloaded"

# =============================================================================
# STEP 4: UDP Buffer Tuning — Prevent RTP packet drops under load
# =============================================================================
section "STEP 4: UDP / RTP Buffer Tuning"

SYSCTL_FILE="/etc/sysctl.d/99-asterisk-rtp.conf"

if [ -f "$SYSCTL_FILE" ] && grep -q "rmem_max.*67108864" "$SYSCTL_FILE"; then
    success "UDP buffer tuning already applied"
else
    cat > "$SYSCTL_FILE" <<'EOF'
# ViciDial Asterisk RTP tuning
# Prevents "Exceptionally long voice queue" warnings under load.
# Large buffers allow the kernel to absorb RTP bursts without dropping packets.
net.core.rmem_max          = 67108864
net.core.rmem_default      = 26214400
net.core.wmem_max          = 67108864
net.core.wmem_default      = 26214400
net.core.netdev_max_backlog = 5000
EOF
    success "Written /etc/sysctl.d/99-asterisk-rtp.conf"
fi

sysctl -p "$SYSCTL_FILE" &>/dev/null
CURRENT_RMAX=$(sysctl -n net.core.rmem_max)
success "net.core.rmem_max = ${CURRENT_RMAX} ($(( CURRENT_RMAX / 1024 / 1024 ))MB)"

# =============================================================================
# STEP 5: Fail2ban — Fix ban action for nftables (firewalld is disabled)
# =============================================================================
section "STEP 5: Fail2ban — nftables Ban Action"

# firewallcmd-rich-rules (firewalld) won't work after we disabled firewalld.
# iptables-allports uses the iptables-nft backend which integrates with nftables.
JAIL_LOCAL="/etc/fail2ban/jail.local"

if grep -q "banaction = iptables-allports" "$JAIL_LOCAL" 2>/dev/null; then
    success "fail2ban ban action already set to iptables-allports"
else
    cat > "$JAIL_LOCAL" <<EOF
[DEFAULT]
bantime  = 86400
findtime = 30
maxretry = 3
banaction = iptables-allports

[asterisk]
enabled  = true
filter   = asterisk
action   = iptables-allports[name=asterisk, protocol=all]
logpath  = /var/log/asterisk/messages
maxretry = 3
findtime = 30
bantime  = 86400
backend  = auto

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/secure
maxretry = 3
findtime = 30
bantime  = 86400
backend  = auto
EOF
    success "fail2ban jail.local updated (banaction: iptables-allports, SSH port: ${SSH_PORT})"
fi

systemctl restart fail2ban
sleep 2
FB_STATUS=$(fail2ban-client status asterisk 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
success "fail2ban asterisk jail active — currently banned: ${FB_STATUS:-0}"

# =============================================================================
# STEP 6: Disable systemd Asterisk unit
# =============================================================================
section "STEP 6: Disable systemd Asterisk (ViciDial uses screen session)"

# ViciDial starts Asterisk via a screen session. The systemd unit conflicts
# and creates a second Asterisk instance that competes for port 5060.
if systemctl is-enabled asterisk &>/dev/null; then
    systemctl stop    asterisk &>/dev/null || true
    systemctl disable asterisk &>/dev/null
    success "systemd asterisk unit disabled"
else
    success "systemd asterisk unit already disabled"
fi

# Verify the screen-session Asterisk is running
AST_PID=$(pgrep -f "asterisk.*-vvv" 2>/dev/null | head -1 || true)
if [ -n "$AST_PID" ]; then
    AST_VER=$(asterisk -rx "core show version" 2>/dev/null || echo "unknown")
    success "Screen Asterisk running (PID ${AST_PID}): ${AST_VER}"
else
    warn "No screen-session Asterisk found — start it via ViciDial's init script"
fi

# =============================================================================
# STEP 7: Verification
# =============================================================================
section "STEP 7: Verification"

# DNS
DNS_TEST=$(dig +short google.com @8.8.8.8 2>/dev/null | head -1)
[ -n "$DNS_TEST" ] && success "DNS: resolves via 8.8.8.8" || warn "DNS: resolution failed"

# nftables
if systemctl is-active nftables &>/dev/null; then
    success "nftables: active"
else
    warn "nftables: not active — run the webphone installer with --mode asterisk first"
fi

# SIP settings
for setting in "allowguest=no" "alwaysauthreject" "qualifyfreq=10"; do
    grep -q "^${setting}" "$SIPCONF" && success "sip.conf: ${setting}" || warn "sip.conf: ${setting} not found"
done

# UDP buffers
RMAX=$(sysctl -n net.core.rmem_max 2>/dev/null)
[ "${RMAX:-0}" -ge 26214400 ] && success "UDP buffers: ${RMAX} bytes" || warn "UDP buffers: low (${RMAX:-unknown})"

# Fail2ban
systemctl is-active fail2ban &>/dev/null && success "fail2ban: active" || warn "fail2ban: not running"

# =============================================================================
# SUMMARY
# =============================================================================
section "HARDENING COMPLETE"
echo ""
echo -e "  ${GREEN}DNS:${NC}        8.8.8.8 / 1.1.1.1 / 8.8.4.4 (NM override: no-dns)"
echo -e "  ${GREEN}SIP:${NC}        allowguest=no, alwaysauthreject=yes, qualifyfreq=10s"
echo -e "  ${GREEN}UDP buffers:${NC} rmem_max=64MB, rmem_default=26MB"
echo -e "  ${GREEN}Fail2ban:${NC}   asterisk + sshd jails, 24h ban, iptables-allports action"
echo -e "  ${GREEN}Systemd:${NC}    asterisk unit disabled (ViciDial screen session takes precedence)"
echo ""
echo -e "  ${YELLOW}Tip:${NC} Re-run anytime — all steps are idempotent."
echo ""
