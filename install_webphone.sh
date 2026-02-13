#!/bin/bash
# =============================================================================
# ViciDial WebRTC WebPhone Installer (chan_sip)
# Version: 2.0
#
# Installs and configures a WebRTC-based webphone for ViciDial using:
#   - chan_sip with WebSocket Secure (WSS) transport
#   - Let's Encrypt SSL certificates
#   - ViciPhone (SIP.js-based WebRTC phone)
#   - ICE/STUN for NAT traversal
#
# Based on the Striker24x7 guide, adapted for:
#   - Asterisk 18.x / ViciDial v10.13
#   - Rocky Linux / RHEL 9
#   - chan_sip (NOT PJSIP)
#
# Requirements:
#   - ViciDial already installed (Part 1 + Part 2)
#   - Asterisk 18.x with chan_sip
#   - A domain name (FQDN) pointing to this server's public IP
#   - Ports 443, 8089 open to the internet
#
# Usage:
#   ./install_webphone.sh --domain <your.domain.com>
#
# Optional flags:
#   --agents <N>       Create N agent/phone pairs (default: 0)
#   --start-ext <N>    Starting extension number (default: 10001)
#   --skip-cert        Skip SSL certificate generation (use existing)
#   --skip-viciphone   Skip ViciPhone installation (already installed)
#
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================
DOMAIN=""
NUM_AGENTS=0
START_EXT=10001
SKIP_CERT=false
SKIP_VICIPHONE=false
SERVER_IP=""
PUBLIC_IP=""
WEBROOT="/var/www/html"
AGC_DIR="${WEBROOT}/agc"
VICIPHONE_REPO="https://github.com/ccabrerar/ViciPhone.git"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# FUNCTIONS
# =============================================================================
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

backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp "$file" "${file}.webphone-backup.$(date +%Y%m%d_%H%M%S)"
        log "Backed up: $file"
    fi
}

usage() {
    echo "Usage: $0 --domain <your.domain.com> [options]"
    echo ""
    echo "  --domain         REQUIRED: FQDN pointing to this server"
    echo "  --agents N       Number of agent/phone pairs to create (default: 0)"
    echo "  --start-ext N    Starting extension number (default: 10001)"
    echo "  --skip-cert      Skip Let's Encrypt cert generation (use existing)"
    echo "  --skip-viciphone Skip ViciPhone installation (already installed)"
    exit 1
}

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)        DOMAIN="$2"; shift 2 ;;
        --agents)        NUM_AGENTS="$2"; shift 2 ;;
        --start-ext)     START_EXT="$2"; shift 2 ;;
        --skip-cert)     SKIP_CERT=true; shift ;;
        --skip-viciphone) SKIP_VICIPHONE=true; shift ;;
        -h|--help)       usage ;;
        *)               fail "Unknown option: $1" ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    fail "Missing required --domain argument. Run with --help for usage."
fi

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
section "PRE-FLIGHT CHECKS"

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root"
fi

# Detect server IP from ViciDial DB
SERVER_IP=$(mysql asterisk -N -e "SELECT server_ip FROM servers LIMIT 1;" 2>/dev/null)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi
log "Server IP (from DB): $SERVER_IP"

# Detect public IP (try multiple sources, fall back to server IP)
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null | grep -oP '^[0-9.]+$' || true)
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s --max-time 5 icanhazip.com 2>/dev/null | grep -oP '^[0-9.]+$' || true)
fi
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP="$SERVER_IP"
    warn "Could not detect public IP, using server IP: $SERVER_IP"
else
    success "Public IP: $PUBLIC_IP"
fi

# Verify DNS
RESOLVED_IP=$(dig +short "$DOMAIN" 2>/dev/null | tail -1)
if [ -z "$RESOLVED_IP" ]; then
    warn "DNS lookup failed for $DOMAIN - make sure it points to this server"
else
    log "DNS resolves $DOMAIN -> $RESOLVED_IP"
    if [ "$RESOLVED_IP" != "$PUBLIC_IP" ] && [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
        warn "DNS resolves to $RESOLVED_IP but server IP is $SERVER_IP / $PUBLIC_IP"
    fi
fi

# Verify ViciDial
if ! mysql asterisk -e "SELECT 1 FROM system_settings LIMIT 1;" &>/dev/null; then
    fail "Cannot connect to ViciDial database. Is ViciDial installed?"
fi
SCHEMA=$(mysql asterisk -N -e "SELECT db_schema_version FROM system_settings LIMIT 1;" 2>/dev/null)
success "ViciDial DB schema: $SCHEMA"

# Verify Asterisk
if ! asterisk -rx "core show version" &>/dev/null; then
    fail "Asterisk is not running"
fi
AST_VER=$(asterisk -V 2>/dev/null)
success "Asterisk: $AST_VER"

# Verify chan_sip is loaded
if asterisk -rx "module show like chan_sip" 2>/dev/null | grep -q "Running"; then
    success "chan_sip module loaded"
else
    fail "chan_sip is not loaded. This script requires chan_sip for WebRTC."
fi

# Check required modules
for mod in res_http_websocket res_crypto res_srtp; do
    if asterisk -rx "module show like ${mod}" 2>/dev/null | grep -q "Running"; then
        success "Module $mod loaded"
    else
        warn "Module $mod not loaded - attempting to load"
        asterisk -rx "module load ${mod}.so" 2>/dev/null || warn "Could not load ${mod}.so"
    fi
done

# =============================================================================
# STEP 1: SSL CERTIFICATE
# =============================================================================
section "STEP 1: SSL Certificate"

if [ "$SKIP_CERT" = true ]; then
    log "Skipping certificate generation (--skip-cert)"
    if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        fail "No cert found at /etc/letsencrypt/live/${DOMAIN}/. Remove --skip-cert to generate one."
    fi
    success "Using existing certificate for $DOMAIN"
else
    # Install certbot if needed
    if ! command -v certbot &>/dev/null; then
        log "Installing certbot..."
        dnf install -y epel-release &>/dev/null || true
        dnf install -y certbot &>/dev/null
        success "Certbot installed"
    fi

    if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        success "Certificate already exists for $DOMAIN"
    else
        log "Generating Let's Encrypt certificate for $DOMAIN..."
        # Stop httpd briefly if it's holding port 80
        certbot certonly --webroot --webroot-path "$WEBROOT" \
            -d "$DOMAIN" --non-interactive --agree-tos \
            --register-unsafely-without-email 2>&1 | tail -5
        if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
            success "SSL certificate generated"
        else
            fail "Certificate generation failed. Check that $DOMAIN points to this server and port 80 is open."
        fi
    fi
fi

# Create cert renewal hook for Asterisk + Apache
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/vicidial-cert-reload.sh <<'HOOK'
#!/bin/bash
# Reload Asterisk and Apache after cert renewal
asterisk -rx "module reload http" 2>/dev/null
systemctl reload httpd 2>/dev/null
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/deploy/vicidial-cert-reload.sh
success "Certificate auto-renewal hook created"

# =============================================================================
# STEP 2: APACHE HTTPS
# =============================================================================
section "STEP 2: Apache HTTPS Configuration"

# Install mod_ssl if needed
if ! httpd -M 2>/dev/null | grep -q ssl_module; then
    dnf install -y mod_ssl &>/dev/null
    success "mod_ssl installed"
fi

SSLCONF="/etc/httpd/conf.d/ssl.conf"
if [ -f "$SSLCONF" ]; then
    backup_file "$SSLCONF"

    # Update certificate paths in ssl.conf
    sed -i "s|^SSLCertificateFile .*|SSLCertificateFile /etc/letsencrypt/live/${DOMAIN}/cert.pem|" "$SSLCONF"
    sed -i "s|^SSLCertificateKeyFile .*|SSLCertificateKeyFile /etc/letsencrypt/live/${DOMAIN}/privkey.pem|" "$SSLCONF"

    # Add chain file if not present
    if grep -q "^#SSLCertificateChainFile" "$SSLCONF"; then
        sed -i "s|^#SSLCertificateChainFile.*|SSLCertificateChainFile /etc/letsencrypt/live/${DOMAIN}/fullchain.pem|" "$SSLCONF"
    elif ! grep -q "^SSLCertificateChainFile" "$SSLCONF"; then
        sed -i "/^SSLCertificateKeyFile/a SSLCertificateChainFile /etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$SSLCONF"
    else
        sed -i "s|^SSLCertificateChainFile .*|SSLCertificateChainFile /etc/letsencrypt/live/${DOMAIN}/fullchain.pem|" "$SSLCONF"
    fi

    success "Apache SSL cert paths configured"
fi

# HTTP to HTTPS redirect (preserve ACME challenge for cert renewals)
cat > /etc/httpd/conf.d/redirect-https.conf <<REDIRECT
<VirtualHost *:80>
    ServerName ${DOMAIN}
    DocumentRoot ${WEBROOT}
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
REDIRECT
success "HTTP -> HTTPS redirect configured"

# Test and restart Apache
if httpd -t 2>&1 | grep -q "Syntax OK"; then
    success "Apache config syntax OK"
    systemctl restart httpd
    success "Apache restarted with HTTPS"
else
    warn "Apache config syntax issue - check manually with: httpd -t"
    systemctl restart httpd || warn "Apache restart failed"
fi

# =============================================================================
# STEP 3: ASTERISK HTTP/WSS (http.conf)
# =============================================================================
section "STEP 3: Asterisk HTTP/WSS Configuration"

HTTPCONF="/etc/asterisk/http.conf"
backup_file "$HTTPCONF"

# Enable HTTP and TLS
sed -i "s|^;*enabled=.*|enabled=yes|" "$HTTPCONF"
sed -i "s|^;*bindaddr=.*|bindaddr=0.0.0.0|" "$HTTPCONF"
sed -i "s|^;*tlsenable=.*|tlsenable=yes|" "$HTTPCONF"
sed -i "s|^;*tlsbindaddr=.*|tlsbindaddr=0.0.0.0:8089|" "$HTTPCONF"

# Update cert paths (remove existing, add fresh)
sed -i "/^tlscertfile=/d" "$HTTPCONF"
sed -i "/^tlsprivatekey=/d" "$HTTPCONF"
sed -i "/^tlsbindaddr=/a tlscertfile=/etc/letsencrypt/live/${DOMAIN}/fullchain.pem\ntlsprivatekey=/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$HTTPCONF"

asterisk -rx "module reload http" &>/dev/null || true
success "Asterisk HTTP TLS configured on port 8089"

# =============================================================================
# STEP 4: ASTERISK MODULES (modules.conf)
# =============================================================================
section "STEP 4: Asterisk Modules"

MODCONF="/etc/asterisk/modules.conf"
backup_file "$MODCONF"

# Make sure res_http_websocket is loaded (required for WSS)
if ! grep -q "^load = res_http_websocket.so" "$MODCONF"; then
    # Add after res_srtp if it exists, otherwise after [modules]
    if grep -q "^load = res_srtp.so" "$MODCONF"; then
        sed -i "/^load = res_srtp.so/a load = res_http_websocket.so" "$MODCONF"
    else
        sed -i "/^\[modules\]/a load = res_http_websocket.so" "$MODCONF"
    fi
    success "Added res_http_websocket.so to modules.conf"
else
    success "res_http_websocket.so already in modules.conf"
fi

# Make sure chan_sip is loaded (not noloaded)
if grep -q "^noload.*chan_sip.so" "$MODCONF"; then
    sed -i "s|^noload.*chan_sip.so|;noload = chan_sip.so  ; enabled for WebRTC|" "$MODCONF"
    warn "chan_sip was noloaded - enabled it (restart required)"
fi

# =============================================================================
# STEP 5: RTP ICE/STUN (rtp.conf)
# =============================================================================
section "STEP 5: RTP ICE/STUN Configuration"

RTPCONF="/etc/asterisk/rtp.conf"

# Check ICE support
if grep -q "^icesupport=yes" "$RTPCONF"; then
    success "ICE support already enabled"
else
    backup_file "$RTPCONF"
    if grep -q "^; icesupport=" "$RTPCONF" || grep -q "^;icesupport=" "$RTPCONF"; then
        sed -i "s|^;* *icesupport=.*|icesupport=yes|" "$RTPCONF"
    elif ! grep -q "^icesupport=" "$RTPCONF"; then
        sed -i "/^\[general\]/a icesupport=yes" "$RTPCONF"
    fi
    success "ICE support enabled"
fi

# Check STUN server
if grep -q "^stunaddr=stun.l.google.com" "$RTPCONF"; then
    success "STUN server already configured (Google)"
elif grep -q "^stunaddr=" "$RTPCONF"; then
    success "STUN server already configured"
else
    sed -i "/^icesupport=/a stunaddr=stun.l.google.com:19302" "$RTPCONF"
    success "STUN server set to stun.l.google.com:19302"
fi

asterisk -rx "module reload res_rtp_asterisk.so" &>/dev/null || true

# =============================================================================
# STEP 6: SIP.CONF - NAT & WebRTC SETTINGS
# =============================================================================
section "STEP 6: sip.conf - NAT & Realm Settings"

SIPCONF="/etc/asterisk/sip.conf"
backup_file "$SIPCONF"

# Set externaddr (critical for NAT traversal)
if grep -q "^externaddr=" "$SIPCONF" || grep -q "^externip=" "$SIPCONF"; then
    success "externaddr/externip already set"
else
    # Add externaddr after the commented externip line
    sed -i "s|^;externip = .*|;externip = 192.168.1.1\nexternaddr=${PUBLIC_IP}|" "$SIPCONF"
    success "Set externaddr=${PUBLIC_IP}"
fi

# Set realm to the domain
if grep -q "^realm=" "$SIPCONF"; then
    success "realm already set"
else
    sed -i "s|^;realm=.*|realm=${DOMAIN}|" "$SIPCONF"
    success "Set realm=${DOMAIN}"
fi

asterisk -rx "sip reload" &>/dev/null || true
success "SIP configuration reloaded"

# Fix pjsip.conf placeholder addresses (PJSIP module still loads and logs errors)
PJSIPCONF="/etc/asterisk/pjsip.conf"
if grep -q "SERVER_EXTERNAL_IP" "$PJSIPCONF" 2>/dev/null; then
    backup_file "$PJSIPCONF"
    sed -i "s|SERVER_EXTERNAL_IP|${PUBLIC_IP}|g" "$PJSIPCONF"
    asterisk -rx "module reload res_pjsip.so" &>/dev/null || true
    success "Fixed pjsip.conf placeholder addresses -> ${PUBLIC_IP}"
fi

# =============================================================================
# STEP 7: VICIDIAL DATABASE - WebRTC SIP TEMPLATE
# =============================================================================
section "STEP 7: ViciDial WebRTC Configuration"

# Create chan_sip WebRTC conf template
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}"
TEMPLATE_CONTENTS="type=friend\nhost=dynamic\nencryption=yes\navpf=yes\nicesupport=yes\ndirectmedia=no\ntransport=wss\nforce_avp=yes\ndtlsenable=yes\ndtlsverify=no\ndtlscertfile=${CERT_PATH}/cert.pem\ndtlsprivatekey=${CERT_PATH}/privkey.pem\ndtlssetup=actpass\nrtcp_mux=yes"

TEMPLATE_EXISTS=$(mysql asterisk -N -e "SELECT COUNT(*) FROM vicidial_conf_templates WHERE template_id='webrtc';" 2>/dev/null)
if [ "$TEMPLATE_EXISTS" = "0" ]; then
    mysql asterisk -e "INSERT INTO vicidial_conf_templates (template_id, template_name, template_contents) VALUES (
        'webrtc',
        'WebRTC WebPhone chan_sip',
        '${TEMPLATE_CONTENTS}'
    );" 2>/dev/null
    success "Created 'webrtc' SIP conf template"
else
    # Update existing template
    mysql asterisk -e "UPDATE vicidial_conf_templates SET
        template_contents='${TEMPLATE_CONTENTS}'
        WHERE template_id='webrtc';" 2>/dev/null
    success "Updated existing 'webrtc' SIP conf template"
fi

# Enable webphone in system settings
mysql asterisk -e "UPDATE system_settings SET
    default_webphone='1',
    webphone_url='https://${DOMAIN}/agc/viciphone/viciphone.php';" 2>/dev/null
success "System settings: webphone enabled"

# Set websocket URL on server
mysql asterisk -e "UPDATE servers SET
    web_socket_url='wss://${DOMAIN}:8089/ws',
    external_web_socket_url='wss://${DOMAIN}:8089/ws'
    WHERE server_ip='${SERVER_IP}';" 2>/dev/null
success "Server WSS URL: wss://${DOMAIN}:8089/ws"

# =============================================================================
# STEP 8: INSTALL VICIPHONE
# =============================================================================
if [ "$SKIP_VICIPHONE" = false ]; then
    section "STEP 8: Install ViciPhone"

    if [ -d "${AGC_DIR}/viciphone" ]; then
        log "ViciPhone already installed at ${AGC_DIR}/viciphone/"
        log "To reinstall, remove the directory first or use --skip-viciphone"
        success "ViciPhone already present"
    else
        log "Cloning ViciPhone..."
        TMPDIR=$(mktemp -d)
        if git clone "$VICIPHONE_REPO" "$TMPDIR/viciphone" &>/dev/null; then
            mkdir -p "${AGC_DIR}/viciphone"
            cp -r "$TMPDIR/viciphone/"* "${AGC_DIR}/viciphone/"
            chown -R apache:apache "${AGC_DIR}/viciphone"
            chmod -R 755 "${AGC_DIR}/viciphone"
            success "ViciPhone installed at ${AGC_DIR}/viciphone/"
        else
            warn "Could not clone ViciPhone. Install manually from: $VICIPHONE_REPO"
        fi
        rm -rf "$TMPDIR"
    fi
else
    log "Skipping ViciPhone installation (--skip-viciphone)"
fi

# =============================================================================
# STEP 9: OPTIONS.PHP
# =============================================================================
section "STEP 9: ViciDial options.php"

OPTIONS_FILE="${AGC_DIR}/options.php"
if [ -f "$OPTIONS_FILE" ]; then
    success "options.php already exists"
else
    if [ -f "${AGC_DIR}/options-example.php" ]; then
        cp "${AGC_DIR}/options-example.php" "$OPTIONS_FILE"
        # Set webphone_call_seconds
        sed -i "s|\$webphone_call_seconds.*=.*|\$webphone_call_seconds\t\t\t= '10';|" "$OPTIONS_FILE" 2>/dev/null || true
        chown apache:apache "$OPTIONS_FILE"
        success "Created options.php from example (webphone_call_seconds=10)"
    else
        warn "options-example.php not found - options.php must be created manually"
    fi
fi

# =============================================================================
# STEP 10: CRONTAB - HTTPS RECORDINGS
# =============================================================================
section "STEP 10: Crontab HTTPS Recordings"

CRONTAB_FILE="/var/spool/cron/root"
if grep -q "\-\-HTTPS" "$CRONTAB_FILE" 2>/dev/null; then
    success "HTTPS flag already in crontab audio compress"
else
    # Update AST_CRON_audio_2_compress.pl to use --HTTPS if present
    if grep -q "AST_CRON_audio_2_compress.pl" "$CRONTAB_FILE" 2>/dev/null; then
        if grep "AST_CRON_audio_2_compress.pl" "$CRONTAB_FILE" | grep -q "\-\-HTTPS"; then
            success "Already using --HTTPS"
        else
            sed -i '/AST_CRON_audio_2_compress.pl/ s/$/ --HTTPS/' "$CRONTAB_FILE"
            success "Added --HTTPS flag to audio compress crontab"
        fi
    else
        log "AST_CRON_audio_2_compress.pl not found in crontab - skipping"
    fi
fi

# =============================================================================
# STEP 11: CREATE AGENTS AND PHONES
# =============================================================================
if [ "$NUM_AGENTS" -gt 0 ]; then
    section "STEP 11: Creating $NUM_AGENTS Agents & Phones"

    for i in $(seq 1 "$NUM_AGENTS"); do
        EXT=$((START_EXT + i - 1))
        PASS="Cbz${EXT}x"

        # Check if phone already exists
        PHONE_EXISTS=$(mysql asterisk -N -e "SELECT COUNT(*) FROM phones WHERE extension='${EXT}';" 2>/dev/null)
        if [ "$PHONE_EXISTS" != "0" ]; then
            log "Phone $EXT already exists, skipping"
            continue
        fi

        # Check if agent already exists
        AGENT_EXISTS=$(mysql asterisk -N -e "SELECT COUNT(*) FROM vicidial_users WHERE user='${EXT}';" 2>/dev/null)
        if [ "$AGENT_EXISTS" = "0" ]; then
            mysql asterisk -e "INSERT INTO vicidial_users
                (user, pass, full_name, user_level, user_group, phone_login, phone_pass,
                 agent_choose_ingroups, scheduled_callbacks, vicidial_recording, vicidial_transfers)
                VALUES ('${EXT}', '${PASS}', 'Agent ${EXT}', 4, 'AGENTS', '${EXT}', '${PASS}',
                        '1', '1', '1', '1');" 2>/dev/null
            log "Created agent ${EXT}"
        fi

        # Create phone entry with WebRTC template
        mysql asterisk -e "INSERT INTO phones
            (extension, dialplan_number, voicemail_id, server_ip, login, pass, status, active,
             phone_type, fullname, protocol, local_gmt, ASTmgrUSERNAME, ASTmgrSECRET, conf_secret,
             is_webphone, webphone_auto_answer, webphone_dialpad, webphone_dialbox,
             webphone_mute, webphone_volume, template_id)
            VALUES ('${EXT}', '${EXT}', '${EXT}', '${SERVER_IP}', '${EXT}', '${PASS}',
                    'ACTIVE', 'Y', 'SIP', 'Agent ${EXT}', 'SIP', '-5.00', 'cron', '1234',
                    '${PASS}', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'webrtc');" 2>/dev/null

        log "Created phone ${EXT} (webrtc template)"
    done

    success "Created $NUM_AGENTS agent/phone pairs (${START_EXT} - $((START_EXT + NUM_AGENTS - 1)))"
fi

# =============================================================================
# STEP 12: FIREWALL
# =============================================================================
section "STEP 12: Firewall Configuration"

if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --permanent --add-service=https &>/dev/null || true
    firewall-cmd --permanent --add-port=8089/tcp &>/dev/null || true

    # Read RTP range from rtp.conf
    RTP_START=$(grep "^rtpstart=" /etc/asterisk/rtp.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
    RTP_END=$(grep "^rtpend=" /etc/asterisk/rtp.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
    RTP_START=${RTP_START:-10000}
    RTP_END=${RTP_END:-20000}
    firewall-cmd --permanent --add-port=${RTP_START}-${RTP_END}/udp &>/dev/null || true

    firewall-cmd --reload &>/dev/null
    success "Firewall: 443/tcp, 8089/tcp, ${RTP_START}-${RTP_END}/udp opened"
else
    warn "firewalld not active - ensure ports 443, 8089, and RTP range are open"
fi

# =============================================================================
# STEP 13: FINAL RELOAD & VERIFICATION
# =============================================================================
section "STEP 13: Final Verification"

# Reload SIP to pick up any new phones
asterisk -rx "sip reload" &>/dev/null || true
sleep 2

# Verify HTTP/WSS
WSS_STATUS=$(asterisk -rx "http show status" 2>/dev/null | grep "HTTPS" || echo "NOT RUNNING")
if echo "$WSS_STATUS" | grep -q "Enabled"; then
    success "HTTPS/WSS: $WSS_STATUS"
else
    warn "HTTPS/WSS may not be running: $WSS_STATUS"
fi

# Verify WebSocket endpoint
if asterisk -rx "http show status" 2>/dev/null | grep -q "/ws"; then
    success "WebSocket endpoint /ws is active"
else
    warn "WebSocket endpoint /ws not found - may need Asterisk restart"
fi

# Verify chan_sip
SIP_PEERS=$(asterisk -rx "sip show peers" 2>/dev/null | tail -1)
success "SIP peers: $SIP_PEERS"

# =============================================================================
# SUMMARY
# =============================================================================
section "WEBPHONE INSTALLATION COMPLETE"

echo ""
echo -e "  Domain:        ${GREEN}${DOMAIN}${NC}"
echo -e "  Public IP:     ${GREEN}${PUBLIC_IP}${NC}"
echo -e "  Server IP:     ${GREEN}${SERVER_IP}${NC}"
echo ""
echo -e "  ViciDial URL:  ${GREEN}https://${DOMAIN}/vicidial/welcome.php${NC}"
echo -e "  Agent Login:   ${GREEN}https://${DOMAIN}/agc/vicidial.php${NC}"
echo -e "  WSS Endpoint:  ${GREEN}wss://${DOMAIN}:8089/ws${NC}"
echo ""
echo -e "  SIP Protocol:  ${GREEN}chan_sip (port 5060)${NC}"
echo -e "  WebRTC:        ${GREEN}WSS via Asterisk HTTP (port 8089)${NC}"
echo -e "  Apache HTTPS:  ${GREEN}Port 443${NC}"
echo ""
echo -e "  SIP Template:  ${GREEN}webrtc${NC} (chan_sip with encryption/avpf/dtls)"
echo ""

if [ "$NUM_AGENTS" -gt 0 ]; then
    echo -e "  ${CYAN}Agent Credentials:${NC}"
    echo -e "  +-----------+-------------+"
    echo -e "  | Agent/Ph  | Password    |"
    echo -e "  +-----------+-------------+"
    for i in $(seq 1 "$NUM_AGENTS"); do
        EXT=$((START_EXT + i - 1))
        printf "  | %-9s | %-11s |\n" "$EXT" "Cbz${EXT}x"
    done
    echo -e "  +-----------+-------------+"
    echo ""
fi

echo -e "  ${YELLOW}NEXT STEPS:${NC}"
echo -e "  1. In ViciDial Admin > Phones, set Template ID to '${GREEN}webrtc${NC}'"
echo -e "  2. Set 'Is Webphone' to ${GREEN}Y${NC} on each phone"
echo -e "  3. Agent logs in at ${GREEN}https://${DOMAIN}/agc/vicidial.php${NC}"
echo -e "  4. Browser will ask for microphone permission - click Allow"
echo ""
echo -e "  ${YELLOW}SSL auto-renews via certbot. Asterisk and Apache${NC}"
echo -e "  ${YELLOW}reload automatically on renewal.${NC}"
echo ""
