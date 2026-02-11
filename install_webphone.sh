#!/bin/bash
# =============================================================================
# ViciDial WebRTC WebPhone Automated Installer
# Version: 1.0
#
# Installs and configures a WebRTC-based webphone for ViciDial using:
#   - PJSIP with WebSocket Secure (WSS) transport
#   - Let's Encrypt SSL certificates
#   - ViciPhone (SIP.js-based WebRTC phone)
#   - ICE/STUN for NAT traversal
#
# Requirements:
#   - ViciDial already installed (Part 1 + Part 2)
#   - Asterisk 13+ (tested on 18.x)
#   - A domain name (FQDN) pointing to this server's public IP
#   - Port 443, 8089 open to the internet
#
# Usage:
#   ./install_webphone.sh --domain <your.domain.com>
#
# Optional flags:
#   --agents <N>       Create N agent/phone pairs (default: 0)
#   --start-ext <N>    Starting extension number (default: 10001)
#   --skip-cert        Skip SSL certificate generation (use existing)
#   --no-viciphone     Skip ViciPhone installation (use your own webphone)
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
ASTERISK_KEYS_DIR="/etc/asterisk/keys"
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
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

section() {
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

usage() {
    echo "Usage: $0 --domain <your.domain.com> [--agents N] [--start-ext N] [--skip-cert] [--no-viciphone]"
    echo ""
    echo "  --domain       REQUIRED: FQDN pointing to this server"
    echo "  --agents       Number of agent/phone pairs to create (default: 0)"
    echo "  --start-ext    Starting extension number (default: 10001)"
    echo "  --skip-cert    Skip Let's Encrypt cert generation"
    echo "  --no-viciphone Skip ViciPhone installation"
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        fail "This script must be run as root"
    fi
}

detect_server_ip() {
    SERVER_IP=$(mysql asterisk -N -e "SELECT server_ip FROM servers LIMIT 1;" 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    log "Detected server IP: $SERVER_IP"
}

verify_dns() {
    local resolved_ip
    resolved_ip=$(dig +short "$DOMAIN" 2>/dev/null | tail -1)
    if [ -z "$resolved_ip" ]; then
        fail "DNS lookup failed for $DOMAIN. Make sure it points to this server."
    fi
    log "DNS resolves $DOMAIN -> $resolved_ip"
}

verify_vicidial() {
    if ! mysql asterisk -e "SELECT 1 FROM system_settings LIMIT 1;" &>/dev/null; then
        fail "Cannot connect to ViciDial database. Is ViciDial installed?"
    fi
    local schema
    schema=$(mysql asterisk -N -e "SELECT db_schema_version FROM system_settings LIMIT 1;" 2>/dev/null)
    log "ViciDial DB schema version: $schema"
}

verify_asterisk() {
    if ! asterisk -rx "core show version" &>/dev/null; then
        fail "Asterisk is not running"
    fi
    local version
    version=$(asterisk -rx "core show version" 2>/dev/null | head -1)
    log "Asterisk: $version"
}

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)    DOMAIN="$2"; shift 2 ;;
        --agents)    NUM_AGENTS="$2"; shift 2 ;;
        --start-ext) START_EXT="$2"; shift 2 ;;
        --skip-cert) SKIP_CERT=true; shift ;;
        --no-viciphone) SKIP_VICIPHONE=true; shift ;;
        -h|--help)   usage ;;
        *)           fail "Unknown option: $1" ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    fail "Missing required --domain argument. Run with --help for usage."
fi

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
section "PRE-FLIGHT CHECKS"

check_root
detect_server_ip
verify_dns
verify_vicidial
verify_asterisk

# Check required modules
for mod in res_http_websocket res_crypto res_srtp; do
    if asterisk -rx "module show like ${mod}" 2>/dev/null | grep -q "Running"; then
        success "Asterisk module $mod loaded"
    else
        warn "Asterisk module $mod not loaded - attempting to load"
        asterisk -rx "module load ${mod}.so" 2>/dev/null || true
    fi
done

# =============================================================================
# STEP 1: SSL CERTIFICATE
# =============================================================================
section "STEP 1: SSL Certificate"

if [ "$SKIP_CERT" = true ]; then
    log "Skipping certificate generation (--skip-cert)"
    if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        fail "No existing cert found at /etc/letsencrypt/live/${DOMAIN}/. Remove --skip-cert to generate one."
    fi
else
    # Install certbot if needed
    if ! command -v certbot &>/dev/null; then
        log "Installing certbot..."
        dnf install -y epel-release &>/dev/null
        dnf install -y certbot &>/dev/null
        success "Certbot installed"
    fi

    # Generate certificate
    if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        log "Certificate already exists for $DOMAIN, skipping generation"
    else
        log "Generating Let's Encrypt certificate for $DOMAIN..."
        certbot certonly --webroot --webroot-path "$WEBROOT" \
            -d "$DOMAIN" --non-interactive --agree-tos \
            --email "admin@${DOMAIN}" 2>&1 | tail -5
        success "SSL certificate generated"
    fi
fi

# Copy certs for Asterisk
mkdir -p "$ASTERISK_KEYS_DIR"
cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${ASTERISK_KEYS_DIR}/${DOMAIN}.pem"
cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${ASTERISK_KEYS_DIR}/${DOMAIN}-key.pem"
chmod 640 "${ASTERISK_KEYS_DIR}"/*.pem
success "Certificates copied to $ASTERISK_KEYS_DIR"

# Create renewal hook
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/asterisk-cert-update.sh <<HOOK
#!/bin/bash
cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${ASTERISK_KEYS_DIR}/${DOMAIN}.pem
cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${ASTERISK_KEYS_DIR}/${DOMAIN}-key.pem
chmod 640 ${ASTERISK_KEYS_DIR}/*.pem
asterisk -rx "module reload http" 2>/dev/null
asterisk -rx "module reload res_pjsip.so" 2>/dev/null
systemctl reload httpd 2>/dev/null
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/deploy/asterisk-cert-update.sh
success "Certificate auto-renewal hook created"

# =============================================================================
# STEP 2: APACHE HTTPS
# =============================================================================
section "STEP 2: Apache HTTPS Configuration"

# Install mod_ssl if needed
if ! httpd -M 2>/dev/null | grep -q ssl_module; then
    dnf install -y mod_ssl &>/dev/null
fi

# Update ssl.conf with real cert paths
SSLCONF="/etc/httpd/conf.d/ssl.conf"
if [ -f "$SSLCONF" ]; then
    # Set ServerName
    if grep -q "#ServerName" "$SSLCONF" || grep -q "www.example.com" "$SSLCONF"; then
        sed -i "s|#*ServerName.*|ServerName ${DOMAIN}:443|" "$SSLCONF"
    fi
    # Set DocumentRoot
    if grep -q "#DocumentRoot" "$SSLCONF"; then
        sed -i "s|#DocumentRoot.*|DocumentRoot \"${WEBROOT}\"|" "$SSLCONF"
    fi
    # Set certificate paths
    sed -i "s|SSLCertificateFile .*|SSLCertificateFile /etc/letsencrypt/live/${DOMAIN}/fullchain.pem|" "$SSLCONF"
    sed -i "s|SSLCertificateKeyFile .*|SSLCertificateKeyFile /etc/letsencrypt/live/${DOMAIN}/privkey.pem|" "$SSLCONF"
    success "Apache SSL configured with Let's Encrypt cert"
fi

# HTTP to HTTPS redirect
cat > /etc/httpd/conf.d/redirect-https.conf <<REDIRECT
<VirtualHost *:80>
    ServerName ${DOMAIN}
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/.well-known/acme-challenge/
    RewriteRule ^(.*)$ https://%{HTTP_HOST}\$1 [R=301,L]
</VirtualHost>
REDIRECT
success "HTTP -> HTTPS redirect configured"

# Test and restart Apache
httpd -t 2>&1 | grep -q "Syntax OK" && success "Apache config syntax OK" || warn "Apache config syntax issue"
systemctl restart httpd
success "Apache restarted with HTTPS"

# =============================================================================
# STEP 3: ASTERISK HTTP/WSS
# =============================================================================
section "STEP 3: Asterisk HTTP/WSS Configuration"

HTTPCONF="/etc/asterisk/http.conf"
if [ -f "$HTTPCONF" ]; then
    # Enable TLS with cert paths
    sed -i "s|^;*tlsenable=.*|tlsenable=yes|" "$HTTPCONF"
    sed -i "s|^;*tlsbindaddr=.*|tlsbindaddr=0.0.0.0:8089|" "$HTTPCONF"

    # Remove old cert lines and add new ones
    sed -i "/^tlscertfile=/d" "$HTTPCONF"
    sed -i "/^tlsprivatekey=/d" "$HTTPCONF"
    sed -i "/^;tlscertfile=/d" "$HTTPCONF"
    sed -i "/^;tlsprivatekey=/d" "$HTTPCONF"

    # Add cert paths after tlsbindaddr
    sed -i "/^tlsbindaddr=/a tlscertfile=${ASTERISK_KEYS_DIR}/${DOMAIN}.pem\ntlsprivatekey=${ASTERISK_KEYS_DIR}/${DOMAIN}-key.pem" "$HTTPCONF"

    success "Asterisk HTTP TLS configured on port 8089"
fi

asterisk -rx "module reload http" &>/dev/null
success "Asterisk HTTP module reloaded"

# =============================================================================
# STEP 4: RTP ICE/STUN
# =============================================================================
section "STEP 4: RTP ICE/STUN Configuration"

RTPCONF="/etc/asterisk/rtp.conf"
if [ -f "$RTPCONF" ]; then
    # Enable ICE
    if grep -q "^; icesupport=" "$RTPCONF"; then
        sed -i "s|^; icesupport=.*|icesupport=yes|" "$RTPCONF"
    elif ! grep -q "^icesupport=yes" "$RTPCONF"; then
        sed -i "/^\[general\]/a icesupport=yes" "$RTPCONF"
    fi

    # Set STUN server
    if grep -q "^; stunaddr=" "$RTPCONF"; then
        sed -i "s|^; stunaddr=.*|stunaddr=stun.l.google.com:19302|" "$RTPCONF"
    elif ! grep -q "^stunaddr=" "$RTPCONF"; then
        sed -i "/^icesupport=/a stunaddr=stun.l.google.com:19302" "$RTPCONF"
    fi

    success "ICE support enabled with Google STUN server"
fi

asterisk -rx "module reload res_rtp_asterisk.so" &>/dev/null
success "RTP module reloaded"

# =============================================================================
# STEP 5: ENABLE PJSIP MODULES
# =============================================================================
section "STEP 5: Enable PJSIP Modules"

MODCONF="/etc/asterisk/modules.conf"
if [ -f "$MODCONF" ]; then
    # Enable chan_pjsip if noloaded
    sed -i "s|^noload.*=>.*chan_pjsip.so|;noload => chan_pjsip.so  ; enabled for WebRTC|" "$MODCONF"
    # Enable websocket transport if noloaded
    sed -i "s|^noload.*=>.*res_pjsip_transport_websocket.so|;noload => res_pjsip_transport_websocket.so  ; enabled for WebRTC|" "$MODCONF"
    success "PJSIP modules enabled in modules.conf"
fi

# Try to load modules (may need restart)
NEED_RESTART=false
if ! asterisk -rx "module show like chan_pjsip" 2>/dev/null | grep -q "Running"; then
    asterisk -rx "module load chan_pjsip.so" &>/dev/null || NEED_RESTART=true
fi
if ! asterisk -rx "module show like res_pjsip_transport_websocket" 2>/dev/null | grep -q "Running\|Not Running"; then
    asterisk -rx "module load res_pjsip_transport_websocket.so" &>/dev/null || NEED_RESTART=true
fi

if [ "$NEED_RESTART" = true ]; then
    warn "Asterisk restart required to load PJSIP modules..."
    asterisk -rx "core restart now" &>/dev/null
    sleep 8
    success "Asterisk restarted"
fi

# =============================================================================
# STEP 6: PJSIP TRANSPORT CONFIGURATION
# =============================================================================
section "STEP 6: PJSIP WSS Transport"

PJSIPCONF="/etc/asterisk/pjsip.conf"

# Update external addresses in transport-udp
if grep -q "external_media_address.*=.*0\.0\.0\.0" "$PJSIPCONF"; then
    sed -i "s|external_media_address.*=.*0\.0\.0\.0|external_media_address          = ${SERVER_IP}|" "$PJSIPCONF"
    sed -i "s|external_signaling_address.*=.*0\.0\.0\.0|external_signaling_address      = ${SERVER_IP}|" "$PJSIPCONF"
fi

# Check if transport-wss already has external addresses
if grep -A5 "\[transport-wss\]" "$PJSIPCONF" | grep -q "external_media_address"; then
    log "WSS transport already has external addresses configured"
else
    # Add external addresses to transport-wss
    sed -i "/^\[transport-wss\]/,/^$/{
        /^bind/a external_media_address          = ${SERVER_IP}\nexternal_signaling_address      = ${SERVER_IP}\nlocal_net                       = 192.168.0.0/255.255.0.0\nlocal_net                       = 10.0.0.0/255.0.0.0\nlocal_net                       = 172.16.0.0/12\nlocal_net                       = 169.254.0.0/255.255.0.0
    }" "$PJSIPCONF"
    success "WSS transport configured with external address $SERVER_IP"
fi

# Add include for webrtc phones config if not present
if ! grep -q "pjsip-webrtc-phones.conf" "$PJSIPCONF"; then
    sed -i '/^#include "pjsip-vicidial.conf"/i #include "pjsip-webrtc-phones.conf"' "$PJSIPCONF"
    success "Added pjsip-webrtc-phones.conf include"
fi

# Create the webrtc phones config with templates
cat > /etc/asterisk/pjsip-webrtc-phones.conf <<WEBRTC
; =============================================================
; WebRTC WebPhone Endpoints
; Auto-generated by install_webphone.sh
; =============================================================

; --- PJSIP endpoint template for WebRTC phones ---
[webrtc-phone](!)
type=endpoint
context=default
dtmf_mode=auto
disallow=all
allow=ulaw
allow=alaw
allow=opus
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
rtp_timeout=60
direct_media=no
trust_id_inbound=yes
send_rpid=yes
webrtc=yes
transport=transport-wss
use_avpf=yes
media_encryption=dtls
dtls_verify=fingerprint
dtls_setup=actpass
dtls_cert_file=${ASTERISK_KEYS_DIR}/${DOMAIN}.pem
dtls_private_key=${ASTERISK_KEYS_DIR}/${DOMAIN}-key.pem
ice_support=yes
media_use_received_transport=yes

[webrtc-aor](!)
type=aor
max_contacts=2
remove_existing=yes
qualify_frequency=30
WEBRTC

success "PJSIP WebRTC templates created"

# =============================================================================
# STEP 7: VICIDIAL DATABASE CONFIGURATION
# =============================================================================
section "STEP 7: ViciDial Database Configuration"

# Create WebRTC conf template if it doesn't exist
TEMPLATE_EXISTS=$(mysql asterisk -N -e "SELECT COUNT(*) FROM vicidial_conf_templates WHERE template_id='WebRTC_phone';" 2>/dev/null)
if [ "$TEMPLATE_EXISTS" = "0" ]; then
    mysql asterisk -e "INSERT INTO vicidial_conf_templates (template_id, template_name, template_contents) VALUES (
    'WebRTC_phone',
    'WebRTC WebPhone PJSIP',
    'type=aor\nmax_contacts=2\nremove_existing=yes\nqualify_frequency=30\n\ntype=auth\nauth_type=userpass\n\ntype=endpoint\ncontext=default\ndtmf_mode=auto\ndisallow=all\nallow=ulaw\nallow=alaw\nallow=opus\nrtp_symmetric=yes\nforce_rport=yes\nrewrite_contact=yes\nrtp_timeout=60\ndirect_media=no\ntrust_id_inbound=yes\nsend_rpid=yes\nwebrtc=yes\ntransport=transport-wss\nuse_avpf=yes\nmedia_encryption=dtls\ndtls_verify=fingerprint\ndtls_setup=actpass\ndtls_cert_file=${ASTERISK_KEYS_DIR}/${DOMAIN}.pem\ndtls_private_key=${ASTERISK_KEYS_DIR}/${DOMAIN}-key.pem\nice_support=yes\nmedia_use_received_transport=yes'
    );" 2>/dev/null
    success "WebRTC_phone conf template created"
else
    log "WebRTC_phone template already exists"
fi

# Update system settings
mysql asterisk -e "UPDATE system_settings SET
    default_webphone='1',
    webphone_url='https://${DOMAIN}/agc/viciphone/viciphone.php';" 2>/dev/null
success "System settings: webphone enabled"

# Update server websocket URL
mysql asterisk -e "UPDATE servers SET
    web_socket_url='wss://${DOMAIN}:8089/ws',
    external_web_socket_url='wss://${DOMAIN}:8089/ws'
    WHERE server_ip='${SERVER_IP}';" 2>/dev/null
success "Server WSS URL set to wss://${DOMAIN}:8089/ws"

# =============================================================================
# STEP 8: INSTALL VICIPHONE
# =============================================================================
if [ "$SKIP_VICIPHONE" = false ]; then
    section "STEP 8: Install ViciPhone"

    if [ -d "${AGC_DIR}/viciphone" ]; then
        log "ViciPhone directory already exists, backing up..."
        mv "${AGC_DIR}/viciphone" "${AGC_DIR}/viciphone.bak.$(date +%s)"
    fi

    log "Cloning ViciPhone..."
    TMPDIR=$(mktemp -d)
    if git clone "$VICIPHONE_REPO" "$TMPDIR/viciphone" &>/dev/null; then
        mkdir -p "${AGC_DIR}/viciphone"
        cp -r "$TMPDIR/viciphone/"* "${AGC_DIR}/viciphone/"
        chown -R apache:apache "${AGC_DIR}/viciphone"

        # Use local JS copies instead of CDN (security hardening)
        TEMPLATE_FILE="${AGC_DIR}/viciphone/vp_template.php"
        if [ -f "$TEMPLATE_FILE" ]; then
            sed -i 's|<script src="https://webrtc.github.io/adapter/adapter-latest.js"></script>|<script src="js/adapter.js"></script>|' "$TEMPLATE_FILE"
            sed -i 's|<script src="https://cdn.jsdelivr.net/npm/sip.js@0.15.11/dist/sip-0.15.11.min.js"></script>|<script src="js/sip-0.15.11.min.js"></script>|' "$TEMPLATE_FILE"
            # Comment out the CDN lines and uncomment local ones
            sed -i '/<!--<script src="js\/adapter.js"><\/script>-->/d' "$TEMPLATE_FILE"
            sed -i '/<!--script src="js\/sip-0.15.11.min.js"><\/script-->/d' "$TEMPLATE_FILE"
        fi

        success "ViciPhone installed at ${AGC_DIR}/viciphone/ (local JS, no CDN)"
    else
        warn "Could not clone ViciPhone repo. You may need to install it manually."
    fi
    rm -rf "$TMPDIR"
else
    log "Skipping ViciPhone installation (--no-viciphone)"
fi

# =============================================================================
# STEP 9: CREATE AGENTS AND PHONES
# =============================================================================
if [ "$NUM_AGENTS" -gt 0 ]; then
    section "STEP 9: Creating $NUM_AGENTS Agents & Phones"

    for i in $(seq 1 "$NUM_AGENTS"); do
        EXT=$((START_EXT + i - 1))
        PASS="Cbz${EXT}!"

        # Check if agent already exists
        EXISTS=$(mysql asterisk -N -e "SELECT COUNT(*) FROM vicidial_users WHERE user='${EXT}';" 2>/dev/null)
        if [ "$EXISTS" != "0" ]; then
            log "Agent $EXT already exists, skipping"
            continue
        fi

        # Create agent
        mysql asterisk -e "INSERT INTO vicidial_users
            (user, pass, full_name, user_level, user_group, phone_login, phone_pass,
             agent_choose_ingroups, scheduled_callbacks, vicidial_recording, vicidial_transfers)
            VALUES ('${EXT}', '${PASS}', 'Agent ${EXT}', 4, 'AGENTS', '${EXT}', '${PASS}',
                    '1', '1', '1', '1');" 2>/dev/null

        # Create phone
        mysql asterisk -e "INSERT INTO phones
            (extension, dialplan_number, voicemail_id, server_ip, login, pass, status, active,
             phone_type, fullname, protocol, local_gmt, ASTmgrUSERNAME, ASTmgrSECRET, conf_secret,
             is_webphone, webphone_auto_answer, webphone_dialpad, webphone_dialbox,
             webphone_mute, webphone_volume, template_id)
            VALUES ('${EXT}', '${EXT}', '${EXT}', '${SERVER_IP}', '${EXT}', '${PASS}',
                    'ACTIVE', 'Y', 'WebRTC', 'Agent ${EXT}', 'PJSIP', '-5.00', 'cron', '1234',
                    '${PASS}', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'WebRTC_phone');" 2>/dev/null

        # Create PJSIP endpoint
        cat >> /etc/asterisk/pjsip-webrtc-phones.conf <<PHONE

; --- Phone ${EXT} ---
[${EXT}](webrtc-aor)
[${EXT}]
type=auth
auth_type=userpass
username=${EXT}
password=${PASS}
[${EXT}](webrtc-phone)
aors=${EXT}
auth=${EXT}
callerid="Agent ${EXT}" <${EXT}>
PHONE

        log "Created agent/phone ${EXT}"
    done

    success "Created $NUM_AGENTS agent/phone pairs (${START_EXT} - $((START_EXT + NUM_AGENTS - 1)))"
fi

# =============================================================================
# STEP 10: FIREWALL
# =============================================================================
section "STEP 10: Firewall Configuration"

if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    # Add HTTPS if not present
    firewall-cmd --permanent --add-service=https &>/dev/null || true
    # Add WSS port
    firewall-cmd --permanent --add-port=8089/tcp &>/dev/null || true
    # Ensure SIP and RTP are open
    firewall-cmd --permanent --add-port=5060/tcp &>/dev/null || true
    firewall-cmd --permanent --add-port=5060/udp &>/dev/null || true
    firewall-cmd --permanent --add-port=10000-20000/udp &>/dev/null || true
    firewall-cmd --reload &>/dev/null
    success "Firewall ports opened: 443, 8089, 5060, 10000-20000/udp"
else
    warn "firewalld not active - make sure ports 443, 8089, 5060, 10000-20000/udp are open"
fi

# =============================================================================
# STEP 11: RELOAD ASTERISK
# =============================================================================
section "STEP 11: Final Asterisk Reload"

asterisk -rx "module reload res_pjsip.so" &>/dev/null
sleep 2

ENDPOINT_COUNT=$(asterisk -rx "pjsip show endpoints" 2>/dev/null | grep -c "Endpoint:" || echo "0")
success "PJSIP endpoints loaded: $ENDPOINT_COUNT"

WSS_STATUS=$(asterisk -rx "http show status" 2>/dev/null | grep "HTTPS" || echo "NOT RUNNING")
success "HTTPS/WSS: $WSS_STATUS"

# =============================================================================
# SUMMARY
# =============================================================================
section "WEBPHONE INSTALLATION COMPLETE"

echo ""
echo -e "  Domain:        ${GREEN}${DOMAIN}${NC}"
echo -e "  ViciDial URL:  ${GREEN}https://${DOMAIN}/vicidial/welcome.php${NC}"
echo -e "  Agent Login:   ${GREEN}https://${DOMAIN}/agc/vicidial.php${NC}"
echo -e "  WSS Endpoint:  ${GREEN}wss://${DOMAIN}:8089/ws${NC}"
echo ""
echo -e "  Apache HTTPS:  ${GREEN}Port 443${NC}"
echo -e "  Asterisk WSS:  ${GREEN}Port 8089${NC}"
echo -e "  chan_sip:      ${GREEN}Port 5060${NC} (carrier trunks)"
echo -e "  PJSIP:        ${GREEN}Port 5061${NC} (WebRTC phones)"
echo ""

if [ "$NUM_AGENTS" -gt 0 ]; then
    echo -e "  ${CYAN}Agent Credentials:${NC}"
    echo -e "  ┌──────────┬─────────────┐"
    echo -e "  │ Agent/Ph │ Password    │"
    echo -e "  ├──────────┼─────────────┤"
    for i in $(seq 1 "$NUM_AGENTS"); do
        EXT=$((START_EXT + i - 1))
        printf "  │ %-8s │ Cbz%-8s│\n" "$EXT" "${EXT}!"
    done
    echo -e "  └──────────┴─────────────┘"
    echo ""
fi

echo -e "  ${YELLOW}NOTE: Agents log in with the same credentials for both${NC}"
echo -e "  ${YELLOW}phone login AND agent login.${NC}"
echo ""
echo -e "  ${YELLOW}SSL cert auto-renews via certbot. Asterisk and Apache${NC}"
echo -e "  ${YELLOW}will be reloaded automatically on renewal.${NC}"
echo ""
