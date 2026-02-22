#!/bin/bash
# =============================================================================
# ViciDial WebRTC WebPhone Installer (chan_sip)
# Version: 3.0
#
# Supports single-server (standalone) and two-server cluster deployments.
#
# STANDALONE (all-in-one):
#   ./install_webphone.sh --domain yourserver.com [options]
#
# CLUSTER - Step 1, run on Server #1 (Web/DB):
#   ./install_webphone.sh --mode web \
#       --web-domain dialengine.ddns.net \
#       --asterisk-domain dialengine2.ddns.net \
#       --asterisk-ip 172.235.34.224
#
# CLUSTER - Step 2, run on Server #2 (Asterisk):
#   ./install_webphone.sh --mode asterisk \
#       --domain dialengine2.ddns.net
#
# Required ports:
#   Server #1: 80/tcp (ACME), 443/tcp (HTTPS)
#   Server #2: 80/tcp (ACME), 8089/tcp (WSS), 10000-20000/udp (RTP)
#
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================
MODE="standalone"          # standalone | web | asterisk
DOMAIN=""                  # shorthand: sets WEB_DOMAIN (standalone/web) or ASTERISK_DOMAIN (asterisk)
WEB_DOMAIN=""              # FQDN for Server #1 — Apache HTTPS, ViciPhone UI
ASTERISK_DOMAIN=""         # FQDN for Server #2 — Asterisk WSS cert, sip realm
ASTERISK_IP=""             # IP of Asterisk server (web mode — for DB updates)
CARRIER_IP=""              # SIP carrier IP (asterisk mode — whitelisted on port 5060)
DB_HOST="localhost"        # MySQL host (asterisk mode only, if DB is on a remote server)
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

# Wrapper so asterisk mode can optionally reach a remote DB via --db-host
mysql_cmd() {
    mysql -h "${DB_HOST}" asterisk "$@"
}

usage() {
    cat <<EOF

Usage: $0 [--mode standalone|web|asterisk] [options]

STANDALONE (single-server, default):
  $0 --domain <your.domain.com> [options]

CLUSTER — Server #1 (Web/DB):
  $0 --mode web \\
       --web-domain <web.domain.com> \\
       --asterisk-domain <pbx.domain.com> \\
       --asterisk-ip <asterisk-server-ip>

CLUSTER — Server #2 (Asterisk):
  $0 --mode asterisk --domain <pbx.domain.com>

Options:
  --mode             standalone (default) | web | asterisk
  --domain           Domain for standalone, or alias for --web-domain (web)
                     / --asterisk-domain (asterisk)
  --web-domain       Server #1 FQDN (Apache HTTPS + ViciPhone)
  --asterisk-domain  Server #2 FQDN (Asterisk WSS cert + realm)
  --asterisk-ip      Asterisk server IP (web mode — updates DB servers table)
  --carrier-ip       SIP carrier IP (asterisk mode — only IP allowed on port 5060)
  --db-host          MySQL hostname/IP (asterisk mode — connect to remote DB)
  --agents N         Create N agent/phone pairs (default: 0)
  --start-ext N      Starting extension number (default: 10001)
  --skip-cert        Skip Let's Encrypt cert generation (use existing)
  --skip-viciphone   Skip ViciPhone installation (already installed)

EOF
    exit 1
}

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)            MODE="$2";            shift 2 ;;
        --domain)          DOMAIN="$2";          shift 2 ;;
        --web-domain)      WEB_DOMAIN="$2";      shift 2 ;;
        --asterisk-domain) ASTERISK_DOMAIN="$2"; shift 2 ;;
        --asterisk-ip)     ASTERISK_IP="$2";     shift 2 ;;
        --carrier-ip)      CARRIER_IP="$2";      shift 2 ;;
        --db-host)         DB_HOST="$2";         shift 2 ;;
        --agents)          NUM_AGENTS="$2";      shift 2 ;;
        --start-ext)       START_EXT="$2";       shift 2 ;;
        --skip-cert)       SKIP_CERT=true;       shift ;;
        --skip-viciphone)  SKIP_VICIPHONE=true;  shift ;;
        -h|--help)         usage ;;
        *)                 fail "Unknown option: $1" ;;
    esac
done

# Validate mode
case "$MODE" in
    standalone|web|asterisk) ;;
    *) fail "Invalid --mode '${MODE}'. Must be: standalone, web, or asterisk" ;;
esac

# Resolve effective domains based on mode and apply --domain alias
case "$MODE" in
    standalone)
        [ -z "$WEB_DOMAIN" ]      && WEB_DOMAIN="$DOMAIN"
        [ -z "$ASTERISK_DOMAIN" ] && ASTERISK_DOMAIN="$DOMAIN"
        [ -z "$WEB_DOMAIN" ]      && fail "Missing required --domain. Run with --help for usage."
        ;;
    web)
        [ -z "$WEB_DOMAIN" ]      && WEB_DOMAIN="$DOMAIN"
        [ -z "$WEB_DOMAIN" ]      && fail "Missing --web-domain (or --domain) for web mode."
        [ -z "$ASTERISK_DOMAIN" ] && fail "Missing --asterisk-domain for web mode."
        ;;
    asterisk)
        [ -z "$ASTERISK_DOMAIN" ] && ASTERISK_DOMAIN="$DOMAIN"
        [ -z "$ASTERISK_DOMAIN" ] && fail "Missing --domain (or --asterisk-domain) for asterisk mode."
        ;;
esac

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
section "PRE-FLIGHT CHECKS  [mode: ${MODE}]"

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root"
fi

log "Mode:    ${MODE}"
[ -n "$WEB_DOMAIN" ]      && log "Web domain:      ${WEB_DOMAIN}"
[ -n "$ASTERISK_DOMAIN" ] && log "Asterisk domain: ${ASTERISK_DOMAIN}"

# Detect public IP
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null | grep -oP '^[0-9.]+$' || true)
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s --max-time 5 icanhazip.com 2>/dev/null | grep -oP '^[0-9.]+$' || true)
fi
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(hostname -I | awk '{print $1}')
    warn "Could not detect public IP externally — using: $PUBLIC_IP"
else
    success "Public IP: $PUBLIC_IP"
fi

# ViciDial DB checks — skip in asterisk mode unless --db-host is explicitly set
DB_AVAILABLE=false
if [ "$MODE" != "asterisk" ] || [ "$DB_HOST" != "localhost" ]; then
    if mysql_cmd -e "SELECT 1 FROM system_settings LIMIT 1;" &>/dev/null; then
        DB_AVAILABLE=true
        SCHEMA=$(mysql_cmd -N -e "SELECT db_schema_version FROM system_settings LIMIT 1;" 2>/dev/null)
        success "ViciDial DB schema: $SCHEMA"
    else
        if [ "$MODE" = "asterisk" ]; then
            warn "Cannot connect to ViciDial DB at ${DB_HOST} — DB steps will be skipped"
        else
            fail "Cannot connect to ViciDial database. Is ViciDial installed and MySQL running?"
        fi
    fi
fi

# Server IP + Asterisk IP (web and standalone modes)
if [ "$MODE" != "asterisk" ] && [ "$DB_AVAILABLE" = true ]; then
    SERVER_IP=$(mysql_cmd -N -e "SELECT server_ip FROM servers LIMIT 1;" 2>/dev/null || true)
    [ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I | awk '{print $1}')
    log "Web server IP (from DB): $SERVER_IP"

    if [ "$MODE" = "web" ] && [ -z "$ASTERISK_IP" ]; then
        ASTERISK_IP=$(mysql_cmd -N -e \
            "SELECT server_ip FROM servers WHERE server_ip != '${SERVER_IP}' LIMIT 1;" \
            2>/dev/null || true)
        if [ -n "$ASTERISK_IP" ]; then
            log "Asterisk server IP (auto-detected from DB): $ASTERISK_IP"
        else
            warn "Could not auto-detect Asterisk server IP — use --asterisk-ip to specify"
            ASTERISK_IP="$PUBLIC_IP"
        fi
    fi
fi

# Asterisk checks — standalone and asterisk modes only
if [ "$MODE" = "standalone" ] || [ "$MODE" = "asterisk" ]; then
    if ! asterisk -rx "core show version" &>/dev/null; then
        fail "Asterisk is not running. Start it first: systemctl start asterisk"
    fi
    AST_VER=$(asterisk -V 2>/dev/null)
    success "Asterisk: $AST_VER"

    if asterisk -rx "module show like chan_sip" 2>/dev/null | grep -q "Running"; then
        success "chan_sip module loaded"
    else
        fail "chan_sip is not loaded. This script requires chan_sip for WebRTC."
    fi

    for mod in res_http_websocket res_crypto res_srtp; do
        if asterisk -rx "module show like ${mod}" 2>/dev/null | grep -q "Running"; then
            success "Module ${mod} loaded"
        else
            warn "Module ${mod} not loaded — attempting to load"
            asterisk -rx "module load ${mod}.so" 2>/dev/null || warn "Could not load ${mod}.so"
        fi
    done
fi

# DNS verification
VERIFY_DOMAIN="${WEB_DOMAIN}"
[ "$MODE" = "asterisk" ] && VERIFY_DOMAIN="${ASTERISK_DOMAIN}"
RESOLVED_IP=$(dig +short "$VERIFY_DOMAIN" 2>/dev/null | tail -1)
if [ -z "$RESOLVED_IP" ]; then
    warn "DNS lookup failed for ${VERIFY_DOMAIN} — ensure it resolves before running"
else
    log "DNS: ${VERIFY_DOMAIN} -> ${RESOLVED_IP}"
    if [ "$RESOLVED_IP" != "$PUBLIC_IP" ]; then
        warn "DNS resolves to ${RESOLVED_IP} but this server's public IP is ${PUBLIC_IP}"
    fi
fi

# =============================================================================
# STEP 1: SSL CERTIFICATE
# =============================================================================
# web mode      → cert for WEB_DOMAIN      (Apache HTTPS)
# asterisk mode → cert for ASTERISK_DOMAIN (Asterisk WSS/TLS on port 8089)
# standalone    → cert for WEB_DOMAIN (= ASTERISK_DOMAIN, same server)
# =============================================================================
section "STEP 1: SSL Certificate"

CERT_DOMAIN="${WEB_DOMAIN}"
[ "$MODE" = "asterisk" ] && CERT_DOMAIN="${ASTERISK_DOMAIN}"

if [ "$SKIP_CERT" = true ]; then
    log "Skipping certificate generation (--skip-cert)"
    if [ ! -f "/etc/letsencrypt/live/${CERT_DOMAIN}/fullchain.pem" ]; then
        fail "No cert found at /etc/letsencrypt/live/${CERT_DOMAIN}/. Remove --skip-cert to generate one."
    fi
    success "Using existing certificate for ${CERT_DOMAIN}"
else
    # Install certbot if needed
    if ! command -v certbot &>/dev/null; then
        log "Installing certbot..."
        dnf install -y epel-release &>/dev/null || true
        dnf install -y certbot &>/dev/null
        success "Certbot installed"
    fi

    if [ -f "/etc/letsencrypt/live/${CERT_DOMAIN}/fullchain.pem" ]; then
        success "Certificate already exists for ${CERT_DOMAIN} — skipping generation"
    else
        log "Generating Let's Encrypt certificate for ${CERT_DOMAIN}..."
        if [ "$MODE" = "asterisk" ]; then
            # Asterisk server: use webroot if httpd is running on port 80,
            # otherwise fall back to standalone
            if ss -tlnp 2>/dev/null | grep -q ':80 '; then
                log "httpd detected on port 80 — using webroot for certbot"
                ASTERISK_WEBROOT=$(apachectl -S 2>/dev/null | grep -i "DocumentRoot\|docroot" | head -1 | awk '{print $NF}' || echo "/var/www/html")
                [ ! -d "$ASTERISK_WEBROOT" ] && ASTERISK_WEBROOT="/var/www/html"
                certbot certonly --webroot --webroot-path "$ASTERISK_WEBROOT" \
                    -d "$CERT_DOMAIN" --non-interactive --agree-tos \
                    --register-unsafely-without-email 2>&1 | tail -5
            else
                certbot certonly --standalone \
                    -d "$CERT_DOMAIN" --non-interactive --agree-tos \
                    --register-unsafely-without-email 2>&1 | tail -5
            fi
        else
            # Web/standalone: use webroot (Apache is already running)
            certbot certonly --webroot --webroot-path "$WEBROOT" \
                -d "$CERT_DOMAIN" --non-interactive --agree-tos \
                --register-unsafely-without-email 2>&1 | tail -5
        fi

        if [ -f "/etc/letsencrypt/live/${CERT_DOMAIN}/fullchain.pem" ]; then
            success "SSL certificate generated for ${CERT_DOMAIN}"
        else
            fail "Certificate generation failed. Ensure ${CERT_DOMAIN} resolves to this server and port 80 is open."
        fi
    fi
fi

# Cert renewal hook — reload only the services that live on this server
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
if [ "$MODE" = "asterisk" ]; then
    cat > /etc/letsencrypt/renewal-hooks/deploy/vicidial-cert-reload.sh <<'HOOK'
#!/bin/bash
# Reload Asterisk HTTP after cert renewal (cluster: Asterisk server)
asterisk -rx "module reload http" 2>/dev/null
HOOK
elif [ "$MODE" = "web" ]; then
    cat > /etc/letsencrypt/renewal-hooks/deploy/vicidial-cert-reload.sh <<'HOOK'
#!/bin/bash
# Reload Apache after cert renewal (cluster: web server)
systemctl reload httpd 2>/dev/null
HOOK
else
    cat > /etc/letsencrypt/renewal-hooks/deploy/vicidial-cert-reload.sh <<'HOOK'
#!/bin/bash
# Reload Asterisk and Apache after cert renewal (standalone)
asterisk -rx "module reload http" 2>/dev/null
systemctl reload httpd 2>/dev/null
HOOK
fi
chmod +x /etc/letsencrypt/renewal-hooks/deploy/vicidial-cert-reload.sh
success "Certificate auto-renewal hook created"

# =============================================================================
# STEP 2: APACHE HTTPS  (web + standalone only)
# =============================================================================
if [ "$MODE" != "asterisk" ]; then
    section "STEP 2: Apache HTTPS Configuration"

    if ! httpd -M 2>/dev/null | grep -q ssl_module; then
        dnf install -y mod_ssl &>/dev/null
        success "mod_ssl installed"
    fi

    SSLCONF="/etc/httpd/conf.d/ssl.conf"
    if [ -f "$SSLCONF" ]; then
        backup_file "$SSLCONF"
        sed -i "s|^SSLCertificateFile .*|SSLCertificateFile /etc/letsencrypt/live/${WEB_DOMAIN}/cert.pem|" "$SSLCONF"
        sed -i "s|^SSLCertificateKeyFile .*|SSLCertificateKeyFile /etc/letsencrypt/live/${WEB_DOMAIN}/privkey.pem|" "$SSLCONF"

        if grep -q "^#SSLCertificateChainFile" "$SSLCONF"; then
            sed -i "s|^#SSLCertificateChainFile.*|SSLCertificateChainFile /etc/letsencrypt/live/${WEB_DOMAIN}/fullchain.pem|" "$SSLCONF"
        elif ! grep -q "^SSLCertificateChainFile" "$SSLCONF"; then
            sed -i "/^SSLCertificateKeyFile/a SSLCertificateChainFile /etc/letsencrypt/live/${WEB_DOMAIN}/fullchain.pem" "$SSLCONF"
        else
            sed -i "s|^SSLCertificateChainFile .*|SSLCertificateChainFile /etc/letsencrypt/live/${WEB_DOMAIN}/fullchain.pem|" "$SSLCONF"
        fi
        success "Apache SSL cert paths configured for ${WEB_DOMAIN}"
    fi

    # HTTP → HTTPS redirect (preserve ACME challenge path for renewals)
    cat > /etc/httpd/conf.d/redirect-https.conf <<REDIRECT
<VirtualHost *:80>
    ServerName ${WEB_DOMAIN}
    DocumentRoot ${WEBROOT}
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
REDIRECT
    success "HTTP -> HTTPS redirect configured"

    if httpd -t 2>&1 | grep -q "Syntax OK"; then
        success "Apache config syntax OK"
        systemctl restart httpd
        success "Apache restarted with HTTPS"
    else
        warn "Apache config syntax issue — check manually: httpd -t"
        systemctl restart httpd || warn "Apache restart failed"
    fi
else
    log "Skipping Step 2 (Apache HTTPS) — asterisk mode"
fi

# =============================================================================
# STEP 3: ASTERISK HTTP/WSS  (asterisk + standalone only)
# =============================================================================
if [ "$MODE" != "web" ]; then
    section "STEP 3: Asterisk HTTP/WSS Configuration"

    HTTPCONF="/etc/asterisk/http.conf"
    backup_file "$HTTPCONF"

    sed -i "s|^;*enabled=.*|enabled=yes|"          "$HTTPCONF"
    sed -i "s|^;*bindaddr=.*|bindaddr=0.0.0.0|"    "$HTTPCONF"
    sed -i "s|^;*tlsenable=.*|tlsenable=yes|"      "$HTTPCONF"
    sed -i "s|^;*tlsbindaddr=.*|tlsbindaddr=0.0.0.0:8089|" "$HTTPCONF"

    # Remove any existing cert lines, then insert fresh ones after tlsbindaddr
    sed -i "/^tlscertfile=/d"   "$HTTPCONF"
    sed -i "/^tlsprivatekey=/d" "$HTTPCONF"
    sed -i "/^tlsbindaddr=/a tlscertfile=/etc/letsencrypt/live/${ASTERISK_DOMAIN}/fullchain.pem\ntlsprivatekey=/etc/letsencrypt/live/${ASTERISK_DOMAIN}/privkey.pem" "$HTTPCONF"

    asterisk -rx "module reload http" &>/dev/null || true
    success "Asterisk HTTP TLS configured on 0.0.0.0:8089 (cert: ${ASTERISK_DOMAIN})"
else
    log "Skipping Step 3 (Asterisk HTTP) — web mode"
fi

# =============================================================================
# STEP 4: ASTERISK MODULES  (asterisk + standalone only)
# =============================================================================
if [ "$MODE" != "web" ]; then
    section "STEP 4: Asterisk Modules"

    MODCONF="/etc/asterisk/modules.conf"
    backup_file "$MODCONF"

    if ! grep -q "^load = res_http_websocket.so" "$MODCONF"; then
        if grep -q "^load = res_srtp.so" "$MODCONF"; then
            sed -i "/^load = res_srtp.so/a load = res_http_websocket.so" "$MODCONF"
        else
            sed -i "/^\[modules\]/a load = res_http_websocket.so" "$MODCONF"
        fi
        success "Added res_http_websocket.so to modules.conf"
    else
        success "res_http_websocket.so already in modules.conf"
    fi

    # Ensure chan_sip is not in the noload list
    if grep -q "^noload.*chan_sip.so" "$MODCONF"; then
        sed -i "s|^noload.*chan_sip.so|;noload = chan_sip.so  ; enabled for WebRTC|" "$MODCONF"
        warn "chan_sip was noloaded — enabled it (Asterisk restart required)"
    fi
else
    log "Skipping Step 4 (Asterisk modules) — web mode"
fi

# =============================================================================
# STEP 5: RTP ICE/STUN  (asterisk + standalone only)
# =============================================================================
if [ "$MODE" != "web" ]; then
    section "STEP 5: RTP ICE/STUN Configuration"

    RTPCONF="/etc/asterisk/rtp.conf"

    if grep -q "^icesupport=yes" "$RTPCONF"; then
        success "ICE support already enabled"
    else
        backup_file "$RTPCONF"
        if grep -qE "^;* *icesupport=" "$RTPCONF"; then
            sed -i "s|^;* *icesupport=.*|icesupport=yes|" "$RTPCONF"
        else
            sed -i "/^\[general\]/a icesupport=yes" "$RTPCONF"
        fi
        success "ICE support enabled"
    fi

    if grep -q "^stunaddr=" "$RTPCONF"; then
        success "STUN server already configured"
    else
        sed -i "/^icesupport=/a stunaddr=stun.l.google.com:19302" "$RTPCONF"
        success "STUN server set to stun.l.google.com:19302"
    fi

    asterisk -rx "module reload res_rtp_asterisk.so" &>/dev/null || true
else
    log "Skipping Step 5 (RTP/ICE) — web mode"
fi

# =============================================================================
# STEP 6: SIP.CONF — NAT & Realm  (asterisk + standalone only)
# =============================================================================
if [ "$MODE" != "web" ]; then
    section "STEP 6: sip.conf — NAT & Realm Settings"

    SIPCONF="/etc/asterisk/sip.conf"
    backup_file "$SIPCONF"

    # externaddr — critical for NAT traversal
    if grep -qE "^(externaddr|externip)=" "$SIPCONF"; then
        success "externaddr/externip already set"
    else
        sed -i "s|^;externip = .*|;externip = 192.168.1.1\nexternaddr=${PUBLIC_IP}|" "$SIPCONF"
        success "Set externaddr=${PUBLIC_IP}"
    fi

    # realm — should match the domain browsers connect to
    if grep -q "^realm=" "$SIPCONF"; then
        success "realm already set"
    else
        sed -i "s|^;realm=.*|realm=${ASTERISK_DOMAIN}|" "$SIPCONF"
        success "Set realm=${ASTERISK_DOMAIN}"
    fi

    asterisk -rx "sip reload" &>/dev/null || true
    success "SIP configuration reloaded"

    # Fix any SERVER_EXTERNAL_IP placeholders in pjsip.conf (avoids log spam)
    PJSIPCONF="/etc/asterisk/pjsip.conf"
    if grep -q "SERVER_EXTERNAL_IP" "$PJSIPCONF" 2>/dev/null; then
        backup_file "$PJSIPCONF"
        sed -i "s|SERVER_EXTERNAL_IP|${PUBLIC_IP}|g" "$PJSIPCONF"
        asterisk -rx "module reload res_pjsip.so" &>/dev/null || true
        success "Fixed pjsip.conf placeholder addresses -> ${PUBLIC_IP}"
    fi
else
    log "Skipping Step 6 (sip.conf) — web mode"
fi

# =============================================================================
# STEP 7: VICIDIAL DATABASE — WebRTC config  (web + standalone only)
# =============================================================================
if [ "$MODE" != "asterisk" ] && [ "$DB_AVAILABLE" = true ]; then
    section "STEP 7: ViciDial WebRTC Configuration"

    # cert path lives on Server #2 (where Asterisk runs)
    CERT_PATH_DB="/etc/letsencrypt/live/${ASTERISK_DOMAIN}"
    TEMPLATE_CONTENTS="type=friend\nhost=dynamic\nencryption=yes\navpf=yes\nicesupport=yes\ndirectmedia=no\ntransport=wss\nforce_avp=yes\ndtlsenable=yes\ndtlsverify=no\ndtlscertfile=${CERT_PATH_DB}/cert.pem\ndtlsprivatekey=${CERT_PATH_DB}/privkey.pem\ndtlssetup=actpass\nrtcp_mux=yes"

    TEMPLATE_EXISTS=$(mysql_cmd -N -e \
        "SELECT COUNT(*) FROM vicidial_conf_templates WHERE template_id='webrtc';" 2>/dev/null)
    if [ "$TEMPLATE_EXISTS" = "0" ]; then
        mysql_cmd -e "INSERT INTO vicidial_conf_templates
            (template_id, template_name, template_contents)
            VALUES ('webrtc', 'WebRTC WebPhone chan_sip', '${TEMPLATE_CONTENTS}');" 2>/dev/null
        success "Created 'webrtc' SIP conf template"
    else
        mysql_cmd -e "UPDATE vicidial_conf_templates
            SET template_contents='${TEMPLATE_CONTENTS}'
            WHERE template_id='webrtc';" 2>/dev/null
        success "Updated 'webrtc' SIP conf template"
    fi

    # webphone_url → always points to Server #1 (web domain)
    mysql_cmd -e "UPDATE system_settings SET
        default_webphone='1',
        webphone_url='https://${WEB_DOMAIN}/agc/viciphone/viciphone.php';" 2>/dev/null
    success "Webphone URL: https://${WEB_DOMAIN}/agc/viciphone/viciphone.php"

    # WSS URL → points to Server #2 (asterisk domain), direct connection, no proxy
    WSS_URL="wss://${ASTERISK_DOMAIN}:8089/ws"
    AST_SERVER_IP="${ASTERISK_IP:-${SERVER_IP}}"
    mysql_cmd -e "UPDATE servers SET
        web_socket_url='${WSS_URL}',
        external_web_socket_url='${WSS_URL}'
        WHERE server_ip='${AST_SERVER_IP}';" 2>/dev/null
    success "Asterisk server (${AST_SERVER_IP}) WSS URL: ${WSS_URL}"

    # ViciWhite IP list (Dynamic Portal agent whitelisting)
    VICIWHITE_EXISTS=$(mysql_cmd -N -e \
        "SELECT COUNT(*) FROM vicidial_ip_lists WHERE ip_list_id='ViciWhite';" 2>/dev/null)
    if [ "$VICIWHITE_EXISTS" = "0" ]; then
        mysql_cmd -e "INSERT INTO vicidial_ip_lists
            (ip_list_id, ip_list_name, active, user_group)
            VALUES ('ViciWhite', 'WebPhone Agent Whitelist', 'Y', '---ALL---');" 2>/dev/null
        success "Created 'ViciWhite' IP list for agent whitelisting"
    else
        success "ViciWhite IP list already exists"
    fi
else
    log "Skipping Step 7 (DB updates) — asterisk mode"
fi

# =============================================================================
# STEP 8: INSTALL VICIPHONE  (web + standalone only)
# =============================================================================
if [ "$MODE" != "asterisk" ] && [ "$SKIP_VICIPHONE" = false ]; then
    section "STEP 8: Install ViciPhone"

    if [ -d "${AGC_DIR}/viciphone" ]; then
        log "ViciPhone already installed at ${AGC_DIR}/viciphone/"
        success "ViciPhone already present"
    else
        log "Cloning ViciPhone from ${VICIPHONE_REPO}..."
        TMPDIR=$(mktemp -d)
        if git clone "$VICIPHONE_REPO" "$TMPDIR/viciphone" &>/dev/null; then
            mkdir -p "${AGC_DIR}/viciphone"
            cp -r "$TMPDIR/viciphone/"* "${AGC_DIR}/viciphone/"
            chown -R apache:apache "${AGC_DIR}/viciphone"
            chmod -R 755 "${AGC_DIR}/viciphone"
            success "ViciPhone installed at ${AGC_DIR}/viciphone/"
        else
            warn "Could not clone ViciPhone. Install manually from: ${VICIPHONE_REPO}"
        fi
        rm -rf "$TMPDIR"
    fi
elif [ "$MODE" = "asterisk" ]; then
    log "Skipping Step 8 (ViciPhone) — asterisk mode"
else
    log "Skipping Step 8 (ViciPhone) — --skip-viciphone"
fi

# =============================================================================
# STEP 9: OPTIONS.PHP  (web + standalone only)
# =============================================================================
if [ "$MODE" != "asterisk" ]; then
    section "STEP 9: ViciDial options.php"

    OPTIONS_FILE="${AGC_DIR}/options.php"
    if [ -f "$OPTIONS_FILE" ]; then
        success "options.php already exists"
    else
        if [ -f "${AGC_DIR}/options-example.php" ]; then
            cp "${AGC_DIR}/options-example.php" "$OPTIONS_FILE"
            sed -i "s|\$webphone_call_seconds.*=.*|\$webphone_call_seconds\t\t\t= '10';|" \
                "$OPTIONS_FILE" 2>/dev/null || true
            chown apache:apache "$OPTIONS_FILE"
            success "Created options.php (webphone_call_seconds=10)"
        else
            warn "options-example.php not found — options.php must be created manually"
        fi
    fi
else
    log "Skipping Step 9 (options.php) — asterisk mode"
fi

# =============================================================================
# STEP 10: CRONTAB — HTTPS recordings  (web + standalone only)
# =============================================================================
if [ "$MODE" != "asterisk" ]; then
    section "STEP 10: Crontab HTTPS Recordings"

    CRONTAB_FILE="/var/spool/cron/root"
    if grep -q "\-\-HTTPS" "$CRONTAB_FILE" 2>/dev/null; then
        success "HTTPS flag already in crontab audio compress"
    elif grep -q "AST_CRON_audio_2_compress.pl" "$CRONTAB_FILE" 2>/dev/null; then
        sed -i '/AST_CRON_audio_2_compress.pl/ s/$/ --HTTPS/' "$CRONTAB_FILE"
        success "Added --HTTPS flag to audio compress crontab"
    else
        log "AST_CRON_audio_2_compress.pl not found in crontab — skipping"
    fi
else
    log "Skipping Step 10 (crontab) — asterisk mode"
fi

# =============================================================================
# STEP 11: CREATE AGENTS AND PHONES  (web + standalone only)
# =============================================================================
if [ "$MODE" != "asterisk" ] && [ "$NUM_AGENTS" -gt 0 ] && [ "$DB_AVAILABLE" = true ]; then
    section "STEP 11: Creating ${NUM_AGENTS} Agents & Phones"

    AST_SERVER_IP="${ASTERISK_IP:-${SERVER_IP}}"

    for i in $(seq 1 "$NUM_AGENTS"); do
        EXT=$((START_EXT + i - 1))
        PASS="Cbz${EXT}x"

        PHONE_EXISTS=$(mysql_cmd -N -e \
            "SELECT COUNT(*) FROM phones WHERE extension='${EXT}';" 2>/dev/null)
        if [ "$PHONE_EXISTS" != "0" ]; then
            log "Phone ${EXT} already exists — skipping"
            continue
        fi

        AGENT_EXISTS=$(mysql_cmd -N -e \
            "SELECT COUNT(*) FROM vicidial_users WHERE user='${EXT}';" 2>/dev/null)
        if [ "$AGENT_EXISTS" = "0" ]; then
            mysql_cmd -e "INSERT INTO vicidial_users
                (user, pass, full_name, user_level, user_group, phone_login, phone_pass,
                 agent_choose_ingroups, scheduled_callbacks, vicidial_recording, vicidial_transfers)
                VALUES ('${EXT}', '${PASS}', 'Agent ${EXT}', 4, 'AGENTS', '${EXT}', '${PASS}',
                        '1', '1', '1', '1');" 2>/dev/null
            log "Created agent ${EXT}"
        fi

        mysql_cmd -e "INSERT INTO phones
            (extension, dialplan_number, voicemail_id, server_ip, login, pass, status, active,
             phone_type, fullname, protocol, local_gmt, ASTmgrUSERNAME, ASTmgrSECRET, conf_secret,
             is_webphone, webphone_auto_answer, webphone_dialpad, webphone_dialbox,
             webphone_mute, webphone_volume, template_id)
            VALUES ('${EXT}', '${EXT}', '${EXT}', '${AST_SERVER_IP}', '${EXT}', '${PASS}',
                    'ACTIVE', 'Y', 'SIP', 'Agent ${EXT}', 'SIP', '-5.00', 'cron', '1234',
                    '${PASS}', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'webrtc');" 2>/dev/null
        log "Created phone ${EXT} (webrtc template, server: ${AST_SERVER_IP})"
    done

    success "Created ${NUM_AGENTS} agent/phone pairs (${START_EXT} - $((START_EXT + NUM_AGENTS - 1)))"
fi

# =============================================================================
# STEP 12: FIREWALL
# Uses nftables (native on RHEL/Rocky 10). Disables firewalld if present.
# Asterisk mode: locks port 5060 to carrier IP only — stops SIP brute-force.
# =============================================================================
section "STEP 12: Firewall Configuration (nftables)"

# Read RTP range from rtp.conf (needed for asterisk/standalone modes)
RTP_START=$(grep "^rtpstart=" /etc/asterisk/rtp.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
RTP_END=$(grep   "^rtpend="   /etc/asterisk/rtp.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
RTP_START=${RTP_START:-10000}
RTP_END=${RTP_END:-20000}

# Disable firewalld if running (conflicts with nftables)
if systemctl is-active firewalld &>/dev/null; then
    systemctl stop firewalld
    systemctl disable firewalld
    log "firewalld stopped and disabled — using nftables"
fi

if command -v nft &>/dev/null; then
    # Build ruleset based on mode
    if [ "$MODE" = "web" ]; then
        # Server #1: web/DB only — no SIP, no RTP
        cat > /etc/sysconfig/nftables.conf <<NFTEOF
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ip  protocol icmp   accept
        ip6 nexthdr  icmpv6 accept
        meta l4proto tcp ct state established,related accept
        tcp dport { 22, 80, 443, 446, 1951 } accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
NFTEOF
        success "Firewall: web mode — 80/443 open, all else dropped"

    elif [ "$MODE" = "asterisk" ]; then
        # Server #2: Asterisk — SIP locked to carrier IP, RTP open, 8089 open
        if [ -z "$CARRIER_IP" ]; then
            warn "No --carrier-ip specified — port 5060 will be closed entirely (add rich rule manually)"
            SIP_RULES="# No carrier IP specified — port 5060 blocked"
        else
            SIP_RULES="        ip saddr != ${CARRIER_IP} udp dport 5060 drop
        ip saddr != ${CARRIER_IP} tcp dport 5060 drop
        ip saddr ${CARRIER_IP} udp dport 5060 accept
        ip saddr ${CARRIER_IP} tcp dport 5060 accept"
        fi
        cat > /etc/sysconfig/nftables.conf <<NFTEOF
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ip  protocol icmp   accept
        ip6 nexthdr  icmpv6 accept
        meta l4proto tcp ct state established,related accept
        # SIP — carrier only (explicit early drop prevents brute-force bypass)
${SIP_RULES}
        # SSH, HTTP (certbot), WSS
        tcp dport { 22, 80, 1951 } accept
        tcp dport 8089 accept
        # RTP media
        udp dport ${RTP_START}-${RTP_END} accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
NFTEOF
        success "Firewall: asterisk mode — 8089/tcp, ${RTP_START}-${RTP_END}/udp open; 5060 locked to ${CARRIER_IP:-NONE}"

    else
        # Standalone: all ports on one server
        if [ -n "$CARRIER_IP" ]; then
            SIP_RULES="        ip saddr != ${CARRIER_IP} udp dport 5060 drop
        ip saddr != ${CARRIER_IP} tcp dport 5060 drop
        ip saddr ${CARRIER_IP} udp dport 5060 accept
        ip saddr ${CARRIER_IP} tcp dport 5060 accept"
        else
            SIP_RULES="        # No --carrier-ip set — port 5060 open (add restriction manually)"
        fi
        cat > /etc/sysconfig/nftables.conf <<NFTEOF
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ip  protocol icmp   accept
        ip6 nexthdr  icmpv6 accept
        meta l4proto tcp ct state established,related accept
${SIP_RULES}
        tcp dport { 22, 80, 443, 446, 1951 } accept
        tcp dport 8089 accept
        udp dport ${RTP_START}-${RTP_END} accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
NFTEOF
        success "Firewall: standalone mode — all required ports open"
    fi

    # Apply and enable
    nft flush ruleset
    nft -f /etc/sysconfig/nftables.conf
    systemctl enable nftables &>/dev/null
    systemctl start  nftables &>/dev/null
    success "nftables rules applied and enabled (persistent)"
else
    warn "nftables not found — install with: dnf install -y nftables"
    warn "Open ports manually: 443(web), 8089(WSS), ${RTP_START}-${RTP_END}/udp(RTP), 5060(carrier only)"
fi

# =============================================================================
# STEP 13: FINAL VERIFICATION
# =============================================================================
section "STEP 13: Final Verification"

if [ "$MODE" != "web" ]; then
    asterisk -rx "sip reload" &>/dev/null || true
    sleep 2

    WSS_STATUS=$(asterisk -rx "http show status" 2>/dev/null | grep -i "https\|tls" || echo "NOT FOUND")
    if echo "$WSS_STATUS" | grep -qi "enabled\|8089"; then
        success "Asterisk HTTPS/WSS active: ${WSS_STATUS}"
    else
        warn "Asterisk HTTPS/WSS may not be active. Check with: asterisk -rx 'http show status'"
    fi

    if asterisk -rx "http show status" 2>/dev/null | grep -q "/ws"; then
        success "WebSocket endpoint /ws is active"
    else
        warn "WebSocket /ws not found — may need full Asterisk restart: systemctl restart asterisk"
    fi

    SIP_PEERS=$(asterisk -rx "sip show peers" 2>/dev/null | tail -1)
    success "SIP peers: ${SIP_PEERS}"
fi

if [ "$MODE" != "asterisk" ]; then
    if systemctl is-active httpd &>/dev/null; then
        success "Apache (httpd) is running"
    else
        warn "Apache (httpd) is not running — check: systemctl status httpd"
    fi
fi

# =============================================================================
# SUMMARY
# =============================================================================
section "INSTALLATION COMPLETE  [mode: ${MODE^^}]"
echo ""

case "$MODE" in
    standalone)
        echo -e "  Domain:        ${GREEN}${WEB_DOMAIN}${NC}"
        echo -e "  Public IP:     ${GREEN}${PUBLIC_IP}${NC}"
        echo ""
        echo -e "  ViciDial URL:  ${GREEN}https://${WEB_DOMAIN}/vicidial/welcome.php${NC}"
        echo -e "  Agent Login:   ${GREEN}https://${WEB_DOMAIN}/agc/vicidial.php${NC}"
        echo -e "  WSS Endpoint:  ${GREEN}wss://${ASTERISK_DOMAIN}:8089/ws${NC}"
        ;;
    web)
        echo -e "  Web Domain:      ${GREEN}${WEB_DOMAIN}${NC}  (this server — Server #1)"
        echo -e "  Asterisk Domain: ${GREEN}${ASTERISK_DOMAIN}${NC}  (Server #2 — ${ASTERISK_IP})"
        echo -e "  Public IP:       ${GREEN}${PUBLIC_IP}${NC}"
        echo ""
        echo -e "  ViciDial URL:    ${GREEN}https://${WEB_DOMAIN}/vicidial/welcome.php${NC}"
        echo -e "  Agent Login:     ${GREEN}https://${WEB_DOMAIN}/agc/vicidial.php${NC}"
        echo -e "  WSS Endpoint:    ${GREEN}wss://${ASTERISK_DOMAIN}:8089/ws${NC}  [direct to Server #2]"
        echo ""
        echo -e "  ${YELLOW}NOW: Run the installer on Server #2 (${ASTERISK_IP}):${NC}"
        echo -e "  ${CYAN}  ./install_webphone.sh --mode asterisk --domain ${ASTERISK_DOMAIN}${NC}"
        ;;
    asterisk)
        echo -e "  Asterisk Domain: ${GREEN}${ASTERISK_DOMAIN}${NC}"
        echo -e "  Public IP:       ${GREEN}${PUBLIC_IP}${NC}"
        echo ""
        echo -e "  WSS Endpoint:  ${GREEN}wss://${ASTERISK_DOMAIN}:8089/ws${NC}"
        echo -e "  Asterisk HTTP: ${GREEN}TLS on 0.0.0.0:8089${NC}"
        ;;
esac

echo ""

if [ "$NUM_AGENTS" -gt 0 ] && [ "$MODE" != "asterisk" ]; then
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
if [ "$MODE" != "asterisk" ]; then
    echo -e "  1. In ViciDial Admin > Phones, set Template ID to '${GREEN}webrtc${NC}'"
    echo -e "  2. Set 'Is Webphone' to ${GREEN}Y${NC} on each phone"
    echo -e "  3. Agent logs in at ${GREEN}https://${WEB_DOMAIN}/agc/vicidial.php${NC}"
    echo -e "  4. Browser will ask for microphone permission — click Allow"
fi
if [ "$MODE" = "web" ]; then
    echo -e "  5. ${YELLOW}Run --mode asterisk on Server #2 to complete the setup${NC}"
fi
echo ""
echo -e "  ${YELLOW}SSL certificates auto-renew via certbot.${NC}"
echo ""
