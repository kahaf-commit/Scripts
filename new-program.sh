#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# KAHAF-COMMIT
# Bug Bounty Recon Framework
# ============================================================
#
# Author  : Jubair Hossain
# GitHub  : github.com/kahaf-commit
# Website : jubairsec.com
#
# Usage:
#   ./kahaf-commit.sh example.com
#   ./kahaf-commit.sh 192.168.1.10
#   ./kahaf-commit.sh program-name
#
# Modes:
#   DOMAIN -> Full domain reconnaissance
#   IP     -> IP reconnaissance
#   NAME   -> Workspace creation only
#
# IMPORTANT:
#   Use only against assets explicitly authorized
#   by the applicable bug bounty/security program.
# ============================================================


# ============================================================
# Configuration
# ============================================================

BASE_DIR="${HOME}/bugbounty"
TARGET="${1:-}"


# ============================================================
# Colors
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'


# ============================================================
# Output Functions
# ============================================================

info() {
    echo -e "${CYAN}[*]${NC} $1"
}

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
}

section() {
    echo
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}============================================================${NC}"
}


# ============================================================
# Banner
# ============================================================

clear

cat << 'EOF'

        ==================================================
                       KAHAF-COMMIT
                  BUG BOUNTY RECON FRAMEWORK
        ==================================================

        [*] Author  : Jubair Hossain
        [*] GitHub  : github.com/kahaf-commit
        [*] Website : jubairsec.com
        [*] Purpose : Bug Bounty Reconnaissance
        [*] Mode    : Passive / Authorized Testing
        ==================================================

EOF

sleep 1


# ============================================================
# Usage
# ============================================================

if [[ -z "$TARGET" ]]; then

    echo
    echo "[!] Usage: $0 <domain|IP|workspace-name>"
    echo
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 192.168.1.10"
    echo "  $0 program-name"
    echo

    exit 1

fi


# ============================================================
# Normalize Target
# ============================================================

TARGET="${TARGET%/}"
TARGET="${TARGET%.}"


# ============================================================
# Target Detection
# ============================================================

is_ipv4() {

    local ip="$1"
    local IFS=.
    local octets

    read -ra octets <<< "$ip"

    [[ ${#octets[@]} -eq 4 ]] || return 1

    for octet in "${octets[@]}"; do

        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1

    done

    return 0
}


is_domain() {

    [[ "$1" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]

}


if is_ipv4 "$TARGET"; then

    TARGET_TYPE="IP"

elif is_domain "$TARGET"; then

    TARGET_TYPE="DOMAIN"

else

    TARGET_TYPE="NAME"

fi


# ============================================================
# Workspace
# ============================================================

BASE="$BASE_DIR/$TARGET"


section "TARGET INFORMATION"

echo
echo " Target      : $TARGET"
echo " Type        : $TARGET_TYPE"
echo " Workspace   : $BASE"
echo


# ============================================================
# Create Workspace
# ============================================================

section "CREATING WORKSPACE"

DIRS=(

    "$BASE"
    "$BASE/recon"
    "$BASE/recon/subdomains"
    "$BASE/recon/dns"
    "$BASE/recon/http"
    "$BASE/recon/urls"
    "$BASE/recon/parameters"
    "$BASE/recon/endpoints"
    "$BASE/recon/js"
    "$BASE/recon/technologies"
    "$BASE/recon/ports"
    "$BASE/recon/screenshots"
    "$BASE/vulnerabilities"
    "$BASE/nuclei"
    "$BASE/notes"
    "$BASE/reports"

)


for DIR in "${DIRS[@]}"; do
    mkdir -p "$DIR"
done


success "Workspace created"


# ============================================================
# README
# ============================================================

cat > "$BASE/README.md" <<EOF
# KAHAF-COMMIT Bug Bounty Workspace

Target      : $TARGET
Target Type : $TARGET_TYPE
Created     : $(date)

## Framework

KAHAF-COMMIT

Author:
Jubair Hossain

GitHub:
github.com/kahaf-commit

Website:
jubairsec.com

## Recon

- Subdomains
- DNS
- HTTP
- URLs
- Parameters
- Endpoints
- JavaScript
- Technologies
- Screenshots
- Ports

## Vulnerabilities

Document confirmed findings here.

## Reports

Store final reports here.

## Scope

Only test assets explicitly authorized by the applicable
bug bounty or security testing program.
EOF


# ============================================================
# Scope File
# ============================================================

cat > "$BASE/notes/scope.txt" <<EOF
============================================================
KAHAF-COMMIT TARGET SCOPE
============================================================

Target:
$TARGET

Target Type:
$TARGET_TYPE

============================================================
IN-SCOPE
============================================================

-

============================================================
OUT-OF-SCOPE
============================================================

-

============================================================
NOTES
============================================================

-

============================================================
IMPORTANT
============================================================

Verify the official program scope before performing
active security testing.

============================================================
EOF


# ============================================================
# Workspace-Only Mode
# ============================================================

if [[ "$TARGET_TYPE" == "NAME" ]]; then

    section "WORKSPACE MODE"

    info "Workspace-only mode selected."
    info "No reconnaissance will be performed."

    echo
    success "Workspace ready:"
    echo "  $BASE"
    echo

    exit 0

fi


# ============================================================
# IP MODE
# ============================================================

if [[ "$TARGET_TYPE" == "IP" ]]; then

    section "IP RECONNAISSANCE"

    info "Starting IP reconnaissance."

    printf '%s\n' "$TARGET" \
        > "$BASE/recon/ports/targets.txt"


    # --------------------------------------------------------
    # HTTPX
    # --------------------------------------------------------

    if command -v httpx >/dev/null 2>&1; then

        info "Checking HTTP services..."

        printf '%s\n' "$TARGET" |
            httpx \
                -silent \
                -follow-redirects \
                -status-code \
                -title \
                -tech-detect \
                -o "$BASE/recon/http/httpx.txt" \
                || true


        if [[ -s "$BASE/recon/http/httpx.txt" ]]; then

            awk '{print $1}' \
                "$BASE/recon/http/httpx.txt" |
                sort -u \
                > "$BASE/recon/http/live.txt"

            success "HTTP discovery completed"

        else

            warning "No HTTP service discovered"

        fi

    else

        warning "httpx not installed - HTTP discovery skipped"

    fi


    # --------------------------------------------------------
    # Nuclei
    # --------------------------------------------------------

    if command -v nuclei >/dev/null 2>&1 &&
       [[ -s "$BASE/recon/http/live.txt" ]]; then

        section "NUCLEI VALIDATION"

        info "Running rate-limited Nuclei."

        nuclei \
            -l "$BASE/recon/http/live.txt" \
            -severity low,medium,high,critical \
            -rate-limit 10 \
            -concurrency 5 \
            -o "$BASE/nuclei/results.txt" \
            || true

        success "Nuclei completed"

    else

        warning "Nuclei skipped"

    fi


    section "IP RECON COMPLETE"

    echo
    echo " Workspace : $BASE"
    echo " HTTP      : $BASE/recon/http/"
    echo " Nuclei    : $BASE/nuclei/"
    echo

    exit 0

fi


# ============================================================
# DOMAIN MODE
# ============================================================

section "DOMAIN RECONNAISSANCE"

info "Target: $TARGET"


# ============================================================
# Dependency Check
# ============================================================

section "DEPENDENCY CHECK"

TOOLS=(
    curl
    dig
    subfinder
    httpx
    gau
    waybackurls
    nuclei
    gowitness
)


for TOOL in "${TOOLS[@]}"; do

    if command -v "$TOOL" >/dev/null 2>&1; then
        success "$TOOL"
    else
        warning "$TOOL not installed"
    fi

done


# ============================================================
# Passive Subdomain Enumeration
# ============================================================

section "SUBDOMAIN ENUMERATION"

if command -v subfinder >/dev/null 2>&1; then

    info "Running Subfinder..."

    subfinder \
        -d "$TARGET" \
        -silent \
        -o "$BASE/recon/subdomains/subfinder.txt" \
        || true

    success "Subfinder completed"

else

    warning "Subfinder unavailable"

fi


# ============================================================
# Certificate Transparency
# ============================================================

section "CERTIFICATE TRANSPARENCY"

if command -v curl >/dev/null 2>&1; then

    info "Querying crt.sh..."

    curl -s \
        --max-time 30 \
        "https://crt.sh/?q=%25.${TARGET}&output=json" |
        grep -oE '"name_value":"[^"]+"' |
        sed 's/"name_value":"//g' |
        sed 's/"//g' |
        sed 's/\\n/\n/g' |
        sed 's/\*\.//g' |
        sort -u \
        > "$BASE/recon/subdomains/crtsh.txt" \
        || true

    success "Certificate data collected"

fi


# ============================================================
# Combine Subdomains
# ============================================================

cat \
    "$BASE/recon/subdomains/"*.txt \
    2>/dev/null |
    sed '/^$/d' |
    sort -u \
    > "$BASE/recon/subdomains/all.txt"


SUBDOMAIN_COUNT=$(
    wc -l < "$BASE/recon/subdomains/all.txt"
)


success "Unique subdomains: $SUBDOMAIN_COUNT"


# ============================================================
# DNS Resolution
# ============================================================

section "DNS RESOLUTION"

if command -v dig >/dev/null 2>&1 &&
   [[ -s "$BASE/recon/subdomains/all.txt" ]]; then

    while IFS= read -r SUBDOMAIN; do

        [[ -z "$SUBDOMAIN" ]] && continue

        IP=$(
            dig +short "$SUBDOMAIN" A 2>/dev/null |
            grep -E \
                '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
            head -n 1 ||
            true
        )


        if [[ -n "$IP" ]]; then

            printf "%-50s %s\n" \
                "$SUBDOMAIN" \
                "$IP"

        fi

    done < "$BASE/recon/subdomains/all.txt" \
        > "$BASE/recon/dns/resolved.txt"


    success "DNS resolution completed"

else

    warning "No domains available for DNS resolution"

fi


# ============================================================
# Live Host Discovery
# ============================================================

section "LIVE HOST DISCOVERY"

if command -v httpx >/dev/null 2>&1 &&
   [[ -s "$BASE/recon/subdomains/all.txt" ]]; then

    info "Running HTTPX..."

    httpx \
        -l "$BASE/recon/subdomains/all.txt" \
        -silent \
        -follow-redirects \
        -status-code \
        -title \
        -tech-detect \
        -o "$BASE/recon/http/httpx.txt" \
        || true


    if [[ -s "$BASE/recon/http/httpx.txt" ]]; then

        awk '{print $1}' \
            "$BASE/recon/http/httpx.txt" |
            sort -u \
            > "$BASE/recon/http/live.txt"


        awk '{print $1}' \
            "$BASE/recon/http/httpx.txt" |
            sed 's#https\?://##' |
            cut -d/ -f1 |
            sort -u \
            > "$BASE/recon/http/hosts.txt"


        success "Live hosts discovered"

    else

        warning "No live HTTP hosts discovered"

    fi

else

    warning "HTTPX unavailable or no subdomains found"

fi


# ============================================================
# Technology Discovery
# ============================================================

section "TECHNOLOGY DISCOVERY"

if [[ -s "$BASE/recon/http/httpx.txt" ]]; then

    cp \
        "$BASE/recon/http/httpx.txt" \
        "$BASE/recon/technologies/httpx-technologies.txt"

    grep -Ei \
        'nginx|apache|iis|wordpress|php|node|react|angular|vue|django|laravel|express|cloudflare|tomcat|next.js' \
        "$BASE/recon/http/httpx.txt" \
        > "$BASE/recon/technologies/detected.txt" \
        || true

    success "Technology information saved"

else

    warning "Technology discovery skipped"

fi


# ============================================================
# URL Discovery - GAU
# ============================================================

section "URL DISCOVERY"

if command -v gau >/dev/null 2>&1; then

    info "Running GAU..."

    gau \
        --subs \
        "$TARGET" \
        2>/dev/null |
        sort -u \
        > "$BASE/recon/urls/gau.txt" \
        || true

    success "GAU completed"

else

    warning "GAU unavailable"

fi


# ============================================================
# URL Discovery - Wayback
# ============================================================

if command -v waybackurls >/dev/null 2>&1; then

    info "Running Waybackurls..."

    printf '%s\n' "$TARGET" |
        waybackurls |
        sort -u \
        > "$BASE/recon/urls/wayback.txt" \
        || true

    success "Waybackurls completed"

else

    warning "Waybackurls unavailable"

fi


# ============================================================
# Combine URLs
# ============================================================

cat \
    "$BASE/recon/urls/"*.txt \
    2>/dev/null |
    sed '/^$/d' |
    sort -u \
    > "$BASE/recon/urls/all.txt"


URL_COUNT=$(
    wc -l < "$BASE/recon/urls/all.txt"
)


success "Unique URLs: $URL_COUNT"


# ============================================================
# Parameter Discovery
# ============================================================

section "PARAMETER DISCOVERY"

if [[ -s "$BASE/recon/urls/all.txt" ]]; then

    grep '?' \
        "$BASE/recon/urls/all.txt" |
        sort -u \
        > "$BASE/recon/parameters/with-parameters.txt" \
        || true


    sed 's/.*?//' \
        "$BASE/recon/parameters/with-parameters.txt" |
        tr '&' '\n' |
        cut -d'=' -f1 |
        sed '/^$/d' |
        sort -u \
        > "$BASE/recon/parameters/names.txt" \
        || true


    PARAM_COUNT=$(
        wc -l < "$BASE/recon/parameters/with-parameters.txt"
    )


    success "Parameterized URLs: $PARAM_COUNT"

else

    warning "No URLs available for parameter discovery"

fi


# ============================================================
# Interesting Endpoint Discovery
# ============================================================

section "INTERESTING ENDPOINTS"

if [[ -s "$BASE/recon/urls/all.txt" ]]; then

    grep -Ei \
        'api|admin|login|signin|signup|register|auth|oauth|token|upload|download|redirect|callback|debug|graphql|swagger|api-docs|password|reset|forgot|user|account' \
        "$BASE/recon/urls/all.txt" |
        sort -u \
        > "$BASE/recon/endpoints/interesting.txt" \
        || true


    ENDPOINT_COUNT=$(
        wc -l < "$BASE/recon/endpoints/interesting.txt"
    )


    success "Interesting endpoints: $ENDPOINT_COUNT"

else

    warning "Endpoint discovery skipped"

fi


# ============================================================
# JavaScript Discovery
# ============================================================

section "JAVASCRIPT DISCOVERY"

if [[ -s "$BASE/recon/urls/all.txt" ]]; then

    grep -Ei \
        '\.js([?#]|$)' \
        "$BASE/recon/urls/all.txt" |
        sort -u \
        > "$BASE/recon/js/javascript.txt" \
        || true


    JS_COUNT=$(
        wc -l < "$BASE/recon/js/javascript.txt"
    )


    success "JavaScript URLs: $JS_COUNT"

else

    warning "JavaScript discovery skipped"

fi


# ============================================================
# Screenshots
# ============================================================

if command -v gowitness >/dev/null 2>&1 &&
   [[ -s "$BASE/recon/http/live.txt" ]]; then

    section "SCREENSHOT COLLECTION"

    info "Running Gowitness..."

    gowitness scan file \
        -f "$BASE/recon/http/live.txt" \
        --destination "$BASE/recon/screenshots" \
        2>/dev/null \
        || true

    success "Screenshot collection completed"

fi


# ============================================================
# Nuclei Validation
# ============================================================

if command -v nuclei >/dev/null 2>&1 &&
   [[ -s "$BASE/recon/http/live.txt" ]]; then

    section "NUCLEI VALIDATION"

    info "Running rate-limited Nuclei..."

    nuclei \
        -l "$BASE/recon/http/live.txt" \
        -severity low,medium,high,critical \
        -rate-limit 10 \
        -concurrency 5 \
        -o "$BASE/nuclei/results.txt" \
        || true

    success "Nuclei completed"

else

    warning "Nuclei skipped"

fi


# ============================================================
# Final Summary
# ============================================================

section "RECON COMPLETE"

echo

echo " Target      : $TARGET"
echo " Type        : $TARGET_TYPE"
echo
echo " Workspace   : $BASE"
echo
echo " Subdomains  : $BASE/recon/subdomains/all.txt"
echo " DNS         : $BASE/recon/dns/resolved.txt"
echo " Live Hosts  : $BASE/recon/http/live.txt"
echo " URLs        : $BASE/recon/urls/all.txt"
echo " Parameters  : $BASE/recon/parameters/with-parameters.txt"
echo " Endpoints   : $BASE/recon/endpoints/interesting.txt"
echo " JavaScript  : $BASE/recon/js/javascript.txt"
echo " Technologies: $BASE/recon/technologies/"
echo " Screenshots : $BASE/recon/screenshots/"
echo " Nuclei      : $BASE/nuclei/results.txt"

echo

echo "============================================================"
echo
echo "             KAHAF-COMMIT | Jubair Hossain"
echo "             github.com/kahaf-commit"
echo "             jubairsec.com"
echo
echo "             Authorized Bug Bounty Recon"
echo
echo "============================================================"

echo
