#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Bug Bounty Workspace & Recon Script
#
# Usage:
#   ./new-program.sh example.com
#   ./new-program.sh 192.168.1.10
#   ./new-program.sh varonis
#
# Modes:
#   DOMAIN -> Full reconnaissance
#   IP     -> IP-based reconnaissance
#   NAME   -> Workspace creation only
# ============================================================

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <domain|IP|workspace-name>"
    echo
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 192.168.1.10"
    echo "  $0 varonis"
    exit 1
fi

# Remove trailing slash/dot
TARGET="${TARGET%/}"
TARGET="${TARGET%.}"

# ============================================================
# Detect Target Type
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

BASE="$HOME/bugbounty/$TARGET"

echo
echo "============================================================"
echo " Bug Bounty Workspace"
echo "============================================================"
echo
echo "[*] Target       : $TARGET"
echo "[*] Target Type  : $TARGET_TYPE"
echo "[*] Workspace    : $BASE"
echo

# ============================================================
# Directory Structure
# ============================================================

DIRS=(
    "$BASE"
    "$BASE/recon"
    "$BASE/recon/subdomains"
    "$BASE/recon/dns"
    "$BASE/recon/http"
    "$BASE/recon/urls"
    "$BASE/recon/screenshots"
    "$BASE/recon/ports"
    "$BASE/vulnerabilities"
    "$BASE/nuclei"
    "$BASE/notes"
    "$BASE/reports"
)

for DIR in "${DIRS[@]}"; do
    mkdir -p "$DIR"
done

echo "[+] Workspace structure created"

# ============================================================
# README
# ============================================================

cat > "$BASE/README.md" <<EOF
# Bug Bounty Workspace

Target: $TARGET
Type: $TARGET_TYPE
Created: $(date)

## Scope

Verify the official program scope before performing active testing.

## Recon

- Subdomains
- DNS
- HTTP
- URLs
- Ports
- Screenshots

## Vulnerabilities

Store confirmed findings here.

## Reports

Store final reports here.

## Notes

Keep manual testing notes here.
EOF

# ============================================================
# Scope File
# ============================================================

cat > "$BASE/notes/scope.txt" <<EOF
============================================================
TARGET / SCOPE
============================================================

Target:
$TARGET

Target Type:
$TARGET_TYPE

============================================================
IMPORTANT
============================================================

Only test assets explicitly authorized by the program.

Add confirmed in-scope assets below.

In-Scope:
-

Out-of-Scope:
-

Notes:
-

============================================================
EOF

# ============================================================
# NAME MODE
#
# Example:
# ./new-program.sh varonis
#
# Only creates workspace.
# ============================================================

if [[ "$TARGET_TYPE" == "NAME" ]]; then

    echo
    echo "[*] Workspace-only mode"
    echo "[*] No reconnaissance will be performed."
    echo
    echo "[+] Workspace ready:"
    echo "    $BASE"
    echo

    exit 0
fi

# ============================================================
# IP MODE
#
# Example:
# ./new-program.sh 192.168.1.10
#
# No subdomain enumeration or crt.sh.
# ============================================================

if [[ "$TARGET_TYPE" == "IP" ]]; then

    echo
    echo "[*] IP reconnaissance mode"

    printf '%s\n' "$TARGET" \
        > "$BASE/recon/ports/targets.txt"

    # --------------------------------------------------------
    # HTTP Enumeration
    # --------------------------------------------------------

    if command -v httpx >/dev/null 2>&1; then

        echo "[*] Checking HTTP services..."

        printf '%s\n' "$TARGET" |
            httpx \
                -silent \
                -status-code \
                -title \
                -tech-detect \
                -follow-redirects \
                -o "$BASE/recon/http/httpx.txt" || true

        if [[ -f "$BASE/recon/http/httpx.txt" ]]; then
            awk '{print $1}' "$BASE/recon/http/httpx.txt" |
                sort -u \
                > "$BASE/recon/http/live.txt"
        fi

    else
        echo "[!] httpx not installed - skipping HTTP enumeration"
    fi

    # --------------------------------------------------------
    # Nuclei
    # --------------------------------------------------------

    if command -v nuclei >/dev/null 2>&1 &&
       [[ -s "$BASE/recon/http/live.txt" ]]; then

        echo
        echo "[*] Running rate-limited Nuclei scan..."
        echo "[*] Verify authorization before active scanning."

        nuclei \
            -l "$BASE/recon/http/live.txt" \
            -severity info,low,medium,high,critical \
            -rate-limit 10 \
            -concurrency 5 \
            -o "$BASE/nuclei/results.txt" || true

    else
        echo "[!] Nuclei skipped"
    fi

    echo
    echo "============================================================"
    echo " IP RECON COMPLETE"
    echo "============================================================"
    echo
    echo "Workspace : $BASE"
    echo "HTTP      : $BASE/recon/http/"
    echo "Nuclei    : $BASE/nuclei/"
    echo

    exit 0
fi

# ============================================================
# DOMAIN MODE
#
# Example:
# ./new-program.sh example.com
# ============================================================

echo
echo "[*] Domain reconnaissance mode"

# ============================================================
# Dependency Check
# ============================================================

echo
echo "[*] Checking tools..."

for TOOL in curl dig; do
    if command -v "$TOOL" >/dev/null 2>&1; then
        echo "[+] $TOOL"
    else
        echo "[!] $TOOL not installed"
    fi
done

# ============================================================
# Subdomain Enumeration
# ============================================================

echo
echo "[*] Starting passive subdomain enumeration..."

if command -v subfinder >/dev/null 2>&1; then

    subfinder \
        -d "$TARGET" \
        -silent \
        -o "$BASE/recon/subdomains/subfinder.txt" || true

    echo "[+] Subfinder completed"

else
    echo "[!] subfinder not installed - skipping"
fi

# ============================================================
# Certificate Transparency
# ============================================================

echo
echo "[*] Collecting Certificate Transparency data..."

if command -v curl >/dev/null 2>&1; then

    curl -s \
        "https://crt.sh/?q=%25.${TARGET}&output=json" |
        grep -oE '"name_value":"[^"]+"' |
        sed 's/"name_value":"//g' |
        sed 's/"//g' |
        sed 's/\\n/\n/g' |
        sed 's/\*\.//g' |
        sort -u \
        > "$BASE/recon/subdomains/crtsh.txt" || true

    echo "[+] Certificate data saved"

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

echo "[+] Unique subdomains: $(wc -l < "$BASE/recon/subdomains/all.txt")"

# ============================================================
# DNS Resolution
# ============================================================

echo
echo "[*] Resolving domains..."

if command -v dig >/dev/null 2>&1; then

    while IFS= read -r SUBDOMAIN; do

        [[ -z "$SUBDOMAIN" ]] && continue

        IP=$(dig +short "$SUBDOMAIN" A 2>/dev/null |
             grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
             head -n 1 || true)

        if [[ -n "$IP" ]]; then
            printf "%-50s %s\n" "$SUBDOMAIN" "$IP"
        fi

    done < "$BASE/recon/subdomains/all.txt" \
        > "$BASE/recon/dns/resolved.txt"

fi

# ============================================================
# HTTP Enumeration
# ============================================================

echo
echo "[*] Checking HTTP services..."

if command -v httpx >/dev/null 2>&1; then

    httpx \
        -l "$BASE/recon/subdomains/all.txt" \
        -silent \
        -follow-redirects \
        -status-code \
        -title \
        -tech-detect \
        -o "$BASE/recon/http/httpx.txt" || true

    if [[ -f "$BASE/recon/http/httpx.txt" ]]; then

        awk '{print $1}' "$BASE/recon/http/httpx.txt" |
            sort -u \
            > "$BASE/recon/http/live.txt"

    fi

    echo "[+] HTTP enumeration completed"

else
    echo "[!] httpx not installed - skipping"
fi

# ============================================================
# Historical URL Discovery
# ============================================================

echo
echo "[*] Collecting historical URLs..."

if command -v gau >/dev/null 2>&1; then

    gau \
        --subs \
        "$TARGET" \
        2>/dev/null |
        sort -u \
        > "$BASE/recon/urls/gau.txt" || true

    echo "[+] GAU completed"

else
    echo "[!] gau not installed - skipping"
fi

if command -v waybackurls >/dev/null 2>&1; then

    printf '%s\n' "$TARGET" |
        waybackurls |
        sort -u \
        > "$BASE/recon/urls/wayback.txt" || true

    echo "[+] Wayback collection completed"

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

echo "[+] Total URLs: $(wc -l < "$BASE/recon/urls/all.txt")"

# ============================================================
# Interesting Endpoints
# ============================================================

grep -Ei \
    '(\?|=|api|admin|login|auth|oauth|token|upload|redirect|callback|debug|graphql|swagger)' \
    "$BASE/recon/urls/all.txt" \
    2>/dev/null |
    sort -u \
    > "$BASE/recon/urls/interesting.txt" || true

echo "[+] Interesting endpoints extracted"

# ============================================================
# Nuclei
# ============================================================

if command -v nuclei >/dev/null 2>&1 &&
   [[ -s "$BASE/recon/http/live.txt" ]]; then

    echo
    echo "[*] Running rate-limited Nuclei scan..."

    nuclei \
        -l "$BASE/recon/http/live.txt" \
        -severity info,low,medium,high,critical \
        -rate-limit 10 \
        -concurrency 5 \
        -o "$BASE/nuclei/results.txt" || true

    echo "[+] Nuclei completed"

else
    echo "[!] Nuclei skipped"
fi

# ============================================================
# Final Summary
# ============================================================

echo
echo "============================================================"
echo " DOMAIN RECON COMPLETE"
echo "============================================================"
echo
echo "Target      : $TARGET"
echo "Workspace   : $BASE"
echo
echo "Subdomains  : $BASE/recon/subdomains/all.txt"
echo "DNS         : $BASE/recon/dns/resolved.txt"
echo "Live Hosts  : $BASE/recon/http/live.txt"
echo "URLs        : $BASE/recon/urls/all.txt"
echo "Interesting : $BASE/recon/urls/interesting.txt"
echo "Nuclei      : $BASE/nuclei/results.txt"
echo
echo "============================================================"
