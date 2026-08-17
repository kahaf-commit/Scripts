#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Bug Bounty Program Workspace & Recon Script
# Usage:
#   ./new-program.sh example.com
#
# Example:
#   ./new-program.sh varonis.com
# ============================================================

PROGRAM="${1:-}"

if [[ -z "$PROGRAM" ]]; then
    echo "Usage: $0 <target-domain>"
    echo "Example: $0 example.com"
    exit 1
fi

# Basic domain validation
if [[ ! "$PROGRAM" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
    echo "[!] Invalid domain: $PROGRAM"
    exit 1
fi

# Remove trailing dot if supplied
PROGRAM="${PROGRAM%.}"

BASE="$HOME/bugbounty/$PROGRAM"

echo
echo "[*] Starting bug bounty workspace: $PROGRAM"
echo "[*] Base directory: $BASE"
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

echo "[+] Directory structure created"

# ============================================================
# Metadata
# ============================================================

cat > "$BASE/README.md" <<EOF
# Bug Bounty Workspace - $PROGRAM

Created: $(date)

## Target

$PROGRAM

## Scope

Only test assets explicitly authorized by the bug bounty program.

## Recon

- Subdomains
- DNS
- HTTP services
- URLs
- Screenshots
- Ports

## Vulnerabilities

Document confirmed findings here.

## Notes

Keep useful observations and manual testing notes here.
EOF

cat > "$BASE/notes/scope.txt" <<EOF
============================================================
TARGET SCOPE
============================================================

Program:
$PROGRAM

IMPORTANT:
Review the official bug bounty program scope before testing.

In-scope:
- Add authorized domains here
- Add authorized subdomains here
- Add authorized IP ranges here

Out-of-scope:
- Add excluded assets here
- Add third-party infrastructure here

============================================================
EOF

# ============================================================
# Tool Check
# ============================================================

TOOLS=(
    "curl"
    "dig"
)

echo
echo "[*] Checking basic dependencies..."

for TOOL in "${TOOLS[@]}"; do
    if command -v "$TOOL" >/dev/null 2>&1; then
        echo "[+] $TOOL"
    else
        echo "[!] Missing: $TOOL"
    fi
done

# ============================================================
# Subdomain Enumeration
# ============================================================

echo
echo "[*] Starting passive subdomain enumeration..."

if command -v subfinder >/dev/null 2>&1; then

    subfinder \
        -d "$PROGRAM" \
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

curl -s \
    "https://crt.sh/?q=%25.${PROGRAM}&output=json" \
    2>/dev/null |
    grep -oE '"name_value":"[^"]+"' |
    sed 's/"name_value":"//g' |
    sed 's/"//g' |
    tr '\\n' '\n' |
    sed 's/\*\.//g' |
    sort -u \
    > "$BASE/recon/subdomains/crtsh.txt" || true

echo "[+] Certificate data saved"

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
echo "[*] Resolving discovered domains..."

while IFS= read -r SUBDOMAIN; do

    [[ -z "$SUBDOMAIN" ]] && continue

    IP=$(dig +short "$SUBDOMAIN" A 2>/dev/null | head -n 1 || true)

    if [[ -n "$IP" ]]; then
        printf "%-50s %s\n" "$SUBDOMAIN" "$IP"
    fi

done < "$BASE/recon/subdomains/all.txt" \
    > "$BASE/recon/dns/resolved.txt"

echo "[+] DNS resolution completed"

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

    # Extract only live URLs
    awk '{print $1}' "$BASE/recon/http/httpx.txt" |
        sort -u \
        > "$BASE/recon/http/live.txt"

    echo "[+] Live hosts: $(wc -l < "$BASE/recon/http/live.txt")"

else
    echo "[!] httpx not installed - skipping HTTP enumeration"
fi

# ============================================================
# Passive URL Discovery
# ============================================================

echo
echo "[*] Collecting historical URLs..."

if command -v gau >/dev/null 2>&1; then

    gau \
        --subs \
        "$PROGRAM" \
        2>/dev/null |
        sort -u \
        > "$BASE/recon/urls/gau.txt" || true

    echo "[+] GAU completed"

else
    echo "[!] gau not installed - skipping"
fi

# ============================================================
# Wayback URLs
# ============================================================

if command -v waybackurls >/dev/null 2>&1; then

    echo "[*] Collecting Wayback URLs..."

    printf '%s\n' "$PROGRAM" |
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
# Interesting URLs
# ============================================================

echo
echo "[*] Extracting potentially interesting endpoints..."

grep -Ei \
    '(\?|=|api|admin|login|auth|oauth|token|upload|redirect|callback|debug|graphql|swagger)' \
    "$BASE/recon/urls/all.txt" \
    2>/dev/null |
    sort -u \
    > "$BASE/recon/urls/interesting.txt" || true

echo "[+] Interesting URLs saved"

# ============================================================
# Nuclei - Rate Limited
# ============================================================

if command -v nuclei >/dev/null 2>&1 &&
   [[ -s "$BASE/recon/http/live.txt" ]]; then

    echo
    echo "[*] Running rate-limited Nuclei scan..."
    echo "[*] Only scan assets confirmed to be in scope."

    nuclei \
        -l "$BASE/recon/http/live.txt" \
        -severity info,low,medium,high,critical \
        -rate-limit 10 \
        -concurrency 5 \
        -o "$BASE/nuclei/results.txt" || true

    echo "[+] Nuclei scan completed"

else
    echo
    echo "[!] Nuclei skipped"
fi

# ============================================================
# Summary
# ============================================================

echo
echo "============================================================"
echo " BUG BOUNTY RECON COMPLETE"
echo "============================================================"
echo
echo "Program      : $PROGRAM"
echo "Workspace    : $BASE"
echo
echo "Subdomains   : $BASE/recon/subdomains/all.txt"
echo "DNS Results  : $BASE/recon/dns/resolved.txt"
echo "Live Hosts   : $BASE/recon/http/live.txt"
echo "All URLs     : $BASE/recon/urls/all.txt"
echo "Interesting  : $BASE/recon/urls/interesting.txt"
echo "Nuclei       : $BASE/nuclei/results.txt"
echo
echo "============================================================"
echo "[+] Happy hunting — stay within program scope."
echo "============================================================"
