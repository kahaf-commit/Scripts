#!/usr/bin/env bash

set -uo pipefail

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 example.com"
    exit 1
fi

BASE="$HOME/bugbounty/$TARGET/recon/subdomains"
mkdir -p "$BASE"

ALL="$BASE/all.txt"
LIVE="$BASE/live.txt"
HTTPX="$BASE/httpx.txt"

echo "[+] Target: $TARGET"
echo "[+] Running subdomain enumeration..."

subfinder -d "$TARGET" -silent | sort -u > "$ALL"

echo "[+] Found $(wc -l < "$ALL") unique subdomains"
echo "[+] Probing HTTP/HTTPS services..."

httpx -l "$ALL" \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -o "$HTTPX"

awk '
{
    url=$1
    status=""

    for(i=1;i<=NF;i++) {
        if($i ~ /^\[[0-9]{3}\]$/) {
            status=$i
            gsub(/[\[\]]/, "", status)
        }
    }

    if(status ~ /^[0-9]{3}$/) {
        print status " " url
    }
}
' "$HTTPX" > "$LIVE"

echo
echo "Final status breakdown:"
echo
printf "%-15s %-8s %s\n" "Final Status" "Count" "Notes"
printf "%-15s %-8s %s\n" "------------" "-----" "-----"

for code in 200 301 302 307 308 401 403 404 500 502 503; do
    count=$(awk -v c="$code" '$1 == c {n++} END {print n+0}' "$LIVE")

    case "$code" in
        200) note="Live, fully resolved" ;;
        301|302|307|308) note="Redirect" ;;
        401) note="Authentication required" ;;
        403) note="Reachable but blocked" ;;
        404) note="Dead route / not found" ;;
        500) note="Server error" ;;
        502) note="Bad gateway" ;;
        503) note="Service unavailable" ;;
    esac

    [[ "$count" -gt 0 ]] &&
        printf "%-15s %-8s %s\n" "$code" "$count" "$note"
done

echo
echo "Saved to: $LIVE"
echo
echo "----------------------------------------"
echo
echo "Hosts worth noting:"

awk '
$1 == "200" {
    print "- " $2 " — 200 — Live host; review application and functionality."
}
$1 == "401" {
    print "- " $2 " — 401 — Authentication endpoint; review auth controls."
}
$1 == "403" {
    print "- " $2 " — 403 — Reachable but blocked; potentially interesting."
}
' "$LIVE"

echo
echo "[+] Total live/reachable hosts: $(wc -l < "$LIVE")"
echo "[+] Results directory: $BASE"
