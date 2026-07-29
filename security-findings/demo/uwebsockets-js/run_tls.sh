#!/usr/bin/env bash
# run_tls.sh — the A/B/C smuggling deviations ARE reachable over HTTPS when uWS
# terminates TLS itself (uWS::SSLApp). This generates a self-signed cert, starts
# a uWebSockets.js SSLApp back-end on :9443, and runs smuggle_probe_tls against it.
#
# Expect: A/B/C = VULNERABLE, TLS 1.3, ALPN "" (uWS.js speaks HTTP/1.1 over TLS).
#
# If instead you probe a TLS endpoint fronted by a NORMALIZING proxy (nginx,
# HAProxy, a cloud LB, Cloudflare), you'll see 'safe' — that is the mitigation
# working; you're probing the terminator, not uWS. See ../../tools/README.md
# ("Testing over TLS/HTTPS") and ../../TESTING-AND-ANALYSIS.md § 3.1.
#
# Prereqs: node (v22+), go, openssl, and `npm install` (done automatically).
set -u
cd "$(dirname "$0")"
TOOLS="../../tools"

echo "== setup =="
mkdir -p tls
if [ ! -f tls/cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout tls/key.pem -out tls/cert.pem -days 365 -nodes -subj "/CN=localhost" >/dev/null 2>&1 \
    && echo "  generated self-signed tls/cert.pem" || { echo "  openssl failed"; exit 1; }
fi
[ -d node_modules/uWebSockets.js ] || { echo "  npm install…"; npm install || exit 1; }
go build -o /tmp/smuggle_probe_tls "$TOOLS/smuggle_probe_tls.go" || { echo "  probe build failed"; exit 1; }

node backend_uwsjs_tls.js 2>/tmp/betls.log & BP=$!
trap 'kill "$BP" 2>/dev/null; wait 2>/dev/null' EXIT INT TERM
sleep 1.5
head -1 /tmp/betls.log

echo
echo "════════ smuggle_probe_tls  ->  uWebSockets.js SSLApp (TLS terminated by uWS itself) ════════"
/tmp/smuggle_probe_tls https://127.0.0.1:9443/
echo
echo "[tls PoC done]  — expect A=VULNERABLE B=VULNERABLE C=VULNERABLE"
