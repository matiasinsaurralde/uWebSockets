#!/usr/bin/env bash
# nginx_mitigation_test.sh — does a modern L7 reverse proxy (nginx) close the
# A/B/C request-smuggling class, even with back-end connection pooling ON?
#
# It puts real nginx in front of the uWebSockets C++ back-end with `upstream
# keepalive` (so back-end connections ARE pooled/reused across clients — the
# precondition that makes cross-user theft possible), then drives the A/B/C
# attacker plus a victim through it. A compliant L7 proxy rejects the malformed
# requests at the edge (400) and re-serializes the rest, so /steal never reaches
# uWS and the victim gets its own response.
#
# Contrast: security-findings/demo/networked/ runs the SAME attacker/victim
# through a LENIENT byte-forwarding proxy (vuln_proxy) and DOES smuggle.
#
# Prereqs: nginx, go, g++ (C++17), and the uSockets submodule checked out.
# Usage:   ./nginx_mitigation_test.sh
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"     # repo root
NET="$ROOT/security-findings/demo/networked"
W="$(mktemp -d)"
cleanup() { kill "$(cat "$W/.n" 2>/dev/null)" "$(cat "$W/.b" 2>/dev/null)" 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT INT TERM

echo "== building uWS back-end + go clients =="
if ! ls "$ROOT"/uSockets/*.o >/dev/null 2>&1; then
  ( cd "$ROOT/uSockets" && cc -DLIBUS_NO_SSL -std=c11 -Isrc -O2 -c src/*.c src/eventing/*.c ) || exit 1
fi
g++ -std=c++17 -I"$ROOT/src" -I"$ROOT/uSockets/src" -O2 \
    "$NET/backend_uws.cpp" "$ROOT"/uSockets/*.o -lz -pthread -o "$W/backend_uws" || exit 1
( cd "$NET" && go build -o "$W/attacker" attacker.go && go build -o "$W/victim" victim.go ) || exit 1

# nginx: pools upstream connections (keepalive) across clients, re-serializes each request.
cat > "$W/nginx.conf" <<CONF
worker_processes 1;
daemon off;
pid $W/nginx.pid;
error_log $W/error.log warn;
events { worker_connections 64; }
http {
    access_log $W/access.log;
    upstream be { server 127.0.0.1:9001; keepalive 16; }   # reuse back-end conns across clients
    server {
        listen 127.0.0.1:8082;
        location / { proxy_pass http://be; proxy_http_version 1.1; proxy_set_header Connection ""; }
    }
}
CONF
nginx -t -c "$W/nginx.conf" 2>&1 | sed 's/^/  /' || exit 1

start() { "$W/backend_uws" >/dev/null 2>"$W/be.log" & echo $! >"$W/.b"
          nginx -c "$W/nginx.conf" 2>"$W/nginx.err" & echo $! >"$W/.n"; sleep 1.2; }
stop()  { kill "$(cat "$W/.n" 2>/dev/null)" "$(cat "$W/.b" 2>/dev/null)" 2>/dev/null; wait 2>/dev/null; sleep 0.4; }

for K in a b c; do
  start
  echo; echo "════════ nginx (pooling) CASE $K ════════"
  echo "-- attacker -> nginx :8082 --"; "$W/attacker" 127.0.0.1:8082 "$K" | sed -n '1,6p'
  sleep 0.3
  echo "-- victim  -> nginx :8082 --"; "$W/victim" 127.0.0.1:8082 | sed -n '1,14p'
  if grep -q "url=/steal" "$W/be.log"; then
    echo ">> RESULT: /steal REACHED uWS — SMUGGLE NOT BLOCKED"
  else
    echo ">> RESULT: /steal never reached uWS — blocked at the proxy"
  fi
  stop
done
echo; echo "[nginx mitigation test done]"
