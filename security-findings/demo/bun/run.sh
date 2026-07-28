#!/usr/bin/env bash
# End-to-end request-smuggling test against a Bun (Bun.serve) back-end.
# Bun's HTTP server runs uWebSockets' C++ HttpParser under the hood, so it
# inherits upstream uWebSockets' HTTP-parsing behavior.
#
# Usage: ./run.sh [a|b|c|mitigate]   (default: all)
# Requires: bun, go, and the four Go files in this dir.
set -u
cd "$(dirname "$0")"
VP=127.0.0.1:8080
SP=127.0.0.1:8081
BE=127.0.0.1:9001

build() { for f in vuln_proxy strict_proxy attacker victim; do go build -o "$f" "$f.go" || exit 1; done; }

# connect-only readiness check: opens the TCP port WITHOUT writing any bytes
# (writing a newline here would be forwarded by the proxy and poison the pooled conn).
wait_port() { for i in $(seq 1 60); do (exec 3<>"/dev/tcp/${1%:*}/${1##*:}") 2>/dev/null && return 0; sleep 0.2; done; return 1; }

start_be()  { : > backend.log; bun backend_bun.js 2>backend.log & echo "$!" > .bpid; wait_port "$BE"; }
start_vp()  { ./vuln_proxy "$BE" "$VP" >/dev/null 2>&1 & echo "$!" > .ppid; wait_port "$VP"; }
start_sp()  { ./strict_proxy "http://$BE" "$SP" >/dev/null 2>&1 & echo "$!" > .spid; wait_port "$SP"; }
stop() { kill "$(cat .ppid 2>/dev/null)" "$(cat .spid 2>/dev/null)" "$(cat .bpid 2>/dev/null)" 2>/dev/null; wait 2>/dev/null; rm -f .ppid .spid .bpid; }

exploit() {
  local K=$1; start_be; start_vp
  echo; echo "════════ Bun EXPLOIT CASE $K (attacker -> vuln_proxy -> pooled Bun <- victim) ════════"
  ./attacker "$VP" "$K"; sleep 0.2; ./victim "$VP"
  echo "---- Bun back-end parsed ----"; cat backend.log
  stop
}
mitigation() {
  start_be; start_sp
  echo; echo "════════ Bun MITIGATION (same attacks through the STRICT proxy :8081) ════════"
  for K in a b c; do echo "---- attacker case $K ----"; ./attacker "$SP" "$K" | sed -n '1,5p'; done
  echo "---- victim (legit) ----"; ./victim "$SP"
  echo "---- back-end parsed ----"; cat backend.log
  stop
}

build
case "${1:-all}" in
  a|b|c) exploit "$1" ;;
  mitigate) mitigation ;;
  all) exploit a; exploit b; exploit c; mitigation ;;
  *) echo "usage: $0 [a|b|c|mitigate]"; exit 2 ;;
esac
echo; echo "[done]"; exit 0
