#!/usr/bin/env bash
# Fully-networked HTTP request-smuggling demo against a REAL hyper-express back-end
# (hyper-express -> uWebSockets.js v20.69.0, the Node binding of the uWebSockets core).
#
# Topology (all real TCP):
#     attacker ─┐                         ┌─ vuln_proxy  (:8080, ONE pooled conn) ─┐
#               ├─► reverse proxy ────────┤                                        ├─► hyper-express (:9001)
#     victim  ─┘                         └─ strict_proxy (:8081, validates)       ┘
#
# Usage:
#   ./run.sh              # run all three exploit cases + the mitigation
#   ./run.sh a|b|c        # run a single exploit case
#   ./run.sh mitigate     # run only the strict-proxy mitigation
#
# Requires: node (v22+), go, and `npm install` (done automatically below).
#
# SAFETY: every background process is tracked by PID in a .*pid file and killed
# by that exact PID in stop(). We NEVER `pkill -f <pattern>` — a pattern that
# matched this script's own command line would kill the shell running it.
set -u
cd "$(dirname "$0")"
BE=127.0.0.1:9001
VP=127.0.0.1:8080
SP=127.0.0.1:8081

build() {
  echo "== building =="
  # Node deps for the hyper-express back-end.
  if [ ! -d node_modules/hyper-express ]; then
    echo "-- npm install (hyper-express) --"
    npm install || exit 1
  fi
  # Go binaries for the two proxies + attacker + victim.
  for f in vuln_proxy strict_proxy attacker victim; do go build -o "$f" "$f.go" || exit 1; done
}

# start a fresh back-end + fresh vuln_proxy (fresh pooled connection), record PIDs
start_vuln() {
  : > backend.log
  node backend_hyperexpress.js 2>backend.log & echo "$!" > .bpid
  sleep 1.2
  ./vuln_proxy "$BE" "$VP" >/dev/null 2>&1 & echo "$!" > .ppid
  sleep 0.5
}

# Kill ONLY the exact PIDs we started (never pkill -f).
stop() {
  kill "$(cat .ppid 2>/dev/null)" "$(cat .spid 2>/dev/null)" "$(cat .bpid 2>/dev/null)" 2>/dev/null
  wait 2>/dev/null
  rm -f .ppid .spid .bpid
}

exploit_case() {
  local K=$1
  start_vuln
  echo
  echo "════════════════ EXPLOIT CASE $K  (attacker → vuln_proxy → pooled hyper-express ← victim) ════════════════"
  ./attacker "$VP" "$K"
  sleep 0.2
  ./victim "$VP"
  echo "---- hyper-express parsed (ground truth) ----"; cat backend.log
  stop
}

mitigation() {
  : > backend.log
  node backend_hyperexpress.js 2>backend.log & echo "$!" > .bpid
  sleep 1.2
  ./strict_proxy "http://$BE" "$SP" >/dev/null 2>&1 & echo "$!" > .spid
  sleep 0.6
  echo
  echo "════════════════ MITIGATION  (same attacks through the STRICT proxy :8081) ════════════════"
  for K in a b c; do echo "---- attacker case $K ----"; ./attacker "$SP" "$K" | sed -n '1,5p'; done
  echo "---- victim (legitimate) ----"; ./victim "$SP"
  echo "---- hyper-express parsed (NO /steal, only the legit /account) ----"; cat backend.log
  stop
}

# Always clean up background procs on exit/interrupt (by tracked PID only).
trap 'stop' EXIT INT TERM

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
