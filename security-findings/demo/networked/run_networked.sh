#!/usr/bin/env bash
# Fully-networked HTTP request-smuggling demo against a REAL uWebSockets back-end.
#
# Topology (all real TCP):
#     attacker ─┐                         ┌─ vuln_proxy  (:8080, ONE pooled conn) ─┐
#               ├─► reverse proxy ────────┤                                        ├─► uWebSockets (:9001)
#     victim  ─┘                         └─ strict_proxy (:8081, validates)       ┘
#
# Usage:
#   ./run_networked.sh            # run all three exploit cases + the mitigation
#   ./run_networked.sh a|b|c      # run a single exploit case
#   ./run_networked.sh mitigate   # run only the strict-proxy mitigation
#
# Requires: g++ (C++17), go, and the uSockets submodule checked out.
set -u
cd "$(dirname "$0")"
ROOT=../../..
BE=127.0.0.1:9001
VP=127.0.0.1:8080
SP=127.0.0.1:8081

build() {
  echo "== building =="
  if ! ls "$ROOT"/uSockets/*.o >/dev/null 2>&1; then
    ( cd "$ROOT/uSockets" && cc -DLIBUS_NO_SSL -std=c11 -Isrc -O2 -c src/*.c src/eventing/*.c )
  fi
  g++ -std=c++17 -I"$ROOT/src" -I"$ROOT/uSockets/src" -O2 backend_uws.cpp "$ROOT"/uSockets/*.o -lz -pthread -o backend || exit 1
  for f in vuln_proxy strict_proxy attacker victim; do go build -o "$f" "$f.go" || exit 1; done
}

# start a fresh backend + fresh vuln_proxy (fresh pooled connection), echo their PIDs
start_vuln() {
  : > backend.log
  ./backend 2>backend.log & echo "$!" > .bpid
  sleep 0.6
  ./vuln_proxy "$BE" "$VP" >/dev/null 2>&1 & echo "$!" > .ppid
  sleep 0.5
}
stop() { kill "$(cat .ppid 2>/dev/null)" "$(cat .spid 2>/dev/null)" "$(cat .bpid 2>/dev/null)" 2>/dev/null; wait 2>/dev/null; rm -f .ppid .spid .bpid; }

exploit_case() {
  local K=$1
  start_vuln
  echo
  echo "════════════════ EXPLOIT CASE $K  (attacker → vuln_proxy → pooled uWS ← victim) ════════════════"
  ./attacker "$VP" "$K"
  sleep 0.2
  ./victim "$VP"
  echo "---- uWebSockets parsed (ground truth) ----"; cat backend.log
  stop
}

mitigation() {
  : > backend.log
  ./backend 2>backend.log & echo "$!" > .bpid
  sleep 0.6
  ./strict_proxy "http://$BE" "$SP" >/dev/null 2>&1 & echo "$!" > .spid
  sleep 0.6
  echo
  echo "════════════════ MITIGATION  (same attacks through the STRICT proxy :8081) ════════════════"
  for K in a b c; do echo "---- attacker case $K ----"; ./attacker "$SP" "$K" | sed -n '1,5p'; done
  echo "---- victim (legitimate) ----"; ./victim "$SP"
  echo "---- uWebSockets parsed (NO /steal, only the legit /account) ----"; cat backend.log
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
