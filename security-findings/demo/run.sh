#!/usr/bin/env bash
# Build and run the request-smuggling demo against a REAL uWebSockets back-end.
#
# Components:
#   backend_uws.cpp  - real uWebSockets HTTP server that reports what it parsed
#   demo.go          - vulnerable pooling reverse proxy + attacker + victim (the exploit)
#   mitigation.go    - a strict front-end (Go net/http) rejecting the same payloads
#   probe.go         - optional: raw two-burst probe straight at the back-end
#
# Requires: g++ (C++17), go, and the uSockets submodule checked out.
set -u
cd "$(dirname "$0")"
ROOT=../..

echo "== building uSockets (if needed) =="
if ! ls "$ROOT"/uSockets/*.o >/dev/null 2>&1; then
  ( cd "$ROOT/uSockets" && cc -DLIBUS_NO_SSL -std=c11 -Isrc -O2 -c src/*.c src/eventing/*.c )
fi

echo "== building uWebSockets back-end =="
g++ -std=c++17 -I"$ROOT/src" -I"$ROOT/uSockets/src" -O2 backend_uws.cpp "$ROOT"/uSockets/*.o -lz -pthread -o backend || exit 1

echo "== building Go components =="
go build -o demo demo.go || exit 1
go build -o mitigation mitigation.go || exit 1

echo "== starting back-end on :9001 =="
: > backend.log
./backend 2>backend.log &
BPID=$!
sleep 0.8

echo
echo "################## EXPLOIT: vulnerable pooling proxy + real uWebSockets ##################"
timeout 15 ./demo

echo
echo "################## MITIGATION: a strict front-end rejects the same payloads ##################"
./mitigation

echo
echo "################## uWebSockets back-end log (ground truth: what uWS parsed) ##################"
cat backend.log

kill "$BPID" 2>/dev/null
wait 2>/dev/null
exit 0
