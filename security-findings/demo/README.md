# Request-smuggling PoCs against a real uWebSockets back-end

This directory contains runnable, end-to-end proofs of concept for the HTTP request-smuggling
class documented in [`../FINDINGS.md`](../FINDINGS.md). Everything runs against a **real,
unmodified uWebSockets server** compiled from this repo's `src/` (`backend_uws.cpp`).

## What's here

| Path | What it is | When to use |
|------|-----------|-------------|
| [`networked/`](networked/) | **Full TCP** PoC: real reverse proxy with its own listener, two client processes, three attack scenarios (A/B/C) + a strict-proxy mitigation. | The main PoC — run this. |
| `demo.go`, `mitigation.go`, `probe.go`, `run.sh` | **In-process** version of the same exploit (proxy modeled as an in-process forwarder). Kept because it runs even where a second TCP listener is blocked. | Constrained environments. |
| [`../poc/`](../poc/) | **Parser-level** PoCs that drive the real headers directly and prove the two surgical plants (`verify_f1_chunked_smuggling.cpp`, `verify_f3_ws_frame_injection.cpp`). | Prove the bugs themselves. |

## Quick start (full TCP PoC)

```bash
cd networked
./run_networked.sh          # all 3 scenarios + mitigation
./run_networked.sh a        # scenario A only … (a|b|c|mitigate)
```

See [`networked/README.md`](networked/README.md) for the topology, per-scenario byte-level
walkthroughs, expected output, and manual `nc` recipes.

## The three scenarios at a glance

| Scenario | Deviation | uWS reads | Outcome (victim) |
|----------|-----------|-----------|------------------|
| **A** | empty header name `:` hides `Content-Length` | body = 0 | served the attacker's `/steal`, **cookie captured** |
| **B** | duplicate `Content-Length` (uWS uses first=6) | 6 body bytes | served the attacker's `/steal`, **cookie captured** |
| **C** | F1 chunked `g`=16 (`ChunkedEncoding.h:57`) | **over-reads** the chunk | desync → `505` + pooled-conn poisoning → **DoS/denied** |

A and B are clean cross-user theft; C is the request-smuggling-class denial of service (F1
over-reads, so it poisons the shared connection rather than cleanly stealing — the honest outcome
for that bug; the `g`=16 deviation itself is proven directly in `../poc/verify_f1_chunked_smuggling.cpp`).

## In-process version

```bash
./run.sh    # builds backend + demo.go + mitigation.go, runs the exploit and the mitigation
```

## What "the back-end reports" means

`backend_uws.cpp` runs a catch-all uWS route that, for **every request it parses**, logs and
echoes `method / url / cookie / x-smuggled`. So when the victim receives
`... url=/steal cookie="victim-secret-cookie" x-smuggled="GET /account HTTP/1.1"`, that is the
real uWebSockets server telling you it parsed the attacker's smuggled request with the victim's
credentials folded in.

## Mitigation, in one line

A strict front-end (here Go `net/http`) rejects A and B with `400` and re-normalizes C, so no
parser disagreement reaches the back-end — the proper fixes are (1) make uWebSockets parse
strictly (reject these inputs), and/or (2) don't pool back-end connections across users.
