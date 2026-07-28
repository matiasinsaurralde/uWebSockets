# Bun — HTTP request-smuggling PoC

End-to-end validation of the uWebSockets HTTP request-smuggling class against **Bun 1.3.14**.

Bun's `Bun.serve` HTTP server runs **uWebSockets' C++ `HttpParser`** under the hood: Bun vendors a
**fork** of uWebSockets in `packages/bun-uws/`, and every server request is parsed by it (verified
from source: `server.zig:539` → `uws_create_app` → `HttpContext::onData` → `HttpParser::getHeaders`;
Bun's `picohttp` parser is used only by the `fetch` *client*, never by `Bun.serve`). Because Bun's
vendored uWS is a **modified** fork, it does **not** inherit upstream's behavior uniformly:

- **Scenario A's** empty-header-name / empty-key sentinel is shipped **unchanged** from upstream
  uWebSockets `fe7c01a` (this repo's `src/` is byte-identical to `fe7c01a`), so **A reproduces** —
  the confirmed cross-user smuggle is caused by the upstream uWebSockets parser code path.
- **Scenarios B and C are actively hardened in Bun's fork** and do **not** smuggle (details below).

See [`CAUSAL-ATTRIBUTION.md`](./CAUSAL-ATTRIBUTION.md) for the exact vendored-source line citations.

## Result summary (Bun 1.3.14, reproduced here)

| Scenario | Result | Detail |
|----------|--------|--------|
| **A** empty header name hides `Content-Length` | ✅ **SMUGGLED** (uWS code path, live) | victim served the attacker's `/steal`, `cookie=victim-secret-cookie` captured — uWS sentinel bug, unchanged from `fe7c01a` |
| **B** duplicate `Content-Length` | ❌ **rejected** (`400`) — **Bun-hardened** | Bun's fork added an all-headers dup-CL scan that rejects differing values (not in upstream); end-to-end the `400`+close poisons the pooled conn → victim DoS |
| **C** chunked `g`=16 | ❌ **rejected** (`400`) — **Bun-hardened** | Bun's fork fixed the `>16` off-by-one, so `g`/`G` → `400`. The attacker's `200 /echo` is the handler replying on headers *before* the body; Bun then rejects the `g` chunk → pool poisoned → victim `400`/close (desync/DoS, **not** an F1 over-read) |

> Note: only **scenario A** is live in Bun 1.3.14 (build `0d9b296`). B and C are already hardened in
> Bun's vendored uWS fork as of 1.3.14 — a body-reading differential probe straight at `Bun.serve`
> shows dup-CL(differing) → `400` and `g`/`G` chunk sizes → `400` (while valid `10` → `200`, 16-byte
> body delivered). Bun's **later master** additionally rejects the empty header name, which is
> expected to close scenario A in a newer release. As of 1.3.14, A reproduces end-to-end.

## Prerequisites

- `bun` (this PoC used 1.3.14 — install: `curl -fsSL https://bun.sh/install | bash`)
- `go` (1.18+) and a POSIX shell.

## Run

```bash
./run.sh            # all scenarios + mitigation
./run.sh a          # scenario A (the positive one) …  (a|b|c|mitigate)
```

`run.sh` builds the Go harness, starts `bun backend_bun.js` on `:9001`, and for each scenario starts
a fresh vulnerable pooling proxy (`vuln_proxy`, `:8080`) and drives the `attacker` then `victim`
through it. Mitigation uses `strict_proxy` (`:8081`).

## Components

| File | Role |
|------|------|
| `backend_bun.js` | `Bun.serve` catch-all that reports the `method/url/cookie/x-smuggled` of every request it parses |
| `vuln_proxy.go` | lenient pooling reverse proxy (one reused Bun connection, verbatim forwarding) |
| `strict_proxy.go` | mitigating proxy (Go `net/http`) |
| `attacker.go` / `victim.go` | the two clients |

## Observed output (verbatim)

**Scenario A — SMUGGLED:**
```
[ATTACKER] response:  BACKEND-SAW method=POST url=/benign cookie= x-smuggled=
[VICTIM]   response:  BACKEND-SAW method=GET url=/steal cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1
[VICTIM] *** SMUGGLED *** -> the victim was served the attacker's /steal request,
         and the victim's own cookie was captured into it.
Bun back-end parsed:
  req#1 method=POST url=/benign  cookie= x-smuggled=
  req#2 method=GET  url=/steal   cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1
```

**Scenario B — rejected:** attacker gets `400 Bad Request` + `Connection: close`; nothing parsed.

**Scenario C — desync/DoS:** attacker gets `200 /echo`; victim gets `400 Bad Request` + close.

**Mitigation:** the strict proxy rejects A and B with `400` and re-normalizes C; the legitimate
victim gets its own `/account` response — no `/steal` reaches the back-end.

## A note on the harness

A pooling front-end readiness check must connect **without writing** any bytes — a stray newline
would be forwarded by the proxy and would poison Bun's pooled connection (Bun rejects the 1-byte
"request" and closes it), producing a *false* negative for scenario A. `run.sh`'s `wait_port` opens
the port read/write with no data. If you adapt this harness, keep that property. The parser-level
truth is also directly reproducible with a two-burst probe straight at `:9001` (attacker bytes, then
victim bytes, on one connection) — that is exactly what the pooled connection does.
