# Bun — HTTP request-smuggling PoC

End-to-end validation of the uWebSockets HTTP request-smuggling class against **Bun 1.3.14**.

Bun's `Bun.serve` HTTP server runs **uWebSockets' C++ `HttpParser`** under the hood (Bun vendors
uWebSockets in `packages/bun-uws` and `Bun.serve` calls `uWS::App::create`), so it inherits
upstream uWebSockets' HTTP-parsing behavior. This repo's `src/` was verified **byte-identical** to
upstream uWebSockets `fe7c01a`, so the bugs here are real upstream uWebSockets bugs, not a fork.

## Result summary (Bun 1.3.14, reproduced here)

| Scenario | Result | Detail |
|----------|--------|--------|
| **A** empty header name hides `Content-Length` | ✅ **SMUGGLED** | victim served the attacker's `/steal`, `cookie=victim-secret-cookie` captured |
| **B** duplicate `Content-Length` | ❌ **rejected** (`400`) | Bun 1.3.14 *does* reject duplicate CL — partial hardening |
| **C** chunked `g`=16 | ⚠️ **desync/DoS** | attacker `200 /echo`, victim `400` + connection closed |

> Note: Bun's **latest master** (`d549845`) further hardens its vendored uWS parser — it also rejects
> empty header names and `g` chunk sizes — so scenario A is expected to be fixed in newer Bun. As of
> 1.3.14, A reproduces.

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
