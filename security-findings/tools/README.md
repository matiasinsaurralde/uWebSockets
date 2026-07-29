# `smuggle_probe` — a single-file request-smuggling deviation probe

A self-contained Go program that, **given a URL**, checks whether the target's HTTP/1.1 parser
exhibits the three deviations behind the uWebSockets request-smuggling class. Point it at your own
local servers (a uWebSockets/uWebSockets.js/hyper-express/Bun back-end, *or* the front door of your
proxy) to test more thoroughly.

```
go run smuggle_probe.go http://127.0.0.1:9001/
go run smuggle_probe.go -k https://127.0.0.1:8443/api      # -k: skip TLS verify (self-signed)
go run smuggle_probe.go -v http://host:port/path           # -v: dump raw requests/responses
```

No dependencies (stdlib only). Build a static binary with `go build -o smuggle_probe smuggle_probe.go`.

## What it checks

| Case | Deviation | Compliant server |
|------|-----------|------------------|
| **A** | an empty header name (a lone `:`) hides a following `Content-Length` | rejects (`400`) |
| **B** | duplicate `Content-Length` accepted, **first** value used | rejects (`400`, RFC 9112 §6.3) |
| **C** | chunk-size hex parser accepts `g`/`G`/`@` as digit 16 | rejects (`400`) |

It speaks **raw HTTP/1.1** over a socket (deliberately *not* `net/http`, which would normalize the
exact bytes we need to send).

- **A and B** open one keep-alive connection, send a request that a *safe* server frames as a single
  request, and **count the HTTP responses that come back**. If an extra ("smuggled") response
  appears — i.e. the trailing embedded request was parsed on its own — the boundary desynced and the
  deviation is present. (Counting walks `Content-Length`/chunked framing, so it isn't fooled by
  response bodies that end in a bare `\n`.)
- **C** sends a differential set of chunk sizes — valid `10`, the suspect `g`/`G`, and always-invalid
  `z` — on fresh connections and compares which are accepted vs rejected. `g`/`G` accepted *like* the
  valid `10` while `z` is rejected ⇒ the off-by-one is live.

## Choosing a target path

The URL's **path is used verbatim** in every probe request, and it matters:

- **A/B/C are HTTP-parser deviations that happen *before* routing**, so any path that reaches uWS and
  returns a normal HTTP response exercises them — a REST route, `/health`, even a 404 path (the C
  check treats any non-`400` response as "parsed & routed", so a 404 control is fine).
- **Pick a path your front-end forwards to the uWS back-end.** If different paths route to different
  backends, target one you know reaches uWS.
- **Do *not* target a WebSocket-only route** (`app.ws('/ws', …)`). These probes send `POST`/chunked
  HTTP requests, not WS `Upgrade` handshakes; a ws-only route may answer oddly or not at all (it waits
  for an upgrade), which can produce a **false negative** for A/B. Use a normal HTTP route. (The parser
  deviation still occurs — parsing precedes routing — but the response won't be cleanly countable.)
- Read the **`[identity]`** line the tool prints: a `uWebSockets` header ⇒ you're hitting uWS itself;
  a `Server: nginx/cloudflare/…` banner ⇒ a proxy/CDN is answering (and probably normalizing).

## Interpreting the result

- `VULNERABLE` — the back-end parser exhibits the deviation.
- `safe` / `safe/rejected` / `safe/hardened` — the input was rejected or normalized.
- `inconclusive` (C) — a control failed (server didn't accept valid chunked, or accepted the invalid
  `z`), so the `g` bug can't be isolated.

Exit code: **0** if nothing was flagged, **1** if any case is `VULNERABLE`, **2** on usage/connection
error — handy for scripting/CI.

## ⚠️ What a positive result means (and doesn't)

A positive result shows the **back-end parser is deviating** — the *necessary* condition for
smuggling. Turning it into **cross-user data theft** additionally requires a front-end that

1. **pools/reuses** back-end connections across clients, **and**
2. **forwards** these malformed requests **without normalizing** them.

That describes an **L4/TCP load balancer** (AWS NLB, HAProxy `mode tcp`, many k8s `LoadBalancer`
services) or a **lenient gateway** — **not** a compliant L7 proxy. So the honest test is to run the
probe **twice**: once against the back-end directly, once against your proxy's front door, and
compare.

## Validated behavior (this repo, 2026-07-28)

Direct back-end (uWebSockets core, uWebSockets.js v20.69.0, and hyper-express 7.0.2 all behave
identically — same parser):

```
[A] empty header name hides Content-Length ........ VULNERABLE   (crafted 1-request framing -> 3 responses)
[B] duplicate Content-Length, first wins .......... VULNERABLE   (used the FIRST Content-Length)
[C] chunk-size accepts 'g'/'G' as 16 (F1) ......... VULNERABLE   ('10'->200 'g'->200 'G'->200 'z'->400)
SUMMARY:  A=VULNERABLE   B=VULNERABLE   C=VULNERABLE
```

The **same back-end behind nginx 1.24** (with `upstream keepalive` — pooling *on*):

```
[A] empty header name hides Content-Length ........ safe/rejected   (nginx -> 400)
[B] duplicate Content-Length, first wins .......... safe/rejected   (nginx -> 400)
[C] chunk-size accepts 'g'/'G' as 16 (F1) ......... safe/hardened   ('g'/'G' -> 400)
SUMMARY:  A=safe/rejected   B=safe/rejected   C=safe/hardened
```

That contrast is the whole point: the parser deviations are real, but a compliant L7 proxy closes
them — the risk is deployments that pool connections **without** normalizing. See
[`../ECOSYSTEM-IMPACT.md`](../ECOSYSTEM-IMPACT.md) for the full analysis.

## Companion scripts in this directory

| Script | What it does |
|--------|--------------|
| `smuggle_probe.go` | the probe above — given an http/https URL, reports A/B/C |
| `smuggle_probe_tls.go` | HTTPS variant with **TLS diagnostics** (prints negotiated TLS version + ALPN, forces ALPN `http/1.1`, warns on `h2`). Use when a TLS endpoint reads "not vulnerable". `go run smuggle_probe_tls.go [-sni name] [-alpn http/1.1] [-verify] <https-url\|host:port>` |
| `validate_c_impact.py` | proves scenario **C** is a scoped connection desync, **not** a crash or server-wide DoS (case-C payload + aggressive over-read + post-attack liveness). `python3 validate_c_impact.py [host] [port]` |
| `nginx_mitigation_test.sh` | runs **real nginx** (with back-end pooling on) in front of the uWS back-end and drives A/B/C through it — shows a compliant L7 proxy blocks all three. `./nginx_mitigation_test.sh` |

## Testing over TLS / HTTPS

`smuggle_probe.go` already supports `https://` (with `-k`). If an HTTPS endpoint keeps reading
**"not vulnerable"**, it's almost always one of these — and `smuggle_probe_tls.go` prints the TLS
details that tell them apart:

1. **A TLS-terminating proxy that normalizes HTTP is in front of uWS** (nginx, HAProxy, a cloud
   load balancer, Cloudflare, an ingress). It rejects/normalizes the malformed requests at the edge,
   so `/steal` never reaches uWS — **genuinely not vulnerable through that front door.** This is the
   compliant-proxy mitigation, not a probe failure. To confirm uWS itself is affected, probe the
   **uWS back-end directly** (behind the proxy) or a `uWS::SSLApp`.
2. **The endpoint negotiated HTTP/2** (ALPN `h2`). An HTTP/1.1 probe can't express the smuggling
   framing over h2, so it reads safe. `smuggle_probe_tls.go` forces ALPN `http/1.1` and **warns
   loudly** if the server still selects `h2`.

**Verified:** against a **uWS.js `SSLApp`** (uWS terminating TLS itself, HTTP/1.1 over TLS),
`smuggle_probe_tls.go` reports `A=VULNERABLE B=VULNERABLE C=VULNERABLE` — the same as plaintext,
because the identical C++ `HttpParser` runs. Against an **nginx TLS-terminator** in front of the same
uWS, it reports `safe` on all three (`400` at the edge). Reproduce both with
[`../demo/uwebsockets-js/run_tls.sh`](../demo/uwebsockets-js/run_tls.sh).

The methodology, full results, and the disclosure/severity reasoning are written up in detail in
[`../TESTING-AND-ANALYSIS.md`](../TESTING-AND-ANALYSIS.md).
