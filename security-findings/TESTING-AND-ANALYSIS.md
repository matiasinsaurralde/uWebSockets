# Testing & analysis — impact validation, proxy mitigation, tooling, and disclosure reasoning

Companion to [`FINDINGS.md`](./FINDINGS.md) (the vulnerabilities) and
[`ECOSYSTEM-IMPACT.md`](./ECOSYSTEM-IMPACT.md) (reach + root-cause attribution). This document records,
in detail, the **follow-up validation** performed after the initial findings, and the **disclosure /
severity reasoning** that came out of it. Everything below was reproduced firsthand on this machine
(2026-07-28) with the scripts in [`tools/`](./tools/).

The three HTTP request-smuggling deviations under discussion throughout:

| | deviation | a compliant parser… |
|---|---|---|
| **A** | an empty header name (a lone `:`) hides a following `Content-Length` | rejects (`400`) |
| **B** | duplicate `Content-Length` accepted, **first** value used | rejects (`400`, RFC 9112 §6.3) |
| **C** | chunk-size hex parser accepts `g`/`G`/`@` as digit 16 (`ChunkedEncoding.h:57` `>16` vs `>15`) | rejects (`400`) |

---

## 0. Scope — this is HTTP, not WebSocket

uWebSockets is an **HTTP *and* WebSocket** library; uWebSockets.js, hyper-express and Bun.serve are
built on it. A/B/C are defects in the **HTTP/1.1 request parser** (`HttpParser.h`,
`ChunkedEncoding.h`) — they are **not** WebSocket-protocol bugs. A WebSocket connection merely
*begins* as an HTTP `GET … Upgrade: websocket` handshake and then switches to frame protocol; the
smuggling vectors here use `POST` bodies, chunked encoding and `Content-Length`, which are HTTP
request features. So:

- "these servers are WebSocket servers" is only half true — they are **HTTP servers that also speak
  WebSocket**, and this class is on the HTTP side (an app's REST/JSON routes, the WS *handshake*
  endpoint, health checks, etc.).
- A separate finding, **F3** (`WebSocketProtocol.h:361`), covers a WebSocket *frame* issue and is
  documented in `FINDINGS.md`; it is unrelated to A/B/C.

**Applicability note (LLM/API infra).** The dominant transport for text LLM APIs is **HTTP + SSE**
(server-sent events) — standard chat/completion endpoints stream over HTTP POST, not
WebSockets. WebSockets appear mainly in the **realtime/voice** niche (e.g. OpenAI's Realtime API,
streaming speech-to-text). We have **no evidence** that any specific LLM provider runs
uWebSockets/Bun in its serving path and make no such claim. The point is only that *if* a service
puts a uWS-family HTTP server behind a non-normalizing/L4 front-end, the A/B/C exposure applies to
its HTTP request handling regardless of whether it also serves WebSockets.

---

## 1. Does C (chunked `g`=16) cause a real DoS or crash?

**Question.** F1's over-read is often loosely labelled "DoS." Does it crash the process, or take the
server down for everyone — or is it something narrower?

**Method** — [`tools/validate_c_impact.py`](./tools/validate_c_impact.py), sent straight at each
back-end (no proxy):
- **T1** — the exact case-C payload (`Transfer-Encoding: chunked`, size line `1g`).
- **T3** — an aggressive over-read: declare a 32-byte chunk (`1g`) but send only 4 bytes, then EOF.
- **T2** — 8 normal requests *after* the attack, to see whether the server still serves.
- plus a process-liveness check (`kill -0` on the server PID).

**Results (firsthand):**

| Target | T1 direct case-C | T3 over-read + EOF | T2 fresh reqs after | process |
|---|---|---|---|---|
| uWebSockets core | `505` | connection aborted, no response | **8 / 8 served** | **ALIVE** |
| uWebSockets.js | `200` | `200` | **8 / 8 served** | **ALIVE** |
| hyper-express | `200` | connection aborted, no response | **8 / 8 served** | **ALIVE** |

> The **T1 status** (`200` vs `505`) is framing-dependent and varies between runs — it is **not** the
> signal here. The load-bearing columns are **T2** (fresh requests served after the attack) and
> **process** (liveness); both were unaffected on every target.

**Findings.**
- **No crash** on any target — all survived both the case-C payload and the aggressive over-read+EOF.
- **No server-wide DoS** — every server kept serving fresh connections (8/8) immediately after.
- **Not a memory-safety bug.** The over-read is *logical* stream mis-framing **bounded by uSockets'
  padded recv buffer** — not an out-of-bounds read. When the declared chunk bytes aren't present the
  streaming parser waits for more or **aborts cleanly on EOF** (T3: no response, no segfault).
- **Real, but scoped.** C corrupts request framing on **the single connection** carrying the bad
  chunk. Behind a *pooling* front-end that reuses one back-end connection across users, that poisoned
  connection returns `505`/close (or a mismatched response) to the co-tenant victim(s) sharing it — a
  request-smuggling-class **denial / response-mismatch against pooled co-tenants**, not a process
  kill. (A and B are the higher-severity findings: clean cross-user cookie theft.)

**Reproduce.**
```bash
# start a back-end on :9001 (any of the demo backends), then:
python3 security-findings/tools/validate_c_impact.py 127.0.0.1 9001
# and separately confirm the server PID is still alive (kill -0 <pid>).
```

---

## 2. Does a modern reverse proxy (nginx) mitigate the class?

**Question.** uWebSockets' documented posture is "sit behind a spec-compliant front-end." Does a real
modern proxy actually close A/B/C — even when it *pools* back-end connections (the theft precondition)?

**Method** — [`tools/nginx_mitigation_test.sh`](./tools/nginx_mitigation_test.sh): real **nginx 1.24**
in front of the uWS back-end, `upstream … { keepalive 16; }` so back-end connections **are** pooled
across clients; drive the A/B/C attacker + a victim through it.

**Results (firsthand):**

| Case | attacker → nginx | `/steal` reached uWS? | victim |
|---|---|---|---|
| **A** empty-header | **`400`** | **no** | clean `/account` |
| **B** dup-CL | **`400`** | **no** | clean `/account` |
| **C** chunk `g` | **`400`** | **no** | clean `/account` |

nginx rejected all three at the edge; the uWS back-end only ever parsed the victim's legitimate
request. **The pooling precondition was satisfied, yet nothing smuggled** — because nginx eliminates
the *other* precondition (parser disagreement) by rejecting malformed requests and re-serializing the
rest from its own parse.

**Analysis — where you are and aren't protected.**
- **Compliant L7 proxies close it.** nginx (validated) and envoy (strict by design) reject A/B/C and
  re-serialize, so the parser disagreement never reaches uWS. This is exactly uWS's "front-end's job"
  argument, and it holds *for that class of front-end*.
- **L4 / TCP load balancers do NOT.** AWS NLB, HAProxy `mode tcp`, many k8s `LoadBalancer` services,
  and other pass-through balancers do **no** HTTP parsing — they pool and forward bytes verbatim, so a
  uWS back-end behind them is fully exposed.
- **Lenient/misconfigured gateways** vary; some forward more permissively than nginx/envoy.
- **A backend that is strict on these three is still safer** than one that isn't: desync research keeps
  finding *new* discrepancies, and a lenient backend re-opens the door on each one.

**Contrast.** The same attacker/victim through the **lenient** byte-forwarding proxy in
[`demo/networked/`](./demo/networked/) (`vuln_proxy`, models an L4/pass-through front-end) **does**
smuggle A/B (cross-user cookie theft) and desyncs C.

**Reproduce.**
```bash
./security-findings/tools/nginx_mitigation_test.sh          # nginx in front -> all blocked
( cd security-findings/demo/networked && ./run_networked.sh )   # lenient proxy -> A/B smuggle, C desync
```

---

## 3. `smuggle_probe` — test any deployment yourself

[`tools/smuggle_probe.go`](./tools/smuggle_probe.go) is a single-file, dependency-free Go program:
give it a URL, it reports A/B/C for that server. Point it at your **back-end directly** and at your
**proxy's front door** and compare — that delta is your actual risk. Full docs in
[`tools/README.md`](./tools/README.md).

```bash
go run security-findings/tools/smuggle_probe.go http://127.0.0.1:9001/     # back-end -> expect VULNERABLE
go run security-findings/tools/smuggle_probe.go http://127.0.0.1:8080/     # compliant L7 front -> safe
```

**How it detects each** (speaks **raw HTTP/1.1**, not `net/http`, so the malformed bytes survive):
- **A & B** — one keep-alive connection; sends a request a *safe* server frames as one, then **counts
  the HTTP responses**. An extra ("smuggled") response ⇒ the boundary desynced. Counting walks
  `Content-Length`/chunked framing (a bug fixed during development: a response body ending in a bare
  `\n` glued onto the next status line and under-counted — naive line-splitting is wrong here).
- **C** — a `g`/`G`/`10`/`z` chunk-size differential: `g`/`G` accepted *like* the valid `10` while `z`
  is rejected ⇒ the off-by-one is live.

Exit code: `0` clean, `1` if any case is `VULNERABLE`, `2` on error (scriptable).

**Self-validation (firsthand).** Direct back-ends (no proxy), each on `:9001`:

| Back-end (direct) | A | B | C | exit |
|---|---|---|---|---|
| uWebSockets core (C++, this repo `src/`) | VULNERABLE | VULNERABLE | VULNERABLE | 1 |
| uWebSockets.js v20.69.0 | VULNERABLE | VULNERABLE | VULNERABLE | 1 |
| hyper-express 7.0.2 → uWS.js 20.69.0 | VULNERABLE | VULNERABLE | VULNERABLE | 1 |

Evidence lines were byte-for-byte identical across all three (they run the same `fe7c01a` parser):
`A` → crafted 1-request framing returned **3 responses**; `B` → **3 responses**, first `Content-Length`
used; `C` → `'10'→200, 'g'→200, 'G'→200, 'z'→400`. The **same back-ends behind nginx** flip to
`A=safe/rejected  B=safe/rejected  C=safe/hardened`. **Bun 1.3.14** (which patched B and C in its uWS
fork) returns `A=VULNERABLE` only.

**⚠️ What a positive result means.** It proves the **back-end parser deviates** — the *necessary*
condition. Cross-user theft *additionally* needs a front-end that (a) **pools** back-end connections
across clients and (b) **forwards without normalizing** — an L4 LB or lenient gateway, not nginx/envoy.

### 3.1 Testing over TLS / HTTPS

`smuggle_probe.go` already speaks `https://` (via `-k`). [`tools/smuggle_probe_tls.go`](./tools/smuggle_probe_tls.go)
is an HTTPS variant that additionally **prints the TLS parameters it negotiated** (version, cipher,
ALPN, peer cert), **forces ALPN `http/1.1`**, and **warns on `h2`** — because an HTTPS endpoint that
reads "not vulnerable" is almost always a *layer* problem, not a real one:

- **A TLS-terminating proxy that normalizes HTTP** (nginx, HAProxy, cloud LB, Cloudflare, ingress)
  sits in front and rejects/normalizes the malformed requests → genuinely not vulnerable *through
  that front door* (the §2 mitigation). Probe the uWS back-end directly to see the deviation.
- **The endpoint negotiated HTTP/2** (ALPN `h2`): an HTTP/1.1 probe can't express the framing → false
  negative. The TLS probe forces `http/1.1` and warns if the server still picks `h2`.

**Verified firsthand** (via [`demo/uwebsockets-js/run_tls.sh`](./demo/uwebsockets-js/run_tls.sh),
which starts a **uWS.js `SSLApp`** — uWS terminating TLS itself — with a self-signed cert):

| TLS target | negotiated | A | B | C |
|---|---|---|---|---|
| **uWS.js `SSLApp`** (uWS does TLS) | TLS 1.3, ALPN `""` (HTTP/1.1) | VULNERABLE | VULNERABLE | VULNERABLE |
| **nginx TLS-terminator** → plaintext uWS | TLS 1.3, ALPN `http/1.1` | safe (`400`) | safe (`400`) | safe (`400`) |

When uWS terminates TLS the **same C++ `HttpParser`** runs, so A/B/C are present over HTTPS exactly as
over plaintext. When a normalizing proxy terminates TLS, it closes them at the edge (`/steal` reached
the back-end **0** times). That contrast is the likely explanation for a "not vulnerable over TLS"
reading: you're probing the terminator, not uWS.

---

## 4. Provenance, disclosure & severity reasoning

### 4.1 Upstream issue #1898 — what it is (verified) and what it isn't

Read directly from GitHub: issue **#1898**, titled *"Server Fails to Properly Handle Extra Data Beyond
Content-Length,"* is closed with the `invalid` label. Its scenario is **single-client**: one client
sends *extra bytes beyond its own declared `Content-Length`*; uWS leaves them in the socket buffer
where they're "interpreted as the start of a new HTTP request." The reporter called it *"potential"*
smuggling. **No written maintainer rationale was retrievable** for the `invalid` label (an earlier
draft of our notes paraphrased a "front-end's job" stance — that was **unsubstantiated and has been
removed**; do not attribute it).

- **For #1898 as reported, `invalid` is defensible.** A client leaving junk on *its own* connection
  only poisons *itself* — no second user, no victim, no trust boundary crossed. And "extra data beyond
  Content-Length" is exactly what a normalizing front-end strips, so it can't reach a proxied back-end.
- **But #1898 is a different, weaker bug than ours.** Our A/B/C are **cross-client parser
  *disagreements*** demonstrated to produce actual attacker→victim theft via a **pooled** back-end
  connection — not single-client leftover bytes. #1898 does not adjudicate our case.

### 4.2 "If it isn't real, why did Bun patch it?" — the revealed-preference argument

A strong point. Bun forked uWS and, at real CPU cost (the metric both projects optimize hardest),
**patched B and C** — Bun's own source even comments that upstream "consumed these bytes blindly,
which let attackers smuggle a second request … Strict validation closes that desync." So:

- **It establishes relevance.** A serious downstream shipping the same parser wrote a *security* patch
  for these. The strongest "non-issue" framing is off the table — it's a real, **server-fixable** bug.
- **What it doesn't by itself establish** is "critical vuln in uWS," because Bun and uWS answer
  *different questions*:
  - **Different artifacts** — Bun patched B and C (and left **A** live in 1.3.14); #1898 was the
    single-client extra-data case. Not a head-to-head refutation.
  - **Different threat models** — Bun.serve is marketed as a *directly-exposable* server ("we can be
    the edge → we must be strict"); uWS positions itself as a *component behind a compliant proxy*
    ("out of scope"). Same parser, opposite-but-defensible calls.
- **Why it still tilts toward "should be fixed."** The "out of scope" defense assumes everyone deploys
  a normalizing L7 proxy — but L4 LBs and lenient gateways are common and break that assumption, and
  the whole industry (Node/llhttp, Go `net/http`, Gunicorn, Puma…) has already tightened server-side
  parsers, several drawing smuggling CVEs. Bun's patch is that maturation applied to uWS; it proves
  the fix is cheap and worthwhile once you can't assume a clean front-end.

### 4.3 Severity verdict (per scenario)

- **B** (conflicting duplicate `Content-Length`) — strongest; near-textbook CWE-444, RFC 9112 §6.3
  explicitly says such a message *ought to be handled as an error*. CVE-worthy on the merits.
- **A** (empty header name hides `Content-Length`) — strong; clean parser-desync primitive with
  demonstrated cross-user theft. The most universal (live even in Bun 1.3.14).
- **C** (chunk `g`=16) — real spec violation, but standalone impact is a **scoped connection desync**
  (§1: no crash, no server-wide DoS). Better framed as hardening/robustness within the class.

**Overall:** a real, server-fixable request-smuggling class (CWE-444) worth coordinated disclosure —
**but deployment-conditional**: a compliant L7 proxy fully mitigates it, so the practical exposure is
directly-internet-facing deployments and those behind L4/pass-through or non-normalizing front-ends.
The honest framing is *"RFC-violating lenient parsing enabling request smuggling behind pooling
front-ends,"* with **Bun's fork as proof it is server-fixable**. Expect the uWebSockets maintainer to
contest an upstream advisory on the "front-end's job" grounds, which likely makes any CVE a *disputed*
one rather than an uncontested vendor GHSA.

---

## 5. Reproduce everything

```bash
# 1) C impact (no crash / no server-wide DoS) — run a backend on :9001 first
python3 security-findings/tools/validate_c_impact.py 127.0.0.1 9001

# 2) nginx mitigation (compliant L7 proxy closes A/B/C even with pooling on)
./security-findings/tools/nginx_mitigation_test.sh

# 3) probe any URL (back-end vs front door)
go run security-findings/tools/smuggle_probe.go http://127.0.0.1:9001/

# 4) end-to-end cross-user theft through a LENIENT pooling proxy (the positive PoCs)
( cd security-findings/demo/networked      && ./run_networked.sh )   # uWS core
( cd security-findings/demo/uwebsockets-js && ./run.sh )             # uWebSockets.js
( cd security-findings/demo/hyper-express  && ./run.sh )             # hyper-express
( cd security-findings/demo/bun            && ./run.sh )             # Bun (A only)
```

Prereqs: `go`, `g++` (C++17) + the `uSockets` submodule for the C++ back-end, `node` (v22+) for the
Node back-ends, `bun` for the Bun PoC, `nginx` for the mitigation test, `python3` for the impact probe.
