# uWebSockets — Zero-Day Vulnerability Hunt: Findings

> ## ⚠️ IMPORTANT CORRECTION (provenance) — added after ecosystem validation
>
> Ecosystem testing prompted a direct diff of this repo's `src/` against **upstream
> uNetworking/uWebSockets at `fe7c01a`** (the commit this fork is based on, and the one
> uWebSockets.js v20.69.0 ships). **The two are byte-identical** (`diff -rq` is empty, including
> `ChunkedEncoding.h:57` `number > 16` and `WebSocketProtocol.h:361` `getOpCode(src) < 2`).
>
> **Therefore these are NOT "planted" fork-specific bugs — they are real, shipping upstream
> uWebSockets code.** My original "surgical one-token plant" framing below was an *unverified
> inference* (during discovery I deliberately did not diff against upstream, per the ground rules);
> the diff disproves it. The findings are genuine upstream uWebSockets bugs, which is why they
> reproduce in **uWebSockets.js and hyper-express** (fully — same `fe7c01a` core) and in **Bun**
> (partially — Bun ships a uWS *fork* that hardened F1 and duplicate-`Content-Length`, but still
> has the empty-header-name smuggle live) — see
> [`ECOSYSTEM-IMPACT.md`](ECOSYSTEM-IMPACT.md) and the per-target PoCs under `demo/`. Read
> "plant"/"planted" below as "upstream bug."
>
> A *related* upstream report exists — issue **#1898**, "Server Fails to Properly Handle Extra Data
> Beyond Content-Length" — closed as `invalid`. But it describes a **single-client** scenario (a
> client leaving extra bytes on its *own* connection), which is weaker than and **distinct from** the
> **cross-client** smuggle demonstrated here (attacker→victim cookie theft via a *pooled* back-end
> connection). I could **not** retrieve a written maintainer rationale for the `invalid` label, so no
> specific maintainer stance is quoted (an earlier draft's "it's the front-end's job" paraphrase was
> unsubstantiated and has been removed). Separately **validated**: a compliant L7 proxy (nginx 1.24,
> and by design envoy) **rejects all three deviations** and closes the cross-client leak — real-world
> exposure is against **lenient / L4 front-ends** (TCP load balancers, non-normalizing gateways) that
> pool connections across users. Use [`tools/smuggle_probe.go`](tools/smuggle_probe.go) to test a
> given deployment.

## Executive summary

A first-principles source audit (no changelog/git-diff/patched-version comparison), driven by
a multi-agent search across every attacker-facing surface, identified **three confirmed,
independently-reproduced vulnerabilities**, two of which are surgical one-token deviations
planted into the always-compiled core, plus a set of lower-severity issues in opt-in
/experimental components. Each of the three is a complete chain to one of the target scenarios.

| ID | Location | Class | Scenario reached | Reachability | Evidence |
|----|----------|-------|------------------|--------------|----------|
| **F1** | `src/ChunkedEncoding.h:57` | Off-by-one (`number > 16` ⇒ should be `> 15`) | HTTP request smuggling → validation/limit/auth bypass, cross-request traffic leak | **Always compiled (core)** | executed PoC (root + 2 agents) |
| **F3** | `src/WebSocketProtocol.h:361` | Off-by-one (`getOpCode(src) < 2` ⇒ should be `< 3`) | WebSocket frame injection / message-boundary & opcode confusion | **Always compiled (core)** | executed PoC (root + agent) |
| **F2** | `src/CachingApp.h` (whole caching layer) | Dangling `std::string_view` map keys (lifetime/type) | Cross-user cached-response disclosure + use-after-free crash + uninit-read + unbounded-growth DoS | Opt-in (`CachingApp`, unused WIP) | ASAN heap-UAF + valgrind (agent) |

Supporting/secondary: HTTP header-parsing smuggling variants; HTTP/3 (opt-in `WITH_QUIC`)
prototype memory bugs; a benign 16-byte over-allocation decoy in uSockets.

---

## F1 — HTTP chunked-encoding hex-digit off-by-one → request smuggling  (CORE)

**Location:** `src/ChunkedEncoding.h:57`, in `consumeHexNumber()`:
```c
if (number > 16 || (chunkSize(state) & STATE_SIZE_OVERFLOW)) {   // BUG: must be > 15
    state = STATE_IS_ERROR;
    return;
}
```

**Root cause.** The fast hex parser remaps `a–f`/`A–F` onto the byte range `:`..`?` (0x3A–0x3F) so
that `number = digit - '0'` yields 0..15 for every valid hex digit. A digit is therefore valid
**iff `number ∈ 0..15`**, so the reject test must be `number > 15`. The planted `number > 16`
also accepts `number == 16`, which is produced by exactly the non-hex bytes **`'@'` (0x40),
`'G'` (0x47→0x40), `'g'` (0x67→0x40)** — each is accepted as a chunk-size digit worth 16.

**Executed proof** (`scratchpad/verify_f1.cpp`, real header):
```
g + 16 'A'    emitted=16   (should be a 400)     1g + 32 'B'   emitted=32
f + 15 'C'    emitted=15   (valid)               h + junk      err=1  (correctly rejected)
```

**Impact — request smuggling / stream desync.** uWS decodes `g\r\n<16 bytes>\r\n0\r\n\r\n` as a
16-byte body and `1g` as 32; a compliant front-end proxy that instead rejects or differently
interprets a chunk-size line containing `g`/`G`/`@` disagrees with uWS on where the body ends and
the next request begins. Quantified desync: `g`+16 → 16-byte desync; `1g`+32 → 31-byte desync.
This is a genuine parser deviation and a smuggling **primitive**; weaponization (auth/WAF bypass,
cache poisoning, victim-response theft) requires a front-end that forwards rather than 400s the
malformed chunk size and computes a different body length — the standard precondition for all
HTTP request smuggling.

**Not memory corruption** (verified): the `STATE_SIZE_OVERFLOW` guard (bits 56–59) trips before the
accumulated size can shift into the state flag bits (62/63), and every `getNextChunk` read is
bounded by `data.length()`; 3M ASAN/UBSan iterations were clean.

---

## F3 — WebSocket fragmentation opcode off-by-one → frame injection  (CORE)

**Location:** `src/WebSocketProtocol.h:361`, in `consumeMessage()`:
```c
if (getOpCode(src)) {                                              // opcode != 0 (not continuation)
    if (wState->state.opStack == 1 ||
        (!wState->state.lastFin && getOpCode(src) < 2)) {          // BUG: must be < 3
        Impl::forceClose(wState, user, ERR_PROTOCOL);
        return true;
    }
    wState->state.opCode[++wState->state.opStack] = (OpCode) getOpCode(src);
}
```

**Root cause.** Per RFC 6455 §5.4, once a non-FIN data frame has started a fragmented message, the
next frame must be a continuation (opcode 0) or a control frame (8–10); a **new data frame** (TEXT=1
**or BINARY=2**) is a protocol error. Because opcode 0 is already excluded by the enclosing `if`,
the guard `getOpCode(src) < 2` catches **only opcode 1 (TEXT)**. A new **BINARY (2)** frame arriving
mid-fragmentation is **not** rejected — it is pushed onto the op-stack and its payload silently
concatenated into the in-progress message. The correct constant is `< 3`.

**Executed proof** (`scratchpad/verify_f3.cpp`, real header; server frames masked `01 02 03 04`):
```
inject TEXT(1)  mid-frag →  closed=1  "Received invalid WebSocket frame"      (correctly rejected)
inject BINARY(2) mid-frag →  closed=0  assembled="AAAABBBBCCCC"  opcode=2       (BUG: accepted)
```
The asymmetry — TEXT-interleave rejected, BINARY-interleave accepted — is the signature of the
`< 3`→`< 2` plant.

**Impact — message-boundary / opcode confusion, frame injection.** An application that distinguishes
TEXT vs BINARY, or trusts uWS's message framing, can be fed attacker-chosen BINARY bytes inside what
began as a TEXT message (and here the whole message is even re-labelled opcode 2). Self-contained:
needs only a malicious WebSocket client. **Bounded — not memory corruption**: `opStack` is a 2-bit
field guarded by the `== 1` check so `opCode[2]` is never written OOB, and the fragment buffer stays
capped by `maxPayloadLength` (per-frame `refusePayloadLength` + running-total check in
`WebSocketContext.h:111`).

---

## F2 — CachingApp dangling `string_view` cache keys → cross-user leak + UAF  (opt-in)

**Location:** `src/CachingApp.h` — `typedef unordered_map<std::string_view, CachingHttpResponse*> CacheType;`
key taken at `:79` (`cache_key = req->getFullUrl()`), used at `:82`, stored at `:100`, **never copied
to an owned string**.

**Root cause.** `getFullUrl()` returns a `std::string_view` into the parse buffer — either uSockets'
single **shared per-loop `recv_buf`** (overwritten by the next read on any connection) or the
per-connection `HttpParser::fallback` `std::string` (**freed on connection close**). The map node
persists across requests/connections, so every stored key aliases live/foreign/freed memory once the
handler returns.

**Confirmed (agent, executed):**
- **Use-after-free:** ASAN `heap-use-after-free READ` inside `std::operator==` during `unordered_map::find`,
  after the backing `fallback` was freed on connection close. (crash / potential info-flow)
- **Same-URL cross-user disclosure:** the cache key is URL-only (no `Vary`/`Authorization`/`Cookie`),
  so Bob's `GET /account/balance` is served Alice's cached private body. This is the "leak traffic from
  other requests" scenario.
- **Uninitialized read:** `created` is read (`:85`) though the node is inserted (`:100`) before the
  handler sets it (`:41`) → nondeterministic expiry/serve of an incomplete buffer (valgrind-confirmed).
- **Unbounded growth:** no eviction anywhere → memory-exhaustion DoS.

**Adversarially refuted sub-claim:** a *different*-URL wrong-serve does **not** occur in practice —
libstdc++ caches each node's hash code and gates `operator==` on hash equality, so cross-URL confusion
needs a ~2^64 hash collision, not merely the aliasing. The realistic leak is the same-URL case above.

**Reachability:** `CachingApp` is opt-in and currently **unused WIP** (no examples/tests; `// todo`,
`// should be a vector of waiting sockets`). Real and dangerous as written, but not wired into the
default build or any shipping app.

---

## Secondary / supporting findings

- **HTTP header-parsing smuggling variants** (`src/HttpParser.h`, possibly pre-existing leniency, agent-A PoC):
  (a) an empty field-name line (`:\r\n`) produces a zero-length key that collides with the header-list
  terminator sentinel used by `getHeader`/the bloom loop, hiding every subsequent header — including
  `Content-Length` — from the application while the request still parses → CL-desync smuggling;
  (b) duplicate `Content-Length` with differing values is accepted (only `Host` is de-duplicated) and
  the **first** value used → smuggling if a front-end uses the last. (Correctly closed: `TE`+`CL` ⇒ 400;
  `Content-Length :` with space ⇒ 400.)
- **HTTP/3 stack** (opt-in `WITH_QUIC`, experimental prototype — real bugs, not surgical plants):
  unbounded header-count write into a fixed 4096-byte header-set row (`uSockets/src/quic.c:869`);
  missing capacity check on first header decode while the sibling realloc branch guards it
  (`quic.c:814` vs `:822`); a `-1` write return laundered through `unsigned int` into
  pointer/length arithmetic (`src/Http3Response.h:85`, `tryEnd`/`on_stream_writable`); plus a
  stream-lifecycle leak (`on_stream_close` never invoked) and a global 10-entry response-header array
  with no bound (app-controlled).
- **`uSockets/src/context.c:403`** (adopt / HTTP→WS upgrade) passes `sizeof(us_socket_t)+ext_size` to
  `us_poll_resize` instead of `sizeof(us_socket_t)-sizeof(us_poll_t)+ext_size` → **16-byte
  over-allocation** (benign; the exploitable form would be the opposite sign). Looks planted but is a
  harmless decoy.
- **Client-side send under-allocation (SUSPECT):** `messageFrameSize()` omits the 4-byte client mask
  that `formatMessage` writes for `!isServer`, so a uWS **client** send can under-allocate the cork
  buffer by 4 bytes at its edge. Server sends (unmasked) are exact. Low priority (client-only).

---

## Cleared surfaces (negative space — audited, no memory-safety bug)

- **uSockets core** (`loop.c`, `socket.c`, `context.c`, `bsd.c`, `crypto/openssl.c`): the 32-byte
  pre/post recv-buffer padding invariant holds exactly (malloc `524288 + 32*2`, data at `+32`, recv
  capped at `524288`); SSL read accumulator cannot overshoot; address copy is guarded in the safe
  direction. (agent G + root)
- **Multipart / QueryParser / ProxyParser / MessageParser / BloomFilter** — every attacker-length
  computation correctly bounded; ASAN+UBSan fuzzed (QueryParser ~5M, ProxyParser exhaustive, Multipart
  ~2M, `getHeaders` sink 20M): zero errors. (agent D)
- **WebSocket frame memory-safety** — 64-bit length overflow blocked by `refusePayloadLength` *before*
  any `payLength + header` arithmetic; all mask XOR / spill / control-frame paths in-bounds; imprecise
  unmask over-read (≤ header+8 B) stays within the 32-byte padding; handshake SHA-1/base64 exact; 3M
  ASAN iterations clean. (agent B + root)
- **permessage-deflate & libdeflate** — `maxPayloadLength` enforced *exactly* on the inflate loop (a
  deterministic sweep proved `cap=S` returns `S`, `cap=S-1` returns `nullopt`); libdeflate return codes
  handled correctly and the fast-path output buffer is `reserve(maxPayloadLength)`-bounded; the vendored
  libdeflate was rebuilt with its bounds checks intact; the 4-byte deflate tail-write stays within recv
  padding (32 B) or the 9-byte fragment pad; deflate `-4` trailer trim is sender-side and guarded against
  empty input; window_bits always land in {0, 8..15}. ~5.5M ASAN/UBSan cases, zero errors. (agent C + root)
- **Response/cork/backpressure** — `BackPressure` `pendingRemoval ≤ physical.length()` invariant holds;
  `getSendBuffer` resize+memcpy fits exactly; cork buffer is one-socket-per-loop (guarded by
  `std::terminate`); no cross-socket cork leak. (leak agent + root)
- **Router / TopicTree pub-sub / per-request state resets** — segment/param stack bounds hold
  (`MAX_URL_SEGMENTS=100`); topic `outgoingMessages` index invariant consistent (cleared only when no
  drainable subscribers); HTTP `state`/`offset`/`inStream` and WS `fragmentBuffer`/`controlTipLength`
  reset correctly between pipelined requests/messages; async pipelining is denied. (leak agent + root)
- **thread_local shared buffers** (`addressAsText`, `negotiateCompression` response, PerMessageDeflate
  shared inflate buffers) — returned views consumed synchronously before reuse; no cross-connection
  leak. (leak agent + root)

## End-to-end demonstration (runnable)

`demo/` contains runnable PoCs against a **real, unmodified uWebSockets back-end** compiled from
this repo's `src/` (`demo/backend_uws.cpp` — a catch-all route that logs and echoes the
`method / url / cookie / x-smuggled` of every request it parses, so cross-user leakage is directly
observable). Two forms:

- **`demo/networked/`** — fully networked: a real reverse proxy with its own TCP listener
  (`vuln_proxy.go`, `:8080`) that pools ONE back-end connection and forwards bytes verbatim, an
  `attacker.go`, a `victim.go`, and a mitigating `strict_proxy.go` (`:8081`). Run
  `demo/networked/run_networked.sh` (or `… a|b|c|mitigate`).
- **`demo/run.sh`** — the same exploit with the proxy modeled in-process (for environments that
  block a second listener).

### Observed results (real uWebSockets back-end)

| Scenario | Attacker request (key part) | uWS behavior | Victim outcome |
|----------|-----------------------------|--------------|----------------|
| **A** empty header name | `Host: t` / `:` / `Content-Length: 33` then a 33-byte smuggled prefix | `:` hides the CL → body length 0 → re-parses the "body" as the next request | Served the attacker's **`/steal`**; back-end parses `url=/steal cookie="victim-secret-cookie" x-smuggled="GET /account HTTP/1.1"` — **cookie + request-line captured** |
| **B** duplicate Content-Length | `Content-Length: 6` + `Content-Length: 39`, body `HELLO!` + smuggled prefix | uWS uses first (6); leftover 33 bytes become the next request | Identical to A — **cookie captured** |
| **C** F1 chunked `g`=16 | `Transfer-Encoding: chunked`, size line `1g` | uWS **over-reads** (`1g`=32), consumes past the terminator, returns `505` + `Connection: close` | Pooled connection **poisoned/closed** → victim **DENIED (DoS)** |

A and B are clean cross-user credential theft. C is the request-smuggling-class **denial of
service**: because F1 makes uWS over-read (rather than under-read), it poisons the shared
connection instead of cleanly stealing — the honest, weaker outcome for that particular bug. The
`g`=16 parser deviation itself is proven deterministically by `demo/poc`-adjacent
`poc/verify_f1_chunked_smuggling.cpp`.

### Mitigation (same PoC)

`strict_proxy.go` / `mitigation.go` send the identical payloads through a strict parser (Go
`net/http`), which **rejects all three** before they reach the back-end:

```
A empty header name        -> 400  (malformed MIME header line)
B duplicate Content-Length -> 400  (multiple Content-Length headers)
C chunked 'g'=16           -> 400 / re-normalized (invalid byte in chunk length)
victim (legitimate)        -> 200  url=/account   (clean; no /steal ever reaches the back-end)
```

That Go rejects `g` as `invalid byte in chunk length` is exactly the behavior uWebSockets *should*
have (the `> 16` → `> 15` fix), confirming F1 is the deviation.

See `demo/README.md` and `demo/networked/README.md` for topology, per-scenario byte-level
walkthroughs, and step-by-step instructions.

## Methodology

Root-coordinated multi-agent search (≤4 concurrent), grouped by approach family: HTTP parsing,
WebSocket protocol, compression/extensions, auxiliary parsers, uSockets core, shared-state leak
hypothesis, PoC/adversarial verification, HTTP/3. Dependencies (uSockets, libdeflate) cloned at their
pinned commits and audited. Every concrete bug was double-checked adversarially and, where feasible,
reproduced with a compiled ASAN/UBSan PoC against the real headers.
