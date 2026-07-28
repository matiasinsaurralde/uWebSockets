# Ecosystem impact & root-cause attribution — the uWebSockets HTTP request-smuggling class

**Question this document answers:** the HTTP request-smuggling primitives in
[`FINDINGS.md`](./FINDINGS.md) were found in uWebSockets' C++ HTTP parser. Do they reach the
popular runtimes/frameworks built on uWebSockets — **uWebSockets.js, Bun, hyper-express** — and when
smuggling is confirmed there, is it **actually caused by the uWebSockets parser code path**, or by
something those projects add on top?

**Answer:** the smuggling is caused by the **uWebSockets C++ `HttpParser`** in every case. Each
downstream is affected *exactly* to the degree it ships that parser unmodified. Three of the four
targets are byte-for-byte the same parser and are fully affected; **Bun** ships a *hardened fork* and
is affected only by the one deviation it did **not** patch. Every cell below was **reproduced
firsthand on this machine**, and the two runtime deep-dives are backed by exact source citations in
per-target `CAUSAL-ATTRIBUTION.md` files.

---

## 1. Confirmed matrix (all reproduced firsthand, 2026-07-28)

| Target | Runs the uWS parser via | **A** empty header name | **B** duplicate `Content-Length` | **C** chunked `g`=16 | Net exposure |
|---|---|:--:|:--:|:--:|---|
| **uWebSockets** (this repo `src/`) | native C++ server | 🔴 **theft** | 🔴 **theft** | 🟠 desync (over-read) | A + B + C |
| **uWebSockets.js** v20.69.0 | prebuilt Node addon, uWS core `fe7c01a` | 🔴 **theft** | 🔴 **theft** | 🟠 desync (over-read) | A + B + C |
| **hyper-express** 7.0.2 | → uWebSockets.js v20.69.0 | 🔴 **theft** | 🔴 **theft** | 🟠 desync (over-read) | A + B + C |
| **Bun** 1.3.14 | **vendored uWS *fork*** (`packages/bun-uws`) | 🔴 **theft** | 🟢 `400` (hardened) | 🟢 `400` (hardened) | **A only** |

- 🔴 **theft** = clean cross-user request smuggling: the victim's normal `GET /account` (carrying
  `Cookie: victim-secret-cookie`) is served the attacker's smuggled `/steal`, and the victim's own
  cookie is folded into it. Directly observed in each PoC's backend log.
- 🟠 **connection desync (over-read)** = uWS *accepts* the `g`=16 chunk size (F1) and **over-reads**
  the chunk *within the buffered stream*, corrupting the framing on **that one connection**; the
  victim sharing it gets `505` + close. **Validated (see §Validated impact of C):** the server
  process does **not** crash and stays fully available to every other connection — the denial of
  service is *scoped to the users on the poisoned pooled connection*, **not** a server-wide outage,
  and it is **not** a memory-safety / out-of-bounds read.
- 🟢 **hardened** = the deviation is **not live**: Bun's fork rejects the input with `400`. (Through a
  *pooling* proxy the `400`+close still poisons the shared connection → a victim-side DoS, but that
  is a front-end pooling artifact, **not** the uWS parser bug being exploitable.)

**Bottom line:** A (the empty-header-name sentinel) is the most dangerous and most universal — it is
live in **all four** targets, including Bun. B and C are live wherever the uWS core is shipped
unmodified (the fork, uWebSockets.js, hyper-express) and only closed where a downstream patched the
parser itself (Bun).

### Validated impact of C — no crash, no server-wide DoS (scoped connection desync)

The `g`=16 (F1) outcome is often loosely called "DoS." To be precise, it was **validated directly**
(2026-07-28): the case-C payload — and an aggressive over-read variant that declares a 32-byte chunk
but sends 4 bytes then closes — were sent straight at each server, and process liveness + server-wide
availability were checked immediately after.

| Target | direct case-C | over-read (declare 32, send 4, EOF) | fresh requests served **after** the attack | process |
|---|---|---|---|---|
| uWS core | `505` | connection aborted (no response) | **8 / 8** | **ALIVE** |
| uWebSockets.js | `200` | `200` | **8 / 8** | **ALIVE** |
| hyper-express | `200` | connection aborted (no response) | **8 / 8** | **ALIVE** |

**Findings:**
- **The process does not crash** on any target — all three stayed alive through both the case-C
  attack and the aggressive over-read+EOF probe.
- **No server-wide denial of service** — every server kept serving fresh connections normally (8/8)
  immediately after the attack.
- **Not a memory-safety bug.** The "over-read" is *logical stream mis-framing bounded by uSockets'
  padded recv buffer*, not an out-of-bounds memory read. When the declared chunk bytes aren't
  present, the streaming parser waits for more data or **aborts cleanly on EOF** (the over-read
  probe closes the connection with no crash).
- **The real, scoped impact:** C corrupts request framing on **the single connection** carrying the
  malformed chunk. Behind a *pooling* front-end that reuses one back-end connection across users,
  that poisoned connection returns `505`/close (or a mis-matched response) to the co-tenant victim(s)
  multiplexed onto it — a request-smuggling-class **denial / response-mismatch against pooled
  co-tenants**, not a crash and not a whole-server outage. (Severity still matters: it breaks request
  integrity and can deny the affected users; it simply isn't a process-kill.)

---

## 2. Root cause — the shared uWebSockets code path (exact lines)

All three primitives are decided **inside** uWebSockets' C++ parser, before any downstream JS/Zig
runs. Citations are this repo's `src/` (proven identical to the shipped cores — see §3).

### A — empty header name (`:`) hides `Content-Length` → `src/HttpParser.h`
1. **The empty field name is accepted, not rejected.** `consumeFieldName` returns immediately at a
   leading `:` (`HttpParser.h:274`), so the stored key has length 0. The loop's only guard checks
   that a colon follows the name (`:401`) — it never rejects a **zero-length** name.
2. **A zero-length key is uWS's end-of-headers sentinel.** Header lookup (`getHeader`, `:117`) and
   header enumeration (`:503`) both iterate `while ((++h)->key.length())`, stopping at the first
   empty key. So every header placed **after** the lone `:` line — including `Content-Length` — is
   invisible.
3. **Body framed as zero.** `getHeader("content-length")` returns empty (`:524`); with no CL and no
   TE, control reaches the "no body" branch `dataHandler(user, {}, 0)` (`:600-603`). The bytes the
   attacker declared via the hidden `Content-Length` are left unconsumed and parsed as the **next**
   request → cross-user smuggle.
   *Root-cause line:* **`HttpParser.h:401`** (no zero-length-field-name rejection).

### B — duplicate `Content-Length`, first wins → `src/HttpParser.h`
- `getHeader("content-length")` returns the **first** match (`:117-120`); the body is framed from it
  (`:584-585`). There is no check that duplicate CL values conflict (RFC 9112 §6.3 requires
  rejecting the message). A front-end that honours the *last* CL disagrees with uWS's *first* →
  smuggle. *(Note the fork **does** defend TE+CL at `:525-530`; it just doesn't defend CL+CL.)*
  *Root-cause:* first-match `getHeader` (`:117`) + missing duplicate-CL conflict check (~`:584`).

### C — chunked `g`/`G`/`@` = hex 16 (F1 off-by-one) → `src/ChunkedEncoding.h`
- The hex-digit remap (`:49-53`) folds `a→:` / `A→:`, sending `g`(0x67) and `G`(0x47) — and the raw
  byte `@`(0x40) — onto ASCII `@`; then `number = digit - '0' = 16` (`:55`). Line `:57`'s
  `number > 16` **allows 16** (a valid hex digit is ≤ 15), so `1g` = `1*16 + 16 = 32`. uWS then
  **over-reads** 32 chunk bytes where the proxy framed fewer → the pooled stream desyncs.
  *Root-cause line:* **`ChunkedEncoding.h:57`** (`number > 16` should be `> 15`).

---

## 3. Provenance — it is the *same* code, established three ways

| Target | Link to the uWS core | How verified (firsthand) |
|---|---|---|
| **This repo `src/`** | == upstream uWebSockets **`fe7c01a`** | `diff -rq src/` vs a clean `fe7c01a` checkout → **byte-identical**. These are real upstream bugs, not fork plants. |
| **uWebSockets.js** v20.69.0 | prebuilt addon → uWS core `fe7c01a` | installed addon `source_commit` = `faf1152` = the `v20.69.0` tag; that tag's `.gitmodules` pins the uWS C++ submodule at **`fe7c01a`**; `HttpParser.h`/`ChunkedEncoding.h` at `fe7c01a` are **SHA256-identical** to this repo's `src/`. → [`demo/hyper-express/CAUSAL-ATTRIBUTION.md` §0](./demo/hyper-express/CAUSAL-ATTRIBUTION.md) |
| **hyper-express** 7.0.2 | → uWebSockets.js v20.69.0 (same binary) | same chain; hyper-express does **no** HTTP parsing of its own. |
| **Bun** 1.3.14 | vendored uWS **fork** `packages/bun-uws` | read the exact source tag `bun-v1.3.14` (build `0d9b296`, matches the live backend's self-report). Scenario-**A** code is **unchanged** from `fe7c01a`; **B** and **C** are Bun-authored hardenings absent from both `fe7c01a` and upstream `master`. → [`demo/bun/CAUSAL-ATTRIBUTION.md`](./demo/bun/CAUSAL-ATTRIBUTION.md) |

---

## 4. Per-target causal attribution (summaries; full citations in the linked files)

### uWebSockets.js & hyper-express → [`demo/hyper-express/CAUSAL-ATTRIBUTION.md`](./demo/hyper-express/CAUSAL-ATTRIBUTION.md)
- **hyper-express performs zero HTTP parsing.** It *is* a native uWS `App` (`Server.js:186/188`),
  binds routes directly on it (`:693`), and reads URL/method/headers/body **only** from native
  accessors (`Request.js:73-77`; body via `onDataV2`, `:253`). A tree-wide sweep found no
  request-line/header/chunked parser anywhere in its JS.
- **uWebSockets.js is a thin V8 binding.** `getUrl`/`getMethod`/`getHeader`/`forEach`/`onDataV2`
  each pass straight through to `uWS::HttpRequest`/`HttpResponse` with no inspection
  (`HttpRequestWrapper.h`, `HttpResponseWrapper.h`).
- **A/B binary-independent proof + C binary proof.** Differential probe against the exact bundled
  binary: `g`/`G`/`10` → `200` + 16-byte body read, `z` → `400` — i.e. the shipping addon **accepts
  `g`=16** (F1 live). A and B are proven-from-source; C is proven-from-source **and**
  binary-confirmed.
- **Verdict:** A/B/C are all caused by the uWebSockets code path reached via uWebSockets.js.
  hyper-express contributes nothing (only a benign, inert last-wins header map used for buffer
  sizing).

### Bun → [`demo/bun/CAUSAL-ATTRIBUTION.md`](./demo/bun/CAUSAL-ATTRIBUTION.md)
- **`Bun.serve` parses through the vendored uWS `HttpParser`.** Source chain: `server.zig:539`
  (`uws.NewApp`) → `uws_create_app` (`libuwsockets.cpp:31`) → `HttpContext::onData`
  (`HttpContext.h:242/281`) → `HttpParser::getHeaders` (`HttpParser.h:661`). Bun runs **no**
  server-side parser of its own; the `picohttp` parser is used **only** by the `fetch` *client*
  (`http.zig:1893`), never by `Bun.serve` — the two paths are correctly distinguished.
- **A is live and unmodified.** The empty-name / empty-key-sentinel logic is byte-for-byte the
  upstream code (`packages/bun-uws/src/HttpParser.h:471/745/228/860/880/980-982`). Firsthand probe:
  `:` before `Content-Length:16` → `200` with **`delivered=0`** (CL hidden; 16 bytes smuggled).
- **B and C are Bun-hardened *inside the fork*.** Bun replaced first-wins CL with an all-headers
  scan that rejects empty/differing duplicates (`HttpParser.h:878-893`) and rewrote the chunk hex
  parser to reject `g`/`G`/`@` (`ChunkedEncoding.h:98-102`), plus added chunk/trailer-terminator
  validation. Both hardenings are absent from `fe7c01a` **and** upstream `master`. Firsthand probe:
  dup-CL(differing) → `400`, `g`/`G` → `400`, valid `10` → `200`.
- **Verdict:** Bun's confirmed smuggling (**A**) is caused by the vendored uWebSockets code path;
  B and C are not exploitable because Bun patched the parser itself.

---

## 5. The instructive contrast: Bun proves the fix belongs in the parser

Bun's fork is a natural experiment. By patching **two** of the three deviations *inside its vendored
uWS* — a duplicate-`Content-Length` rejection and a corrected chunk-size grammar — Bun closed B and
C for every `Bun.serve` app, while adding **nothing** to its Zig/JS layer to do so. That
demonstrates two things at once:
1. **These are parser-level bugs, fixable in the parser** (Bun's diffs are the proof-of-fix — and a
   ready template for upstream). The empty-header-name sentinel (A) is simply the one Bun hasn't
   patched *yet* (its later `master` reportedly does).
2. **Downstreams inherit exactly the parser they ship.** uWebSockets.js and hyper-express ship the
   unmodified `fe7c01a` core, so they inherit **all three** bugs 1:1. A front-end or wrapper cannot
   "accidentally" fix a parser deviation it never sees — and, as the PoCs show, a *lenient* one makes
   every deviation exploitable.

---

## 6. Fix recommendations (in priority order)

1. **Fix uWebSockets' parser** (closes the class at the root, for all downstreams):
   - Reject a **zero-length field name** at `HttpParser.h:401` (closes **A**).
   - Reject **conflicting duplicate `Content-Length`** (closes **B**) — Bun's `HttpParser.h:878-893`
     is a working reference.
   - Change `ChunkedEncoding.h:57` `number > 16` → `> 15` (closes **C**) — Bun's
     `ChunkedEncoding.h:98-102` is a working reference; also validate chunk/trailer terminators.
2. **Deploy a strict, re-serializing front-end.** A compliant reverse proxy (the PoCs use Go
   `net/http`) rejects A and B with `400` and re-normalizes C before the back-end ever sees the
   disagreement. Demonstrated by every PoC's `strict_proxy`, and **validated with real nginx 1.24**:
   with `upstream keepalive` (back-end pooling explicitly *on*), all three attacks return `400` at
   the edge and `/steal` never reaches uWS. So a compliant **L7** proxy (nginx; envoy by design)
   closes the whole class. The residual exposure is **L4/TCP load balancers** (AWS NLB, HAProxy
   `mode tcp`, many k8s `LoadBalancer` services) and **non-normalizing gateways**, which pool
   connections across users *without* re-serializing.
3. **Do not pool back-end connections across users.** Removes the cross-user channel that turns a
   parser disagreement into cross-user theft (and turns C's over-read/rejection into a shared-pool
   DoS).

---

## 7. Reproduce it yourself

Each target has a self-contained, fully-networked PoC (attacker + victim + pooling `vuln_proxy` +
mitigating `strict_proxy`, all real TCP). From `security-findings/demo/`:

```bash
# Real uWebSockets C++ server (the core)
cd networked        && ./run_networked.sh            # A/B theft, C desync, + mitigation

# uWebSockets.js v20.69.0
cd uwebsockets-js    && ./run.sh                      # A/B theft, C desync, + mitigation

# hyper-express 7.0.2 (-> uWebSockets.js 20.69.0)
cd hyper-express     && ./run.sh                      # A/B theft, C desync, + mitigation

# Bun 1.3.14 (vendored uWS fork)
cd bun               && ./run.sh                      # A theft; B/C hardened -> DoS; + mitigation
```

Parser-level proofs of the deviations themselves are in [`poc/`](./poc/). Per-runtime source
attribution is in each PoC dir's `CAUSAL-ATTRIBUTION.md`.

**Test any deployment yourself** with the single-file probe in [`tools/`](./tools/):

```bash
go run tools/smuggle_probe.go http://127.0.0.1:9001/   # your back-end directly  -> expect VULNERABLE
go run tools/smuggle_probe.go http://127.0.0.1:8080/   # your proxy's front door -> compliant L7 = safe
```

It reports A/B/C as `VULNERABLE` / `safe` for any HTTP/1.1 URL (exit 1 if any case is vulnerable).
Run it against the back-end *and* the front door and compare — that difference is the whole point.
