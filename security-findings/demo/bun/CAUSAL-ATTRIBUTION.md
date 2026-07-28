# Causal attribution — is Bun.serve's request smuggling caused by the vendored uWebSockets parser?

**Target:** Bun 1.3.14 `Bun.serve` HTTP back-end (the binary at `/root/.bun/bin/bun`, `bun --version` = `1.3.14`).
**Question:** the cross-user smuggling is *confirmed end-to-end* elsewhere (see `README.md`). This document does **not** re-confirm the exploit — it proves, from source and from the live binary, **which code path is the root cause**: the uWebSockets C++ `HttpParser` that Bun vendors, or Bun's own Zig/JS HTTP layer.

**Method:** the exact Bun source that built the tested binary was read (git tag `bun-v1.3.14`, commit `0d9b296af33f2b851fcbf4df3e9ec89751734ba4`), its vendored uWS parser compared against this repo's upstream baseline (`src/`, byte-identical to upstream uWebSockets `fe7c01a`) and against current upstream uWS `master`, and each scenario was then re-driven against a live `Bun.serve` back-end that **reads the request body** (so acceptance is proven by the handler running, not by a pre-body reply).

---

## 0. Verdict (summary)

| Scenario | Confirmed Bun behavior | Is it CAUSED BY the uWS code path? | Backing |
|---|---|---|---|
| **A** — empty header name (lone `:`) hides `Content-Length` | **SMUGGLED** | **YES** — the vulnerable uWS parser code is present **unmodified** in Bun's vendored fork, and Bun.serve runs it | proven-from-source **and** binary-confirmed |
| **B** — duplicate `Content-Length` (first-wins) | **rejected `400`** | **NO — Bun-hardened.** The upstream first-wins bug is *unreachable*: Bun added a duplicate-CL rejection **inside its uWS fork** | proven-from-source **and** binary-confirmed |
| **C** — chunked `g`/`G`/`@` = hex 16 (F1 off-by-one) | **rejected `400`** at the parser (end-to-end "desync/DoS" is a *pool-layer* effect, not this bug) | **NO — Bun-hardened.** The `number > 16` off-by-one is **fixed** in Bun's uWS fork | proven-from-source **and** binary-confirmed |

**One-line conclusion:** Bun.serve's request parsing is done entirely by the **vendored uWebSockets C++ `HttpParser`** (not by Bun's Zig/JS layer, and not by the `picohttp` parser that Bun's *fetch client* uses). Scenario **A** is a genuine, live uWS-parser bug in Bun 1.3.14. Scenarios **B** and **C** are **blocked** because Bun maintains a **hardened fork** of uWS that patched those two bugs — they are not "inherited unchanged."

> This refines (and in one place corrects) `README.md`: Bun's `packages/bun-uws` is **not** byte-identical to upstream and is **not** "not a fork" — it is a substantially modified fork. Only scenario **A**'s code is unchanged from upstream; B and C are hardened. See §7.

---

## 1. Version pinning — the source read *is* the binary tested

| Artifact | Identity |
|---|---|
| Tested binary | `bun --version` → **1.3.14**; the probe backend self-reported `Bun.serve … (bun 1.3.14)` |
| Source read | git tag **`bun-v1.3.14`** → commit `0d9b296af33f2b851fcbf4df3e9ec89751734ba4` |
| Upstream baseline | this repo `/home/user/uWebSockets/src/` = upstream uWebSockets **`fe7c01a`** (byte-identical, per established facts) |
| Upstream head (for B/C provenance) | uNetworking/uWebSockets **`master`** (fetched live) |

Reading the exact tag that produced the binary means the source-level findings below apply directly to the tested artifact, not to an approximate version.

---

## 2. Where Bun vendors uWebSockets / uSockets

Found by walking the `bun-v1.3.14` tree. **There is no submodule / `.gitmodules` / `source_commit` / version pin** — Bun carries uWS/uSockets as an in-tree, maintained **fork**:

| Path (in Bun @ 1.3.14) | Role |
|---|---|
| `packages/bun-uws/src/HttpParser.h` | vendored uWS **HTTP request parser** (scenarios A & B live here) |
| `packages/bun-uws/src/ChunkedEncoding.h` | vendored uWS **chunked-body parser** (scenario C lives here) |
| `packages/bun-uws/src/HttpContext.h` | socket→parser glue (`onData` → `consumePostPadded`) |
| `packages/bun-uws/src/App.h` | `uWS::TemplatedApp`, owns the `HttpContext` |
| `packages/bun-usockets/src/` | vendored uSockets fork (accept/read loop) |
| `src/uws_sys/libuwsockets.cpp` | C shim (`uws_create_app`, …) exposing the C++ App to Zig |
| `src/uws/uws.zig` | Zig binding layer (`uws.NewApp`) |
| `src/runtime/server/server.zig` | **`Bun.serve`** implementation |

`packages/bun-uws/README.md:1` states it plainly: **"Bun's fork of uWebSockets"** ("based on uWebSockets … Thanks to @uNetworkingAB"). The parser file even carries Bun-authored comments describing where and why it *diverges* from upstream to close smuggling holes (see §6–§7). It is a fork, not a snapshot.

---

## 3. Bun.serve routes server request parsing THROUGH the uWS C++ parser (the code path)

Full chain from an accepted TCP socket to a parsed request, every hop cited. This is the crux of the attribution — **Bun does not run its own request-line/header/body-framing parser on the server side**:

1. **`Bun.serve` builds a uWS App.** `src/runtime/server/server.zig:539`:
   ```zig
   pub const App = uws.NewApp(ssl_enabled);
   ```
2. **`uws.NewApp` → C shim → C++ `uWS::App`.** `src/uws_sys/libuwsockets.cpp:31`:
   ```cpp
   uws_app_t *uws_create_app(int ssl, struct us_bun_socket_context_options_t options)
   ```
3. **The App owns an `HttpContext`.** `packages/bun-uws/src/App.h:52` `#include "HttpContext.h"`; `App.h:96`:
   ```cpp
   HttpContext<SSL> *httpContext;
   ```
4. **`HttpContext` registers `onData` as the socket's `on_data`.** `packages/bun-uws/src/HttpContext.h:571` (`/* on_data */ &onData`).
5. **Every received TCP segment is handed to the uWS parser.** `HttpContext.h:242` `static us_socket_t *onData(us_socket_t *s, char *data, int length)` → `HttpContext.h:281`:
   ```cpp
   auto result = httpResponseData->consumePostPadded(
       httpContextData->maxHeaderSize, …, data, (unsigned int) length, s, proxyParser,
       [httpContextData](void *s, HttpRequest *httpRequest) -> void * { … requestHandler … });
   ```
6. **`consumePostPadded` is the uWS parser entry point.** `packages/bun-uws/src/HttpParser.h:995` → `fenceAndConsumePostPadded<…>` → `getHeaders` (`HttpParser.h:661`). This is where request line, headers, `Content-Length`/`Transfer-Encoding` framing, and chunked decoding are all decided.

The request object the JS `fetch(req)` handler receives is exactly what `uWS::HttpParser` produced. **No Bun-side HTTP request parser sits in front of it.**

**Not to be mis-attributed — the `picohttp` client parser is a different path.** `picohttp` is used **only by Bun's HTTP *client* (`fetch`)** to parse *responses*: `src/http/http.zig` uses `picohttp.Request` (to *emit* outbound requests) and `picohttp.Response.parseParts` (`src/http/http.zig:1893`, parsing server responses). `grep` of `src/runtime/server/server.zig` for `picohttp` → **none**. The server never touches picohttp.

---

## 4. Scenario A — empty header name hides `Content-Length` → **root cause = uWS parser, PRESENT**

**The bug:** a header line that is a lone `:` (empty field name) is accepted and stored as a header with an **empty key**; every header-iteration loop in the parser uses "empty key" as its end-of-headers sentinel, so **every header after the lone `:` — including `Content-Length` — becomes invisible** to the framing logic. uWS then frames the body as length 0 and treats the real body as the next (smuggled) request.

**Bun's vendored code (unmodified from upstream):**

- The field-name scanner returns immediately on a leading `:`, yielding an **empty key** — `packages/bun-uws/src/HttpParser.h:471–472`:
  ```cpp
  if (*p == ':') {
      return p;          // empty field name -> zero-length key
  }
  ```
- The only field-name guard checks `postPaddedBuffer[0] != ':'` — which is **false** for a lone colon, so **no rejection**; the empty-key header is stored and the header pointer advances — `HttpParser.h:740` (key), `:745` (the guard that does *not* fire), `:781` (value), `:796` (`headers++`).
- Every consumer then stops at the empty-key sentinel, hiding what follows:
  - `getHeader()` — `HttpParser.h:228` `for (Header *h = headers; (++h)->key.length();)`
  - `getTransferEncoding()` — `HttpParser.h:253` (same loop)
  - bloom-filter population — `HttpParser.h:860` (same loop; hidden headers aren't even indexed)
  - the duplicate-`Content-Length` scan — `HttpParser.h:880` (same loop)
- With `Content-Length` hidden and no `Transfer-Encoding` seen, framing falls to the "no body" branch — `HttpParser.h:980–982`:
  ```cpp
  } else {
      /* If we came here without a body; emit an empty data chunk to signal no data */
      dataHandler(user, {}, true);
  }
  ```
  `remainingStreamingBytes` stays `0`; the actual body bytes are left in the buffer and parsed as a fresh request → the smuggle.

**Upstream baseline (identical logic):** this repo `src/HttpParser.h:274` (`if (*p == ':') return (void *)p;`), guard `:401`, sentinel loops `:117` and `:503`, empty-body branch `:601–602`. **Bun's fork left this untouched** — hence A is live in Bun.

**Determination: proven-from-source** that the empty-name→hidden-CL primitive is the uWS parser code path, unmodified from upstream. Binary-confirmed in §7.

---

## 5. Scenario B — duplicate `Content-Length` → **Bun-hardened inside the fork (Bun-added)**

**Upstream bug:** duplicate `Content-Length` is resolved **first-wins**, enabling a front-end/back-end value disagreement (classic CL.CL smuggling). Upstream reads the first value via a single `getHeader("content-length")` and never compares duplicates:

- this repo `src/HttpParser.h:524`: `std::string_view contentLengthString = req->getHeader("content-length");` (returns the **first** match; no duplicate check anywhere).
- current upstream `master` (fetched live) is the **same** — `HttpParser.h:490` still `req->getHeader("content-length")`, still no duplicate-value comparison. *(So this bug was never fixed upstream — its absence in Bun is not "a newer upstream.")*

**Bun's fork replaced that lookup with an all-headers duplicate-rejecting scan** — `packages/bun-uws/src/HttpParser.h:878–893`:
```cpp
std::string_view contentLengthString;
if (req->bf.mightHave("content-length")) {
    for (HttpRequest::Header *h = req->headers; (++h)->key.length(); ) {
        if (h->key.length() == 14 && !strncmp(h->key.data(), "content-length", 14)) {
            if (contentLengthString.data() == nullptr) {
                if (h->value.length() == 0) {
                    return HttpParserResult::error(HTTP_ERROR_400_BAD_REQUEST,
                                                   HTTP_PARSER_ERROR_INVALID_CONTENT_LENGTH);   // empty value -> 400
                }
                contentLengthString = h->value;
            } else if (h->value.length() != contentLengthString.length() ||
                       strncmp(h->value.data(), contentLengthString.data(), contentLengthString.length())) {
                return HttpParserResult::error(HTTP_ERROR_400_BAD_REQUEST,
                                               HTTP_PARSER_ERROR_INVALID_CONTENT_LENGTH);        // differing dup -> 400
            }
        }
    }
}
```

**Which of (i) newer-upstream / (ii) Bun-added / (iii) other?** → **(ii) Bun-added**, pinned:
- It uses Bun-specific machinery that does not exist upstream: the `HttpParserResult` return type and the `HTTP_PARSER_ERROR_INVALID_CONTENT_LENGTH` error enum (part of Bun's parser rewrite, alongside Bun-only params `isConnectRequest`, `useStrictMethodValidation`, `maxHeaderSize`, and the `req->head` span for Node.js compat).
- Both the upstream baseline (`fe7c01a`) **and** current upstream `master` still use first-wins with **no** duplicate check. The rejection exists **only** in Bun's fork.

Note the check is deliberately narrow: **identical** duplicate values are allowed; only **empty or differing** duplicates are rejected. That is exactly the smuggling-relevant case, and it matches the binary result in §7 (16-vs-5 → 400; 16-vs-16 → 200).

**Determination: proven-from-source** that B's `400` is a **Bun-authored hardening in the vendored uWS fork**, not the upstream first-wins bug. The upstream code path that would smuggle is present in neither `fe7c01a` nor `master` reachability here — Bun overrides it before it matters.

---

## 6. Scenario C — chunked `g`/`G`/`@` = hex 16 (F1 off-by-one) → **Bun-hardened inside the fork**

**Upstream bug (F1):** the chunk-size hex parser uses `number > 16` where it must be `> 15`, so the non-hex bytes `g`/`G`/`@` map to digit value 16 and are accepted:

- this repo `src/ChunkedEncoding.h:57`: `if (number > 16 || (chunkSize(state) & STATE_SIZE_OVERFLOW)) { … }` — with the digit-mapping at `:48–55`, `'g'` → `('a'-…)` fold → value `16`, which is **not** `> 16`, so it passes.

**Bun's fork rewrote the hex parser correctly** — `packages/bun-uws/src/ChunkedEncoding.h:98–102`:
```cpp
unsigned int d = c | 0x20;                 /* fold A-F -> a-f */
unsigned int n;
if      ((unsigned)(d - '0') < 10) n = d - '0';
else if ((unsigned)(d - 'a') < 6)  n = d - 'a' + 10;   /* only a..f (6 values) */
else return STATE_IS_ERROR;                            /* g/G/@/z/… -> error */
```
For `'g'`: `d = 'g'`, `(d - 'a') = 6`, `6 < 6` is **false** → `STATE_IS_ERROR`. Same for `'G'` (folds to `'g'`) and `'@'`. The off-by-one is **fixed** (correct `< 6` bound instead of `> 16`).

Bun's `ChunkedEncoding.h` is hardened well beyond the hex digit, all with Bun-authored comments describing the upstream weakness being closed:
- **Chunk `\r\n` terminator is now validated** — `ChunkedEncoding.h:218–230` (upstream did not check it).
- **Trailer/terminator bytes are validated by parity** — `ChunkedEncoding.h:167–183`, comment `:156–161`: *"Upstream uWS consumed these bytes blindly, which let attackers smuggle a second request … Strict validation closes that desync."*

**On the end-to-end "desync/DoS" for C:** at the **parser** level Bun cleanly rejects the malformed chunk with `400` (binary-confirmed, §7). So the DoS observed through the *pooling proxy* is a **downstream consequence of that strict rejection + connection close on a shared pooled connection**, **not** the F1 primitive being live. The vendored parser is *not* the cause of any body-framing disagreement for C in Bun.

**Determination: proven-from-source** that C is **Bun-hardened**; the F1 off-by-one is not present in the vendored fork.

---

## 7. Binary confirmation against live Bun 1.3.14

Two differential probes were run against a `Bun.serve` backend whose handler does `const b = await req.arrayBuffer(); return new Response('GOTBODY bytes='+b.byteLength)` — so a scenario is only "accepted" if the handler actually ran and reported the body byte-count uWS delivered.

**Chunk-size probe** (one chunk, size line = token, then exactly 16 payload bytes, then `0\r\n\r\n`):

| size-line token | Bun status | body bytes delivered | meaning |
|---|---|---|---|
| `g` | `400 Bad Request` | — | **rejected** (F1 fixed) |
| `G` | `400 Bad Request` | — | **rejected** (F1 fixed) |
| `10` (hex 16) | `200 OK` | **16** | accepted (valid hex path works; harness sound) |
| `z` (control) | `400 Bad Request` | — | rejected (as expected) |

`g`/`G` behave like the control `z`, **not** like the valid `10` → the `ChunkedEncoding.h` off-by-one is **not live** in Bun's binary. Matches §6.

**A/B probe** (backend reads body; `delivered` = bytes uWS handed the handler):

| request | Bun status | delivered | meaning |
|---|---|---|---|
| baseline: single `Content-Length: 16` + 16 bytes | `200 OK` | `16` | sanity: framing works |
| **A**: `…Host\r\n:\r\nContent-Length: 16\r\n\r\n` + 16 bytes | `200 OK` | **`0`** | **empty-name header hid `Content-Length`** → body framed as 0; the 16 bytes are left as a smuggled pipelined request. **A is LIVE** |
| **B**: `Content-Length: 16` + `Content-Length: 5` + 16 bytes | `400 Bad Request` | — | **dup differing CL rejected** (Bun's added check) |
| B-control: `Content-Length: 16` + `Content-Length: 16` | `200 OK` | `16` | identical dup allowed → confirms the check targets *differing* values (matches `HttpParser.h:887–889`) |

A → `delivered=0` (not `16`, not `400`) is the decisive result: the parser accepted the request but **could not see the `Content-Length`**, exactly the desync primitive from §4. B → `400` on differing values but `200` on identical values exactly reproduces the source logic from §5.

*(Probe scripts, for reproduction, live in the scratchpad: `bun_probe_server.js`, `bun_probe_client.js`, `bun_probe_ab.js`.)*

---

## 8. Correction to `README.md`

`README.md` (this directory) states: *"Bun … calls `uWS::App::create` … so it inherits upstream uWebSockets' HTTP-parsing behavior. This repo's `src/` was verified byte-identical to upstream uWebSockets `fe7c01a`, so the bugs here are real upstream uWebSockets bugs, not a fork."*

Two refinements from the source:
1. **It is a fork.** `packages/bun-uws` is a substantially modified fork (`README.md:1` "Bun's fork of uWebSockets"): `HttpParser.h` is 1130 lines vs the upstream 748; `ChunkedEncoding.h` is fully rewritten. It is **not** byte-identical to `fe7c01a`.
2. **Only A is "inherited unchanged."** The byte-identical-to-`fe7c01a` claim holds for **this repo's `src/`**, and for **scenario A's code inside Bun's fork** — but **not** for B or C, which Bun's fork actively hardened. The demo's own result table already reflects this (B rejected, C rejected); this document supplies the source-level *why*. The exact App-creation entry point is `uws_create_app` (`libuwsockets.cpp:31`) reached via `uws.NewApp` (`server.zig:539`), not a literal `uWS::App::create`.

---

## 9. Final verdict table (per scenario, with citations)

| # | Scenario | Bun 1.3.14 behavior | Caused by the uWS code path? | Primary source citations | Binary |
|---|---|---|---|---|---|
| **A** | empty header name (lone `:`) hides `Content-Length` | **SMUGGLED** | **YES — proven-from-source & binary-confirmed.** Vulnerable uWS parser code present **unmodified**; Bun.serve executes it | Bun `packages/bun-uws/src/HttpParser.h:471–472, 745, 860, 880, 228, 980–982`; upstream `src/HttpParser.h:274, 401, 117, 503`; server path `server.zig:539` → `libuwsockets.cpp:31` → `App.h:96` → `HttpContext.h:571,281` → `HttpParser.h:995,661` | A → `delivered=0` |
| **B** | duplicate `Content-Length` | **rejected `400`** | **NO — Bun-hardened (Bun-added check inside the uWS fork).** Upstream first-wins bug is unreachable | Bun `packages/bun-uws/src/HttpParser.h:878–893`; upstream first-wins `src/HttpParser.h:524` **and** upstream `master` `HttpParser.h:490` (no dup check) | 16-vs-5 → `400`; 16-vs-16 → `200/16` |
| **C** | chunked `g`/`G`/`@` = hex 16 (F1) | **rejected `400`** at parser (E2E "desync/DoS" is a pool-layer effect) | **NO — Bun-hardened.** `number > 16` off-by-one fixed; chunk/trailer terminators now validated | Bun `packages/bun-uws/src/ChunkedEncoding.h:98–102` (hex), `218–230` (terminator), `156–183` (trailer); upstream bug `src/ChunkedEncoding.h:57` | `g`/`G`/`z` → `400`; `10` → `200/16` |

**Bottom line.** The confirmed `Bun.serve` cross-user smuggling is **caused by the vendored uWebSockets C++ `HttpParser` code path** — specifically the scenario-**A** empty-header-name / empty-key-sentinel logic that Bun ships **unchanged** from upstream `fe7c01a` and executes for every server request (Bun's own Zig/JS layer and the picohttp fetch-client parser are not involved). Scenarios **B** and **C** are **not** live in Bun because Bun maintains a **hardened fork** of uWS that patched the duplicate-`Content-Length` and chunk-size-hex bugs; both hardenings are Bun-authored and confirmed absent from upstream.
