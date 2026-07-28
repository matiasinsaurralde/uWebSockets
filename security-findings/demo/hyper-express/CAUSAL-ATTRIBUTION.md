# Causal Attribution — hyper-express HTTP Request Smuggling → uWebSockets C++ Parser

**Question answered:** Is the confirmed cross-user request smuggling in the `hyper-express`
back-end caused by the **uWebSockets C++ HTTP parser** (reached through the `uWebSockets.js`
native addon), and *not* by anything in hyper-express's own JavaScript?

**Verdict: YES.** hyper-express performs **no HTTP parsing of its own**. It registers its route
handlers directly on the native uWS `App`, and reads the request line, headers, and body solely
through the native addon (`getUrl` / `getMethod` / `getQuery` / `getHeader` / `forEach` /
`onDataV2`). Every one of the three smuggling primitives (A, B, C) is decided in the uWS C++
core (`HttpParser.h`, `ChunkedEncoding.h`) *before* hyper-express JS ever runs, and hyper-express
adds no validation that would catch A/B and no parser that would alter C. The app is vulnerable
exactly to the degree `uWebSockets.js` is.

This report distinguishes **proven-from-source** (exact `file:line` in code that is byte-identical
to what the running binary was compiled from) versus **binary-confirmed** (the team's differential
probe against the loaded `.node`). Scenarios A and B are proven-from-source; C is both
proven-from-source and binary-confirmed.

---

## 0. Provenance — the exact C++ compiled into the PoC's binary

The strength of this attribution rests on a verified chain from the installed addon down to the
exact C++ source lines cited below. Each link was checked firsthand in this session.

| Link | Value | How verified |
|---|---|---|
| PoC's installed addon version | `uWebSockets.js` **20.69.0** | `node_modules/uWebSockets.js/package.json` |
| PoC addon `source_commit` | `faf115275bb9c55edf739a06406849e42e89ec04` | `node_modules/uWebSockets.js/source_commit` |
| `uWebSockets.js` git tag `v20.69.0` → `source_commit` | `faf1152…` (**identical**) | shallow clone of tag; `source_commit` file + identical prebuilt `.node` sizes |
| `uWebSockets.js` @ `faf1152` → uWS core submodule pin | **`fe7c01a477b688a7743f754fee33bdd78d52ad91`** | `git fetch` by SHA; `.gitmodules` + `git ls-tree HEAD uWebSockets` → `160000 commit fe7c01a…` |
| uWS core @ `fe7c01a` `HttpParser.h` vs this repo `src/HttpParser.h` | **SHA256-identical** `35ace54045957b4042108688ed763b78ad257fcafc9d8851d780b0ef24fe0125` | `git fetch` uWebSockets @ `fe7c01a`; `diff` + `sha256sum` |
| uWS core @ `fe7c01a` `ChunkedEncoding.h` vs this repo `src/ChunkedEncoding.h` | **SHA256-identical** `7c98fc4e7bd9ba9892e32f94eb687c65fc72cd17111631cba44c76cb2323251f` | same |

**Conclusion of §0:** The `v20.69.0` binary that hyper-express loads was built from
`uWebSockets.js@faf1152`, which vendors the uWS C++ core at `fe7c01a`, whose `HttpParser.h` and
`ChunkedEncoding.h` are byte-for-byte this repo's `src/` files. Therefore the line numbers cited
below (from `/home/user/uWebSockets/src/`) are the *actual* code paths compiled into the PoC's
parser. This is the tag's own submodule pin — `fe7c01a` is not merely "close to" the analyzed
source, it *is* the analyzed source. (Relation to any other reference commit is moot: the tag pins
`fe7c01a` directly, and its content matches.)

---

## 1. hyper-express does NO HTTP parsing of its own

### 1.1 The server *is* a uWS App; routes are bound directly on it

`components/Server.js`:
- **`Server.js:4`** — `const uWebSockets = require('uWebSockets.js');`
- **`Server.js:186` / `Server.js:188`** — the server instance is a native uWS app:
  `this.#uws_instance = uWebSockets.SSLApp(this.#options)` / `uWebSockets.App(this.#options)`.
- **`Server.js:693-695`** — every route handler is registered **directly on the native uWS app**,
  and the native app invokes it with the already-parsed native `(response, request)`:
  ```js
  return this.#uws_instance[method](pattern, (response, request) => {
      this._handle_uws_request(route, request, response, null);
  });
  ```
  By the time this callback fires, the uWS C++ `HttpParser` has already consumed the request line,
  parsed all headers, and decided the body-framing state (`remainingStreamingBytes`).

### 1.2 The wrapper reads everything from the native request — it does not re-derive anything

`components/http/Request.js` constructor, **`Request.js:73-77`**:
```js
this._query  = raw_request.getQuery();                 // native
this._path   = route.path || raw_request.getUrl();     // native
this._method = route.method !== 'ANY' ? route.method : raw_request.getMethod(); // native
raw_request.forEach((key, value) => (this.headers[key] = value)); // native header enumeration
```
- URL/path — from native `getUrl()` (no request-line parsing in JS).
- Method — from native `getMethod()`.
- Query — from native `getQuery()`.
- Headers — the entire `this.headers` map is populated **only** by the native `forEach` iterator
  (`Request.js:77`). There is no JS tokenizer that splits raw header bytes on `:` or `\r\n`.

### 1.3 The body is received solely through the native `onDataV2` callback

`components/http/Request.js`:
- **`Request.js:253`** — the single native body consumer:
  `this._raw_response.onDataV2((chunk, max_remaining_body_length) => { … })`.
- **`Request.js:344-388`** (`_body_parser_on_chunk`) — the "is this the last chunk / is the body
  complete?" decision is taken **entirely from the native hint**:
  `const is_last = max_remaining_body_length === 0n;` (`Request.js:345`), and `this.received = true`
  is set only when the native callback reports `is_last` (`Request.js:381-382`). hyper-express never
  counts bytes against a Content-Length to find the body boundary and never de-chunks a chunked
  body — the native parser delivers already-de-framed bytes.

**There is no independent request-line, header, or chunked-body parser anywhere in hyper-express's
JS.** A tree-wide sweep for the relevant tokens returns only:
- Response-side (outgoing) Content-Length / chunked handling in `components/http/Response.js`
  (e.g. `Response.js:456,485,660,758,774`) — this shapes hyper-express's *own responses*, not
  inbound request parsing, and is irrelevant to smuggling of inbound requests.
- SSE output sanitisation in `components/plugins/SSEventStream.js:41,104,108` — response-side.
- Route-pattern matching on `:`/`*` in `components/router/Router.js:403` — URL routing, not HTTP framing.
- The **only** inbound CL/TE read: `Request.js:234-235` (analysed in §4.2 — used for buffer
  pre-sizing and the byte-limit check, never for body framing).

### 1.4 Dispatch path summary

`Server.js:842-864` (`_handle_uws_request`): wraps the native objects
(`new Request(route, uws_request)`, `new Response(uws_response)`), calls
`request._body_parser_run(response, route.max_body_length)` (`Server.js:863`), then
`route.handle(request, response)` (`Server.js:864`). No parsing occurs here — only lifecycle
plumbing over values the native parser already produced.

---

## 2. The uWebSockets.js addon is a thin binding over the uWS C++ parser

Source read at `uWebSockets.js@faf1152` (`src/HttpRequestWrapper.h`, `src/HttpResponseWrapper.h`).
Every accessor hyper-express uses is a direct pass-through to `uWS::HttpRequest` /
`uWS::HttpResponse`; the binding does zero HTTP parsing and only marshals `std::string_view` ↔ V8.

| JS call (used by hyper-express) | Addon binding | Native call | No-reparse evidence |
|---|---|---|---|
| `req.getUrl()` | `HttpRequestWrapper.h:87-95` | `req->getUrl()` (`:91`) | returns the `std::string_view` verbatim as a V8 string |
| `req.getMethod()` | `HttpRequestWrapper.h:130-138` | `req->getMethod()` (`:134`) | verbatim |
| `req.getQuery()` | `HttpRequestWrapper.h:153-178` | `req->getQuery()` (`:168`) | verbatim |
| `req.getHeader(k)` | `HttpRequestWrapper.h:99-113` | `req->getHeader(k)` (`:108`) | verbatim (first-match value; see B) |
| `req.forEach(cb)` | `HttpRequestWrapper.h:46-59` | `for (auto p : *req)` (`:52`) | iterates the uWS `HttpRequest` **HeaderIterator directly** — same begin/end that stop at the empty-name sentinel (see A) |
| `res.onDataV2(cb)` | `HttpResponseWrapper.h:196-217` | `res->onDataV2(...)` (`:203`) | forwards `(data, maxRemainingBodyLength)` straight from the parser's `dataHandler`; wraps `data` as a zero-copy ArrayBuffer (`:206`), no inspection |

Key consequence: because `req.forEach` (`HttpRequestWrapper.h:52`) walks the **native**
`HttpRequest` header iterator, hyper-express's `this.headers` map inherits the C++ parser's exact
header set — including the empty-name truncation (A) and the last-duplicate-wins ordering that the
iterator produces for JS (see §4.2). The binding cannot and does not "repair" any parser quirk.

---

## 3. The three uWS C++ defects (exact lines, byte-identical to the compiled binary)

Citations are `/home/user/uWebSockets/src/HttpParser.h` and `.../ChunkedEncoding.h`, proven
byte-identical to the `fe7c01a` core compiled into `v20.69.0` (§0).

### A — Empty header name (`:`) acts as an end-of-headers sentinel, hiding `Content-Length`

1. **Empty name is accepted and stored (not rejected).** For a header line beginning with `:`,
   `consumeFieldName` returns immediately at the colon (`HttpParser.h:274` — `if (*p == ':') return`),
   so the stored key has length 0. The very next check, **`HttpParser.h:401`**
   (`if (postPaddedBuffer[0] != ':')`), *passes* because the byte is `:`; no rule rejects a
   zero-length key. The empty-key header is then stored and the loop advances
   (`HttpParser.h:433,446`).
2. **A zero-length key terminates every header lookup/iteration.** `getHeader` loops
   `for (Header *h = headers; (++h)->key.length(); )` — **`HttpParser.h:117`** — stopping at the
   first empty key. The `HeaderIterator` used by `forEach` has the same semantics
   (`HttpParser.h:84-90` `operator!=`, `:102-108` begin/end). So any real header **after** the
   injected `:` line is invisible.
3. **Body consequence.** At **`HttpParser.h:524`**,
   `contentLengthString = req->getHeader("content-length")` returns empty (blinded by the sentinel).
   With no CL and no TE, control falls to the `else` at **`HttpParser.h:600-603`**
   (`dataHandler(user, {}, 0);`) — the parser declares a **zero-length body**. The bytes the
   attacker declared via the hidden `Content-Length` are left unconsumed in the socket buffer and
   are re-parsed as the **next** pipelined request → smuggle. (`Host` still validates at
   `HttpParser.h:514` when placed before the `:` line, so the request is accepted.)

### B — Duplicate `Content-Length` → first value wins, no rejection

1. **First match wins.** `getHeader` returns on the first matching header:
   **`HttpParser.h:117-119`** (`return h->value;` inside the scan loop). Two `Content-Length`
   headers ⇒ the **first** value is used.
2. **No duplicate-CL rejection.** The only duplicate-header guard rejects a repeated **Host**
   (`HttpParser.h:506-508`); there is no equivalent for `Content-Length`. The RFC 9112 §6.3
   guard at `HttpParser.h:525-530` only fires when TE *and* CL are both present — it does nothing
   for two CLs.
3. **Body framing uses the first CL.** `remainingStreamingBytes = toUnsignedInteger(contentLengthString)`
   (**`HttpParser.h:585`**) then consumes exactly that many body bytes (**`HttpParser.h:591-599`**).
   A front-end that honours the *second* CL disagrees with uWS's *first*-CL boundary → the trailing
   bytes are smuggled into the next request.

### C — Chunk-size hex parser off-by-one (`> 16` should be `> 15`)

**`ChunkedEncoding.h:57`** — `if (number > 16 || (chunkSize(state) & STATE_SIZE_OVERFLOW))`.
A valid hex digit is 0–15; the bound must be `> 15`. Because it is `> 16`, the value **16** is
accepted as a legal digit. The digit-normalisation just above
(**`ChunkedEncoding.h:48-55`**: `if (digit >= 'a') digit -= 39; else if (digit >= 'A') digit -= 7;`
then `number = digit - '0'`) maps three non-hex bytes to exactly 16:
- `g` (0x67) → 0x67−39 = 64 → 64−'0' = **16** (accepted)
- `G` (0x47) → 0x47−7 = 64 → **16** (accepted)
- `@` (0x40) → 64 → **16** (accepted)
- control: `f` → 15 (valid); `z` → 35 (>16 → `STATE_IS_ERROR` → 400)

This path is entered whenever `Transfer-Encoding` is present
(**`HttpParser.h:568,573`** → `uWS::ChunkIterator` → `consumeHexNumber`). Corrupting the chunk-size
grammar this way lets an attacker inject a chunk length the front-end and back-end interpret
differently, desyncing the connection — observed as request desync / DoS in hyper-express.

---

## 4. Ruling out hyper-express as an independent cause

### 4.1 hyper-express adds no validation that would catch A or B, and no parser that changes C

- It never inspects raw header bytes (headers come pre-tokenised from native `forEach`,
  `Request.js:77`), so it cannot notice the empty-name sentinel (A) or a duplicate `Content-Length`
  (B) — both are already collapsed by the C++ parser before JS sees them.
- It never de-chunks a body (chunked bytes are de-framed natively and delivered via `onDataV2`),
  so it has no chunk-size grammar of its own that could reject or "fix" `g`/`G`/`@` (C).
- There is no CL/TE conflict check, no duplicate-CL check, and no chunk validation anywhere in the
  hyper-express request path (§1.3 sweep). The app inherits the parser's decisions unchanged.

### 4.2 The one benign JS/native divergence (does not change the outcome)

hyper-express's `this.headers` map is built by assigning on each `forEach` iteration
(`Request.js:77`: `this.headers[key] = value`), so for a duplicate header the **last** value wins
in the JS map. In `_body_parser_run`, **`Request.js:234`**
(`const content_length = Number(this.headers['content-length'])`) therefore reads the **last** CL,
while native uWS frames the body from the **first** CL (§3-B, `HttpParser.h:585`).

This divergence is **inert** for the smuggle because the JS value is used only to *pre-size the
receive buffer and enforce the byte limit* — never to decide the body boundary:
- `declared_length` seeds `_body_expected_bytes` as an allocation hint (`Request.js:238-245`).
- The authoritative length is continuously overwritten from the **native** hint
  (`Request.js:352-359`: `_body_expected_bytes = Math.max(_body_expected_bytes, received + max_remaining_body_length)`),
  and body completion is signalled **only** by the native `max_remaining_body_length === 0n`
  (`Request.js:345,381-382`).
- The delivered body is sliced to the bytes actually received (`buffer.subarray(0, offset)`,
  `Request.js:481`).

So whichever CL the JS map happens to show, the number of body bytes hyper-express actually consumes
— and thus where the request ends on the wire — is dictated by the native first-CL framing. The JS
last-wins map cannot move the smuggle boundary. (For scenario A the JS map and native framing
*agree*: the `forEach` iterator stops at the same empty-name sentinel, so hyper-express's map also
lacks `content-length` — it neither detects nor prevents the truncation.)

---

## 5. Scenario → uWS C++ line mapping

| Scenario | Observed hyper-express outcome | Root-cause C++ lines | One-line mechanism |
|---|---|---|---|
| **A** — empty-name `:` header hides `Content-Length` | **SMUGGLED** | `HttpParser.h:274,401` (empty key accepted) + `:117`/`:84-90,102-108` (zero-len key = end-of-headers sentinel) + `:524,600-603` (CL invisible ⇒ zero-length body ⇒ declared bytes reparsed as next request) | The `:`-header truncates header lookup, so uWS sees no Content-Length and leaves the body bytes to be parsed as a second request. |
| **B** — duplicate `Content-Length`, first wins | **SMUGGLED** | `HttpParser.h:117-119` (getHeader returns first match) + no dup-CL guard (`:506-508` guards Host only) + `:585,591-599` (body framed from first CL) | uWS silently frames the body using the first CL; a front-end honouring the second CL desyncs, leaking the remainder into the next request. |
| **C** — chunk-size accepts `g`/`G`/`@` as 16 | **desync / DoS** | `ChunkedEncoding.h:57` (`> 16`, must be `> 15`) + `:48-55` (`g`/`G`/`@` normalise to 16); reached via `HttpParser.h:568,573` | Off-by-one accepts value 16 as a hex digit, so non-hex bytes forge chunk sizes and desync chunk framing. |

---

## 6. Verdict

| Scenario | Caused by the uWebSockets code path (via uWebSockets.js)? | Backing citation | hyper-express contributes |
|---|---|---|---|
| **A** (empty-name sentinel) | **YES — proven-from-source** | `HttpParser.h:274,401,117,84-90,102-108,514,524,600-603` (byte-identical to compiled `fe7c01a`, §0); reached via `HttpRequestWrapper.h:52` / `Request.js:77` | **nothing** — no header-byte inspection; JS map is blinded by the same native sentinel |
| **B** (dup-CL first-wins) | **YES — proven-from-source** | `HttpParser.h:117-119,506-508,585,591-599` (byte-identical, §0); reached via `HttpResponseWrapper.h:203` / `Request.js:253` | **only** a benign last-wins `req.headers` map used for buffer sizing/limits (`Request.js:234`), which cannot move the native body boundary (§4.2) |
| **C** (chunk-size `>16` off-by-one) | **YES — proven-from-source *and* binary-confirmed** | `ChunkedEncoding.h:57,48-55` (byte-identical, §0); native binary probe: `g`/`G`/`10` → 200 + 16-byte body, `z` → 400 | **nothing** — no chunk parser in JS; native `onDataV2` delivers the desynced framing |

**Overall:** hyper-express 7.0.2 is a thin JS lifecycle layer over `uWebSockets.js` v20.69.0, which
is a thin V8 binding over the uWS C++ `HttpParser` at `fe7c01a`. All three smuggling primitives are
decided in that C++ core before any hyper-express code executes, and hyper-express adds no
mitigating validation and no independent parser. The confirmed cross-user request smuggling is
**caused by the uWebSockets HTTP parser code path reached through uWebSockets.js** — hyper-express
itself does no HTTP parsing and is neither an independent cause nor a barrier.
