# End-to-end HTTP request-smuggling demo (real uWebSockets back-end)

This demonstrates, with running code, that the HTTP-parsing deviations documented in
`../FINDINGS.md` produce a **real cross-user request smuggle** when uWebSockets sits
behind a connection-pooling reverse proxy — and that a **strict front-end mitigates it**.

## Run it

```
./run.sh
```

(Requires `g++` C++17, `go`, and the `uSockets` submodule checked out. It builds a real
uWebSockets server and drives it over TCP.)

## The four actors

| Actor | What it is |
|-------|-----------|
| **uWebSockets back-end** | `backend_uws.cpp` — a real uWS HTTP server (catch-all route) that reports the method / URL / `Cookie` / `X-Smuggled` header of every request it **parses**. |
| **Vulnerable proxy** | in `demo.go` — reuses **one** pooled back-end connection across all clients and forwards each client request **verbatim** after framing it by `Content-Length` (models a lenient CDN/LB; the front-end↔proxy hop is in-process only because this sandbox blocks a second listener — the proxy↔back-end path is real TCP). |
| **Attacker** | sends one crafted request. |
| **Victim** | sends one normal request moments later, over the same pooled connection. |

## What the exploit does

The attacker's single request contains an **empty header name** (`:` on its own line).
uWebSockets' `getHeader` treats the empty key as the end-of-headers sentinel, so it never
sees the following `Content-Length` and concludes the request is **body-less**. The proxy,
however, does see the `Content-Length` and forwards the declared "body" — which is actually
a **smuggled request prefix** (`GET /steal … X-Smuggled: `, ending mid-header). uWS parses
that prefix as the start of the *next* request and waits.

When the victim's `GET /account` (with `Cookie: victim-secret-cookie`) arrives on the same
pooled connection, uWS **appends** it to the buffered prefix, completing:

```
GET /steal HTTP/1.1
X-Smuggled: GET /account HTTP/1.1      <- victim's request-line captured
Host: t
Cookie: victim-secret-cookie           <- victim's session captured
```

**Observed result:** the victim receives the response for `/steal`, and the back-end log
shows it parsed `url=/steal cookie="victim-secret-cookie" x-smuggled="GET /account HTTP/1.1"`.
The victim's credentials were smuggled into an attacker-controlled request.

The same effect is reproducible with the duplicate-`Content-Length` and (via a chunk-size
disagreement) the F1 chunked-`g` deviations; see `probe.go` for a raw two-burst probe
straight at the back-end.

## The mitigation

`mitigation.go` feeds the identical payloads to a **strict** parser (Go `net/http`,
representative of a compliant proxy). It **rejects all of them**:

```
F1 chunked 'g'=16        -> REJECTED: invalid byte in chunk length
empty header name ':'    -> REJECTED: malformed MIME header line
duplicate Content-Length -> REJECTED: multiple Content-Length headers
normal request           -> accepted
```

So the attack is closed either by making **uWebSockets** parse strictly (reject these
inputs itself — the proper fix for the planted bugs) **or** by a **strict front-end** that
rejects/normalizes ambiguous requests before forwarding. Not pooling the back-end
connection across users removes the cross-user step entirely. Defense on both ends is best.
