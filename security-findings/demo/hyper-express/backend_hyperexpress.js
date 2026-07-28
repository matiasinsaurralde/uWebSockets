// Real hyper-express HTTP back-end for the request-smuggling demo.
//
// hyper-express is a thin high-level framework on top of uWebSockets.js (the
// Node binding of the same uWebSockets C++ core audited in ../../FINDINGS.md).
// A single catch-all `any('/*')` route reports exactly what method / URL /
// Cookie / X-Smuggled header hyper-express (and therefore uWS) PARSED for every
// request, so cross-request/user leakage is directly observable on the wire.
//
// Response body format is kept byte-compatible with the C++ back-end so the
// existing victim.go check (greps for `url=/steal` and `victim-secret-cookie`)
// works unchanged:
//     BACKEND-SAW method=<m> url=<u> cookie=<c> x-smuggled=<x>\n
//
// Listens on 127.0.0.1:9001 (HTTP/1.1 keep-alive, fixed Content-Length — the
// pooled vuln_proxy reuses the one back-end connection and reads exactly one
// Content-Length-framed response per request).

const HyperExpress = require('hyper-express');

const s = new HyperExpress.Server();

let counter = 0;

s.any('/*', (req, res) => {
    const id = ++counter;

    // hyper-express caches these straight out of the uWS HttpRequest:
    //   req.method       <- uWS raw_request.getMethod()
    //   req.path         <- uWS raw_request.getUrl()
    //   req.headers[...] <- uWS raw_request.forEach((k,v)=>headers[k]=v)
    const method = req.method;
    const url = req.path; // path only, mirrors the C++ getUrl()
    const cookie = req.headers['cookie'] || '';
    const smuggled = req.headers['x-smuggled'] || '';

    const parsed =
        'req#' + id +
        ' method=' + method +
        ' url=' + url +
        ' cookie=' + cookie +
        ' x-smuggled=' + smuggled;

    // Ground-truth log of what uWS/hyper-express actually parsed.
    process.stderr.write('[BACKEND] PARSED  ' + parsed + '\n');

    // Exact body format the harness greps.
    res.send(
        'BACKEND-SAW method=' + method +
        ' url=' + url +
        ' cookie=' + cookie +
        ' x-smuggled=' + smuggled + '\n'
    );
});

s.listen(9001, '127.0.0.1')
    .then(() => {
        process.stderr.write('[BACKEND] hyper-express (uWebSockets.js) listening on 127.0.0.1:9001\n');
    })
    .catch((err) => {
        process.stderr.write('[BACKEND] FAILED to listen on 9001: ' + err + '\n');
        process.exit(1);
    });
