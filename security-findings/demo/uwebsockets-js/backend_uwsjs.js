// Real uWebSockets.js HTTP back-end for the request-smuggling PoC.
//
// This is the SHIPPING npm package `uWebSockets.js` (pinned to tag v20.69.0),
// whose HTTP layer is upstream uWebSockets' C++ HttpParser compiled into a
// prebuilt .node binary. Nothing in this repo's src/ is compiled here -- the
// request parsing is done entirely by the released, unmodified library.
//
// Catch-all handler: for EVERY request the library parses it reports, to stderr
// AND in the response body, exactly what request line + headers it saw, so any
// cross-request / cross-user leakage is directly observable.
//
// Body contract expected by the existing Go clients (attacker.go / victim.go):
//
//     BACKEND-SAW method=<m> url=<u> cookie=<c> x-smuggled=<x>\n
//
// victim.go declares *** SMUGGLED *** when the response body it receives on its
// own connection contains BOTH "url=/steal" and "victim-secret-cookie".

const uWS = require('uWebSockets.js');
const fs = require('fs');
const path = require('path');

// Read the real installed version + bundled upstream commit off disk so the
// banner cannot drift from what is actually loaded. (The package's `exports`
// map blocks require('uWebSockets.js/package.json'), hence fs.)
let VERSION = 'unknown', COMMIT = 'unknown';
try {
  const base = path.dirname(require.resolve('uWebSockets.js'));
  VERSION = JSON.parse(fs.readFileSync(path.join(base, 'package.json'), 'utf8')).version;
  COMMIT = fs.readFileSync(path.join(base, 'source_commit'), 'utf8').trim();
} catch (_) {}

uWS.App().any('/*', (res, req) => {
  // req is only valid synchronously -- COPY every field out immediately.
  const method = req.getMethod();
  const url = req.getUrl();
  const cookie = req.getHeader('cookie');
  const smuggled = req.getHeader('x-smuggled');

  process.stderr.write(
    `[BACKEND] PARSED  method=${method} url=${url} ` +
      `cookie="${cookie}" x-smuggled="${smuggled}"\n`
  );

  // Guard against aborted connections (required by uWS.js or it can crash).
  res.onAborted(() => {});

  res.end(
    `BACKEND-SAW method=${method} url=${url} ` +
      `cookie=${cookie} x-smuggled=${smuggled}\n`
  );
}).listen('127.0.0.1', 9001, (token) => {
  if (token) {
    process.stderr.write(
      `[BACKEND] uWebSockets.js v${VERSION} (upstream commit ${COMMIT}) ` +
        `listening on 127.0.0.1:9001\n`
    );
  } else {
    process.stderr.write('[BACKEND] FAILED to listen on 9001\n');
    process.exit(1);
  }
});
