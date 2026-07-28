// Bun HTTP back-end for the request-smuggling validation harness.
//
// Mirrors ../networked/backend_uws.cpp: a catch-all handler that reports, to
// stderr AND in the response body, exactly what request line + headers Bun's
// HTTP layer PARSED, so cross-request / cross-user leakage is directly
// observable. The body format is the contract the existing Go victim.go /
// attacker.go clients expect:
//
//     BACKEND-SAW method=<m> url=<u> cookie=<c> x-smuggled=<x>\n
//
// victim.go declares SMUGGLED when the response body contains BOTH the
// substring "url=/steal" and "victim-secret-cookie".
//
// Bun.serve keeps the connection alive by default (HTTP/1.1 keep-alive), which
// is what lets vuln_proxy pool this one backend connection across clients.

let counter = 0;

const server = Bun.serve({
  port: 9001,
  hostname: "127.0.0.1",
  // Be permissive about body size / idle so nothing here masks a desync.
  fetch(req) {
    const id = ++counter;
    const method = req.method;
    const url = new URL(req.url).pathname;
    const cookie = req.headers.get("cookie") ?? "";
    const smuggled = req.headers.get("x-smuggled") ?? "";

    const line =
      `req#${id} method=${method} url=${url} ` +
      `cookie=${cookie} x-smuggled=${smuggled}`;
    process.stderr.write(`[BACKEND] PARSED  ${line}\n`);

    return new Response(
      `BACKEND-SAW method=${method} url=${url} ` +
        `cookie=${cookie} x-smuggled=${smuggled}\n`,
    );
  },
});

process.stderr.write(
  `[BACKEND] Bun ${Bun.version} (${Bun.revision}) listening on ` +
    `${server.hostname}:${server.port}\n`,
);
