// strict_proxy: a MITIGATING reverse proxy built on Go's net/http, which parses
// (and thereby validates + re-normalizes) every request before forwarding. The
// malformed smuggling requests are rejected with 400 by the HTTP server layer
// before they ever reach the back-end, so the smuggle is closed.
//
// Listens on :8081, forwards accepted requests to the back-end (default :9001).
package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func main() {
	backend := "http://127.0.0.1:9001"
	listen := "127.0.0.1:8081"
	if len(os.Args) > 1 {
		backend = os.Args[1]
	}
	if len(os.Args) > 2 {
		listen = os.Args[2]
	}
	target, _ := url.Parse(backend)
	rp := httputil.NewSingleHostReverseProxy(target)
	fmt.Printf("[STRICT-PROXY] listening on %s -> %s (validates+normalizes; malformed => 400)\n", listen, backend)
	// http.Server rejects malformed requests (empty header name, duplicate
	// Content-Length, invalid chunk size) with 400 before this handler runs.
	if err := http.ListenAndServe(listen, rp); err != nil {
		fmt.Println("[STRICT-PROXY]", err)
		os.Exit(1)
	}
}
