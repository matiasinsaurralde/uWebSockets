// Mitigation demonstration: a STRICT front-end parser (Go net/http, representative
// of a compliant reverse proxy / CDN) REJECTS the same requests that uWebSockets
// accepts -- so a strict front-end never forwards them, closing the smuggle.
package main

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
)

func tryParse(name, raw string) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		fmt.Printf("  [STRICT PROXY] %-28s -> REJECTED: %v\n", name, err)
		return
	}
	// If it parsed, try to read the body the way the chunked/CL machinery would.
	buf := make([]byte, 4096)
	n, berr := req.Body.Read(buf)
	if berr != nil && berr.Error() != "EOF" {
		fmt.Printf("  [STRICT PROXY] %-28s -> body REJECTED: %v\n", name, berr)
		return
	}
	fmt.Printf("  [STRICT PROXY] %-28s -> accepted (method=%s url=%s body=%q)\n",
		name, req.Method, req.URL.Path, string(buf[:n]))
}

func main() {
	CRLF := "\r\n"
	fmt.Println("How a STRICT front-end handles the same payloads uWebSockets mis-parses:")

	// F1: chunked size 'g'
	tryParse("F1 chunked 'g'=16",
		"POST / HTTP/1.1"+CRLF+"Host: t"+CRLF+"Transfer-Encoding: chunked"+CRLF+CRLF+
			"g"+CRLF+strings.Repeat("A", 16)+CRLF+"0"+CRLF+CRLF)

	// Empty header name
	tryParse("empty header name ':'",
		"POST /benign HTTP/1.1"+CRLF+"Host: t"+CRLF+":"+CRLF+"Content-Length: 5"+CRLF+CRLF+"AAAAA")

	// Duplicate Content-Length
	tryParse("duplicate Content-Length",
		"POST / HTTP/1.1"+CRLF+"Host: t"+CRLF+"Content-Length: 6"+CRLF+"Content-Length: 43"+CRLF+CRLF+"HELLO!")

	// A normal request, for contrast
	tryParse("normal request",
		"GET /account HTTP/1.1"+CRLF+"Host: t"+CRLF+CRLF)
}
