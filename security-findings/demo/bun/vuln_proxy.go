// vuln_proxy: a REAL TCP reverse proxy that is vulnerable to request smuggling
// because it (a) reuses ONE pooled connection to the back-end across all clients
// and (b) forwards each client request byte-for-byte after framing it with its
// OWN parser, without re-normalizing. This models a lenient CDN / load-balancer.
//
// Listens on :8080, pools one connection to the back-end (default :9001).
//
// Framing rules (deliberately lenient, so parser disagreements survive):
//   * Content-Length present  -> read exactly that many body bytes (LAST value wins).
//   * Transfer-Encoding chunked -> stream the body until the terminating "0\r\n\r\n"
//                                  is seen (does NOT re-validate individual chunk sizes).
//   * otherwise                -> no body.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type pool struct {
	mu sync.Mutex
	bc net.Conn
	br *bufio.Reader
}

// readHeaders reads up to and including CRLFCRLF. Returns raw bytes, last
// Content-Length (or -1), and whether Transfer-Encoding: chunked was present.
func readHeaders(r *bufio.Reader) (raw []byte, cl int, chunked bool, err error) {
	cl = -1
	for {
		var line []byte
		line, err = r.ReadBytes('\n')
		if len(line) > 0 {
			raw = append(raw, line...)
		}
		if err != nil {
			return
		}
		t := strings.TrimRight(string(line), "\r\n")
		if t == "" {
			return
		}
		if i := strings.IndexByte(t, ':'); i > 0 {
			name := strings.ToLower(strings.TrimSpace(t[:i]))
			val := strings.TrimSpace(t[i+1:])
			switch name {
			case "content-length":
				if n, e := strconv.Atoi(val); e == nil {
					cl = n // last one wins
				}
			case "transfer-encoding":
				if strings.Contains(strings.ToLower(val), "chunked") {
					chunked = true
				}
			}
		}
	}
}

func readCL(r *bufio.Reader, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	b := make([]byte, n)
	got := 0
	for got < n {
		m, err := r.Read(b[got:])
		got += m
		if err != nil {
			return b[:got], err
		}
	}
	return b, nil
}

// readChunkedUntilTerminator streams bytes until the "0\r\n\r\n" last-chunk
// marker is observed (lenient: it does not parse individual chunk sizes).
func readChunkedUntilTerminator(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	term := []byte("0\r\n\r\n")
	for {
		b, err := r.ReadByte()
		if err != nil {
			return buf, err
		}
		buf = append(buf, b)
		if bytes.HasSuffix(buf, term) {
			return buf, nil
		}
		if len(buf) > 1<<20 {
			return buf, fmt.Errorf("chunked body too large")
		}
	}
}

func (p *pool) handle(c net.Conn) {
	defer c.Close()
	cr := bufio.NewReader(c)
	head, cl, chunked, err := readHeaders(cr)
	if err != nil || len(head) == 0 {
		return
	}
	var body []byte
	switch {
	case chunked:
		body, _ = readChunkedUntilTerminator(cr)
	case cl > 0:
		body, _ = readCL(cr, cl)
	}
	req := append(append([]byte{}, head...), body...)
	fmt.Printf("[VULN-PROXY] framed a %d-byte request (cl=%d chunked=%v); forwarding VERBATIM over the ONE pooled backend conn\n", len(req), cl, chunked)

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.bc.Write(req); err != nil {
		fmt.Println("[VULN-PROXY] backend write err:", err)
		return
	}
	// Read exactly one response (status+headers, then CL body) and relay it.
	rhead, rcl, _, err := readHeaders(p.br)
	if err != nil {
		fmt.Println("[VULN-PROXY] backend read err:", err)
		return
	}
	rbody, _ := readCL(p.br, rcl)
	c.Write(rhead)
	c.Write(rbody)
}

func main() {
	backend := "127.0.0.1:9001"
	listen := "127.0.0.1:8080"
	if len(os.Args) > 1 {
		backend = os.Args[1]
	}
	if len(os.Args) > 2 {
		listen = os.Args[2]
	}
	bc, err := net.Dial("tcp", backend)
	if err != nil {
		fmt.Println("[VULN-PROXY] cannot reach backend:", err)
		os.Exit(1)
	}
	p := &pool{bc: bc, br: bufio.NewReader(bc)}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Println("[VULN-PROXY] bind err:", err)
		os.Exit(1)
	}
	fmt.Printf("[VULN-PROXY] listening on %s -> ONE pooled backend conn %s\n", listen, backend)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		p.handle(c) // serial: one shared backend conn (models sequential arrival on a pooled conn)
	}
}
