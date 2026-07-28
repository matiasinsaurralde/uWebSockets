// victim: sends ONE normal request through the proxy, moments after the attacker,
// over the same pooled back-end connection. Usage: victim <proxyAddr>
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// readAll accumulates the response until a short idle timeout.
func readAll(c net.Conn) string {
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
	return string(out)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: victim <proxyAddr>")
		os.Exit(2)
	}
	addr := os.Args[1]
	CRLF := "\r\n"
	req := "GET /account HTTP/1.1" + CRLF + "Host: t" + CRLF +
		"Cookie: victim-secret-cookie" + CRLF + CRLF
	fmt.Println("[VICTIM] sending a normal:  GET /account   (Cookie: victim-secret-cookie)")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("[VICTIM] dial err:", err)
		os.Exit(1)
	}
	defer c.Close()
	c.Write([]byte(req))
	resp := readAll(c)
	fmt.Printf("[VICTIM] response:\n%s\n", resp)
	switch {
	case strings.Contains(resp, "url=/steal") && strings.Contains(resp, "victim-secret-cookie"):
		fmt.Println("[VICTIM] *** SMUGGLED *** -> the victim was served the attacker's /steal")
		fmt.Println("         request, and the victim's own cookie was captured into it.")
	case strings.Contains(resp, "url=/account"):
		fmt.Println("[VICTIM] clean: victim received its own /account response.")
	case strings.TrimSpace(resp) == "":
		fmt.Println("[VICTIM] *** DENIED (DoS) *** -> no response: the attacker's malformed")
		fmt.Println("         request desynced and poisoned/closed the pooled backend connection.")
	default:
		fmt.Println("[VICTIM] desynced/other: see response above and the backend log.")
	}
}
