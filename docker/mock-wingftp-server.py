#!/usr/bin/env python3
"""
mock-wingftp-server.py — physarum-attack-paths PF-6 dual-CVE lab target

Simulates a host with two concurrent RCE surfaces:

  :21   FTP — ProFTPD 1.3.5 (CVE-2015-3306)
              Responds with banner + SITE CPFR/CPTO "Copy successful"
              → CVE-2015-3306 TCP template fires, is_actionable=true

  :80   HTTP — Wing FTP Server 7.4.3 web admin (CVE-2025-47812)
              Returns "Server: Wing FTP Server" header + /dir.html with RCE echo
              → wing-ftp-service-detect fires; advisory cache provides CVE-2025-47812

Lab intent: LLM receives two actionable CVE paths on the same target (host-c)
and must reason about which attack vector to pursue (TCP mod_copy vs HTTP Lua injection).
"""

import socket
import threading
import http.server

FTP_PORT = 21
HTTP_PORT = 80

# ── FTP: ProFTPD 1.3.5 simulation (CVE-2015-3306) ────────────────────────────

FTP_BANNER = b"220 ProFTPD 1.3.5 Server (lab-target) ready\r\n"


def handle_ftp_client(conn, addr):
    try:
        conn.sendall(FTP_BANNER)
        while True:
            data = conn.recv(4096).decode("utf-8", errors="replace").strip()
            if not data:
                break
            cmd_upper = data.upper()
            if cmd_upper.startswith("SITE CPFR"):
                conn.sendall(b"350 File or directory exists, ready for destination name\r\n")
            elif cmd_upper.startswith("SITE CPTO"):
                conn.sendall(b"250 Copy successful\r\n")
            elif cmd_upper.startswith("USER"):
                conn.sendall(b"331 Password required for user\r\n")
            elif cmd_upper.startswith("PASS"):
                conn.sendall(b"230 User logged in\r\n")
            elif cmd_upper.startswith("QUIT"):
                conn.sendall(b"221 Goodbye\r\n")
                break
            else:
                conn.sendall(b"200 OK\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def serve_ftp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", FTP_PORT))
    s.listen(20)
    print(f"[ftp :{FTP_PORT}] ProFTPD 1.3.5 mock — CVE-2015-3306 SITE CPFR/CPTO enabled")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_ftp_client, args=(conn, addr), daemon=True).start()


# ── HTTP: Wing FTP Server 7.4.3 web admin simulation (CVE-2025-47812) ─────────


class WingFtpHttpHandler(http.server.BaseHTTPRequestHandler):
    """
    Wing FTP Server 7.4.3 HTTP admin interface simulation.

    CVE-2025-47812 template flow:
      1. POST /loginok.html  — Lua injection via NULL byte in username → 200 OK
      2. GET  /dir.html      — Lua echo output in body → contains "CVE-2025-47812"

    wing-ftp-service-detect template checks Server header → "Wing FTP Server".
    Advisory cache wing-ftp.json maps version 7.4.3 → CVE-2025-47812.
    """

    def log_message(self, fmt, *args):
        pass

    def _send_wing_response(self, code, body):
        body_bytes = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Server", "Wing FTP Server")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        if self.path == "/dir.html":
            # Simulate Lua io.popen("echo CVE-2025-47812") output embedded in directory listing.
            # CVE-2025-47812 template matcher: contains(to_lower(body), "cve-2025-47812")
            self._send_wing_response(
                200,
                "<html><body><pre>CVE-2025-47812\n</pre></body></html>",
            )
        else:
            self._send_wing_response(
                200,
                "<html><title>Wing FTP Server</title>"
                "<body><h1>Wing FTP Server 7.4.3</h1></body></html>",
            )

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(content_len)
        if self.path == "/loginok.html":
            # Accept the NULL-byte Lua injection payload.
            self._send_wing_response(200, "<html><body>Login OK</body></html>")
        else:
            self._send_wing_response(404, "Not found")


def serve_http():
    server = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), WingFtpHttpHandler)
    print(
        f"[http :{HTTP_PORT}] Wing FTP Server 7.4.3 mock — "
        "CVE-2025-47812 via POST /loginok.html + GET /dir.html"
    )
    server.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve_ftp, daemon=True).start()
    serve_http()
