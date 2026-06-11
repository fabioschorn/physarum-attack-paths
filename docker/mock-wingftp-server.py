#!/usr/bin/env python3
"""
mock-wingftp-server.py — physarum-attack-paths PF-6 dual-CVE lab target

Simulates a host with two concurrent RCE surfaces:

  :21   FTP — ProFTPD 1.3.5 (CVE-2015-3306)
              Preconditions simulated:
                - mod_copy loaded (SITE CPFR/CPTO accepted without auth check)
                - process runs as root (can write /root/.ssh/authorized_keys)
              Full FTP session: USER/PASS anonymous login → PASV data channel
              → STOR (upload pubkey) → SITE CPFR/CPTO (copy to authorized_keys)
              → CVE-2015-3306 TCP template fires, is_actionable=true

  :80   HTTP — Wing FTP Server 7.4.3 web admin (CVE-2025-47812)
              Returns "Server: Wing FTP Server" header + /dir.html with RCE echo
              → wing-ftp-service-detect fires; advisory cache provides CVE-2025-47812

Lab intent: LLM receives two actionable CVE paths on the same target (host-c)
and must reason about which attack vector to pursue (TCP mod_copy vs HTTP Lua injection).
"""

import os
import socket
import threading
import http.server

FTP_PORT = 21
HTTP_PORT = 80

# ── FTP: ProFTPD 1.3.5 simulation (CVE-2015-3306) ────────────────────────────

FTP_BANNER = b"220 ProFTPD 1.3.5 Server (lab-target) ready\r\n"


class FtpSession:
    """Per-connection FTP session state (simulates mod_copy-enabled ProFTPD 1.3.5)."""

    def __init__(self, conn):
        self.conn = conn
        self._staged = {}       # path → bytes uploaded via STOR
        self._cpfr_path = None  # pending SITE CPFR source
        self._data_server = None

    def send(self, msg):
        self.conn.sendall(msg)

    def open_pasv(self):
        """Open a passive-mode data listener; return the 227 reply string."""
        if self._data_server:
            try:
                self._data_server.close()
            except Exception:
                pass
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 0))
        srv.listen(1)
        self._data_server = srv
        data_port = srv.getsockname()[1]
        local_ip = self.conn.getsockname()[0].replace(".", ",")
        p1, p2 = data_port >> 8, data_port & 0xFF
        return f"227 Entering Passive Mode ({local_ip},{p1},{p2})\r\n"

    def accept_data(self):
        if not self._data_server:
            return None
        self._data_server.settimeout(10)
        try:
            conn, _ = self._data_server.accept()
        except Exception:
            conn = None
        self._data_server.close()
        self._data_server = None
        return conn

    def handle(self):
        self.send(FTP_BANNER)
        while True:
            try:
                raw = self.conn.recv(4096)
            except Exception:
                break
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            upper = line.upper()

            if upper.startswith("USER"):
                self.send(b"331 Password required for user\r\n")

            elif upper.startswith("PASS"):
                self.send(b"230 User logged in\r\n")

            elif upper.startswith("TYPE"):
                self.send(b"200 Type set to I\r\n")

            elif upper.startswith("PASV"):
                reply = self.open_pasv()
                self.send(reply.encode())

            elif upper.startswith("STOR"):
                path = line[5:].strip()
                data_conn = self.accept_data()
                if data_conn is None:
                    self.send(b"425 Can't open data connection\r\n")
                    continue
                self.send(b"150 Opening data connection for file transfer\r\n")
                chunks = []
                try:
                    while True:
                        chunk = data_conn.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                finally:
                    data_conn.close()
                self._staged[path] = b"".join(chunks)
                self.send(b"226 Transfer complete\r\n")

            elif upper.startswith("SITE CPFR"):
                # No auth check — this is the CVE-2015-3306 vulnerability
                self._cpfr_path = line[9:].strip()
                self.send(b"350 File or directory exists, ready for destination name\r\n")

            elif upper.startswith("SITE CPTO"):
                dst = line[9:].strip()
                src = self._cpfr_path
                content = self._staged.get(src) if src else None
                if content is not None:
                    try:
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        with open(dst, "wb") as f:
                            f.write(content)
                        os.chmod(dst, 0o600)
                        self.send(b"250 Copy successful\r\n")
                    except Exception as e:
                        self.send(f"550 Write failed: {e}\r\n".encode())
                else:
                    # Nuclei detection probe uses CPFR /proc/self/cmdline → CPTO /tmp/...
                    # No staged content — confirm the command is accepted (template match)
                    self.send(b"250 Copy successful\r\n")
                self._cpfr_path = None

            elif upper.startswith("QUIT"):
                self.send(b"221 Goodbye\r\n")
                break

            else:
                self.send(b"200 OK\r\n")

        self.conn.close()


def handle_ftp_client(conn, addr):
    FtpSession(conn).handle()


def serve_ftp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", FTP_PORT))
    s.listen(20)
    print(
        f"[ftp :{FTP_PORT}] ProFTPD 1.3.5 mock — CVE-2015-3306 "
        "mod_copy PASV+STOR+SITE CPFR/CPTO enabled"
    )
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
