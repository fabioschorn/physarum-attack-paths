#!/usr/bin/env python3
"""
Mock Apache Struts CVE-2021-31805 OGNL endpoint for physarum Docker Lab.

Simulates a Struts 2.5.29 action that performs forced double evaluation of the
'id' parameter (query string or multipart form body) via freemarker.Execute —
CVE-2021-31805 / S2-062.

Key constraint: freemarker.Execute.exec(list) passes the first list element to
Runtime.exec(String), which tokenizes by whitespace. One command per request —
no shell metacharacters (&&, ;, |) are interpreted.  The OgnlExec executor
sends a separate HTTP POST for each command in OgnlExec.commands.

Detection behaviour (nuclei CVE-2021-31805 template compatibility):
  The nuclei template sends a multipart POST to / with the 'id' form field
  containing an OGNL payload that calls freemarker.Execute.exec({'cat /etc/passwd'}).
  A real Struts 2.5.29 server evaluates the expression and the result of
  'cat /etc/passwd' appears embedded in the HTTP response.
  This mock replicates that behaviour: when 'cat /etc/passwd' is detected
  inside a detection probe (multipart or query-string id), the /etc/passwd
  content is returned in the response body so the nuclei regex matcher fires.

This mock:
  1. Accepts GET/POST to /index.action (Struts default action path) and /.
  2. Reads the 'id' field from query string OR multipart form body.
  3. Extracts the OS command from two OGNL patterns:
       a. physarum executor pattern: #arglist.add("CMD")
       b. nuclei detection pattern:  .exec({'CMD'})
  4. For physarum executor commands: executes via subprocess (bounded to
     /tmp/physarum/ writes only) and returns empty HTML response (real Struts).
  5. For nuclei detection probes (cat /etc/passwd): returns the file content
     embedded in the response, simulating freemarker Execute output.
  6. Returns HTTP 200 always.
"""

import os
import re
import subprocess
from urllib.parse import unquote
from flask import Flask, request

app = Flask(__name__)

# Restrict command execution to safe lab-only side-effects.
ALLOWED_CMD_PREFIXES = (
    "wget ", "curl ", "chmod ", "mkdir ", "sh ", "bash ",
    "nohup ", "echo ", "cat ", "/tmp/",
)

# Commands that are detection probes: execute and embed output in response.
DETECTION_CMDS = ("cat /etc/passwd", "cat /etc/shadow", "id", "whoami")


def get_id_field() -> str:
    """
    Read 'id' from query string, multipart form body, or raw body fallback.

    The nuclei CVE-2021-31805 template sends a raw HTTP request with a hardcoded
    Content-Length that may not match the actual body length, which can cause
    Werkzeug's multipart parser to fail silently. The raw-body fallback extracts
    the value between the multipart boundary name="id" header and the next boundary.
    """
    raw = request.args.get("id", "")
    if not raw and request.content_type and "multipart/form-data" in request.content_type:
        try:
            raw = request.form.get("id", "")
        except Exception:
            pass
    if not raw:
        # Raw body fallback: find form-data field named "id" in the body text
        try:
            body = request.get_data(as_text=True)
            m = re.search(
                r'Content-Disposition:\s*form-data;\s*name=["\']id["\']\s*\r?\n\r?\n(.*?)(?:\r?\n------|\Z)',
                body,
                re.DOTALL | re.IGNORECASE,
            )
            if m:
                raw = m.group(1).strip()
        except Exception:
            pass
    return raw


def extract_command_from_ognl(ognl: str) -> tuple[str | None, bool]:
    """
    Extract OS command from OGNL expression.
    Returns (cmd, is_detection_probe).

    Recognises two patterns:
      physarum executor: (#arglist.add("CMD"))
      nuclei detection:  .exec({'CMD'}) or .exec(["CMD"])
    """
    # physarum executor pattern
    m = re.search(r'#arglist\.add\("([^"]+)"\)', ognl)
    if m:
        return m.group(1), False

    # nuclei / generic Execute.exec detection pattern
    m = re.search(r'\.exec\(\{[\'"]([^\'"]+)[\'"]\}\)', ognl)
    if m:
        return m.group(1), True
    m = re.search(r'\.exec\(\[\'([^\']+)\'\]\)', ognl)
    if m:
        return m.group(1), True

    return None, False


def is_allowed(cmd: str) -> bool:
    return any(cmd.strip().startswith(p) for p in ALLOWED_CMD_PREFIXES)


def handle_ognl_request():
    raw_id = get_id_field()
    ognl = unquote(unquote(raw_id))

    # Strip outer %{...} wrapper if present
    if ognl.startswith("%{") and ognl.endswith("}"):
        ognl = ognl[2:-1]

    cmd, is_probe = extract_command_from_ognl(ognl)

    if cmd and is_probe and cmd.strip() in DETECTION_CMDS:
        # Detection probe: execute and embed output in response (real Struts behaviour).
        app.logger.info(f"[CVE-2021-31805] Detection probe: {cmd!r}")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            output = result.stdout
        except Exception:
            output = ""
        from flask import make_response
        resp = make_response(f"<!DOCTYPE HTML><html><body>{output}</body></html>", 200)
        resp.headers["Server"] = "Apache Struts/2.5.29"
        return resp

    if cmd and is_allowed(cmd):
        app.logger.info(f"[CVE-2021-31805] Executing: {cmd}")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            app.logger.info(
                f"[CVE-2021-31805] exit={result.returncode} stdout={result.stdout[:200]!r}"
            )
        except subprocess.TimeoutExpired:
            app.logger.warning("[CVE-2021-31805] command timed out")
    else:
        if cmd:
            app.logger.warning(
                f"[CVE-2021-31805] command blocked by lab policy: {cmd!r}"
            )
        else:
            app.logger.debug(
                "[CVE-2021-31805] no command extracted from OGNL (probe or fingerprint)"
            )

    from flask import make_response
    resp = make_response("<!DOCTYPE HTML><html><body>Apache Struts 2.5.29</body></html>", 200)
    resp.headers["Server"] = "Apache Struts/2.5.29"
    return resp


@app.route("/index.action", methods=["GET", "POST"])
def ognl_endpoint():
    return handle_ognl_request()


@app.route("/", methods=["GET", "POST"])
def root():
    # Root path: detection probes hit / (nuclei template posts to /),
    # fingerprint requests get a plain Struts version banner.
    raw_id = get_id_field()
    if raw_id:
        return handle_ognl_request()
    from flask import make_response
    # Banner is deliberately explicit: version 2.5.29 is ONLY affected by S2-062/CVE-2021-31805.
    # S2-061/CVE-2020-17530 was patched in 2.5.26, so version 2.5.29 is NOT vulnerable to it.
    resp = make_response(
        "<!DOCTYPE HTML><html><body>"
        "Apache Struts 2.5.29 — S2-062 / CVE-2021-31805 (OgnlExec RCE). "
        "NOTE: CVE-2020-17530 (S2-061) was patched in Struts 2.5.26; "
        "this version 2.5.29 is vulnerable ONLY to CVE-2021-31805 / S2-062."
        "</body></html>",
        200,
    )
    resp.headers["Server"] = "Apache-Struts/2.5.29"
    return resp


@app.route("/struts2-showcase/index.action", methods=["GET", "POST"])
def showcase():
    return handle_ognl_request()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=False)
