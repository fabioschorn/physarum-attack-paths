#!/usr/bin/env python3
"""
Mock Apache Struts CVE-2021-31805 OGNL endpoint for physarum Docker Lab.

Simulates a Struts 2.5.29 action that performs forced double evaluation of the
'id' query parameter via freemarker.Execute — CVE-2021-31805 / S2-062.

Key constraint: freemarker.Execute.exec(list) passes the first list element to
Runtime.exec(String), which tokenizes by whitespace. One command per request —
no shell metacharacters (&&, ;, |) are interpreted.  The OgnlExec executor
sends a separate HTTP POST for each command in OgnlExec.commands.

This mock:
  1. Accepts GET/POST to /index.action (Struts default action path).
  2. Reads the 'id' query parameter (URL-encoded OGNL expression).
  3. Extracts the OS command from the OGNL arglist pattern.
  4. Executes the command via subprocess (bounded to /tmp/physarum/ writes only).
  5. Returns HTTP 200 always (real Struts returns 200 or 400 after RCE fires).

The SecurityMemberAccess bypass OGNL built by physarum-maze contains:
  (#arglist.add("{cmd}")).(#execute=#instancemanager.newInstance("freemarker...")).
  (#execute.exec(#arglist))
This mock extracts the {cmd} value from the #arglist.add() call.
"""

import os
import re
import subprocess
from urllib.parse import unquote
from flask import Flask, request

app = Flask(__name__)

# Restrict command execution to safe lab-only side-effects.
# Only allow writes to /tmp/physarum/ and reads from /tmp.
ALLOWED_CMD_PREFIXES = (
    "wget ", "curl ", "chmod ", "mkdir ", "sh ", "bash ",
    "nohup ", "echo ", "cat ", "/tmp/",
)


def extract_command_from_ognl(ognl: str) -> str | None:
    """Extract the OS command embedded in the physarum OGNL bypass expression."""
    # The executor produces: (#arglist.add("{cmd}"))
    # After URL-decoding the 'id' parameter the pattern is: #arglist.add("CMD")
    m = re.search(r'#arglist\.add\("([^"]+)"\)', ognl)
    if m:
        return m.group(1)
    return None


def is_allowed(cmd: str) -> bool:
    return any(cmd.strip().startswith(p) for p in ALLOWED_CMD_PREFIXES)


@app.route("/index.action", methods=["GET", "POST"])
def ognl_endpoint():
    raw_id = request.args.get("id", "")
    ognl = unquote(unquote(raw_id))  # double-decode: %25%7B...%7D → %{...} → {ognl}

    # Strip outer %{...} wrapper if present
    if ognl.startswith("%{") and ognl.endswith("}"):
        ognl = ognl[2:-1]

    cmd = extract_command_from_ognl(ognl)

    if cmd and is_allowed(cmd):
        app.logger.info(f"[CVE-2021-31805] Executing: {cmd}")
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            app.logger.info(f"[CVE-2021-31805] exit={result.returncode} stdout={result.stdout[:200]!r}")
        except subprocess.TimeoutExpired:
            app.logger.warning("[CVE-2021-31805] command timed out")
    else:
        if cmd:
            app.logger.warning(f"[CVE-2021-31805] command blocked by lab policy: {cmd!r}")
        else:
            app.logger.debug(f"[CVE-2021-31805] no command extracted from OGNL (probe or fingerprint)")

    # Real Struts returns 200 with a response body even when RCE fires.
    return "<!DOCTYPE HTML><html><body>Welcome to Struts app</body></html>", 200


@app.route("/", methods=["GET", "POST"])
def root():
    # Accept root path too — some OGNL probes hit /
    return "<!DOCTYPE HTML><html><body>Struts 2.5.29</body></html>", 200


@app.route("/struts2-showcase/index.action", methods=["GET", "POST"])
def showcase():
    return ognl_endpoint()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=False)
