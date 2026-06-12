# physarum-target-ognlexec — Issue #144 OgnlExec validation target
#
# Simulates an Apache Struts 2.5.29 web application vulnerable to CVE-2021-31805
# (S2-062: OGNL injection via forced double evaluation of tag attribute values).
#
# The endpoint accepts GET/POST to /index.action?id=<OGNL> and executes the OGNL
# expression via freemarker.Execute. Each request executes ONE OS command —
# the LLM must discover this constraint from Exploit-DB enrichment and generate
# OgnlExec.commands with one element per command (no && chaining).
#
# Build (must use desktop-linux builder — never cloud builder):
#   docker buildx build --builder desktop-linux \
#     --platform linux/amd64 \
#     -f docker/physarum-target-ognlexec.Dockerfile \
#     -t physarum-target-ognlexec:lab --load .
#
# CVE-2021-31805 / S2-062 references:
#   https://cwiki.apache.org/confluence/display/WW/S2-062
#   EDB-51213, EDB-50155

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        openjdk-11-jre-headless \
        openssh-server \
        curl \
        wget \
        python3 \
        python3-flask \
        ca-certificates \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── SSH setup ────────────────────────────────────────────────────────────────
RUN mkdir -p /var/run/sshd /root/.ssh && \
    chmod 700 /root/.ssh && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "root:physarum" | chpasswd

# ── Mock Struts OGNL endpoint (Python/Flask — no real Struts needed for lab) ─
# Simulates CVE-2021-31805 OGNL execution: accepts one OS command per request.
# Path: GET/POST /index.action?id=<OGNL-encoded-command>
# The OgnlExec executor sends the SecurityMemberAccess bypass OGNL expression;
# this mock decodes the %-encoded command string and executes it via subprocess.
#
# In a real deployment this would be a Struts 2.5.29 WAR on Tomcat.
# For the Docker lab, the Flask mock is functionally equivalent — the executor
# sends the same HTTP requests and the same delivery sequence is validated.

COPY docker/mock-ognlexec-server.py /opt/mock-ognlexec-server.py
RUN chmod +x /opt/mock-ognlexec-server.py

# ── Entrypoint ───────────────────────────────────────────────────────────────
RUN mkdir -p /tmp/physarum

EXPOSE 8090 22

CMD ["/bin/bash", "-c", \
     "service ssh start && \
      python3 /opt/mock-ognlexec-server.py"]
