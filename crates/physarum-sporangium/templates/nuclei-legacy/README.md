# nuclei-legacy templates

Detection templates written in **Nuclei YAML format** (projectdiscovery/nuclei).

These files are kept as the canonical reference for the Nuclei template schema.
They document the detection logic that was ported to `physarum-sporangium` and
serve as the input format for the planned YAML loader (see `yaml_loader.rs`).

## Status

| State | Meaning |
|-------|---------|
| **legacy** | Format is Nuclei-native YAML — not yet parsed by physarum-sporangium |
| **reference** | Each template has a counterpart in `catalog.rs` or `vuln_intel/cache/` |
| **future** | YAML loader will make these executable without recompilation |

## Structure

```
nuclei-legacy/
├── http/
│   ├── detect/          # Server/technology fingerprinting
│   │   ├── nginx-detect.yaml
│   │   ├── apache-detect.yaml
│   │   ├── openssh-detect.yaml
│   │   └── server-version-exposed.yaml
│   ├── misconfig/       # Security header / configuration checks
│   │   ├── missing-hsts.yaml
│   │   ├── missing-x-frame-options.yaml
│   │   └── missing-csp.yaml
│   └── cve/             # CVE-specific exploitation/detection templates
│       ├── CVE-2021-23017-nginx-resolver.yaml
│       ├── CVE-2021-41773-apache-path-traversal.yaml
│       └── CVE-2021-42013-apache-rce.yaml
├── ssl/                 # TLS certificate inspection templates
│   ├── expired-cert.yaml
│   ├── self-signed-cert.yaml
│   └── tls-version-detect.yaml
├── dns/                 # DNS protocol templates
│   ├── dns-zone-transfer.yaml
│   └── dns-txt-records.yaml
└── network/             # Raw TCP / banner-grab templates
    ├── openssh-version-detect.yaml
    └── CVE-2023-38408-openssh-agent.yaml
```

## Nuclei YAML schema — key fields

```yaml
id: <unique-template-id>

info:
  name: <human-readable name>
  author: <author>
  severity: info | low | medium | high | critical
  description: <text>
  cve-id: <CVE-YYYY-NNNNN>        # optional
  cvss-score: <float>              # optional
  cwe-id: <CWE-NNN>               # optional
  tags: <comma,separated,tags>

# Protocol block (one of):
http:
  - method: GET | POST | PUT | PATCH | DELETE | HEAD
    path:
      - "{{BaseURL}}/path"
    headers:
      X-Custom: value
    body: "request body"
    matchers-condition: and | or
    matchers:
      - type: word | regex | status | dsl | binary | size | xpath
        ...
    extractors:
      - type: regex | kval | json | xpath | dsl
        ...

dns:
  - name: "{{FQDN}}"
    type: A | AAAA | CNAME | MX | TXT | NS | SOA | PTR | DS | AXFR | ANY
    matchers: [...]
    extractors: [...]

ssl:
  - address: "{{Host}}:{{Port}}"
    matchers: [...]   # dsl fields: subject, issuer, sans, not_before, not_after,
    extractors: [...]  # serial, fingerprint_sha256, self_signed, expired,
                       # key_size, tls_version, cipher

network:
  - inputs:
      - data: "<hex or text>"
        read: <bytes>
    host:
      - "{{Hostname}}:{{Port}}"
    read-size: <bytes>
    matchers: [...]
    extractors: [...]
```

## Correspondence with physarum-sporangium

| Template file | catalog.rs check_id | advisory cache CVE |
|--------------|--------------------|--------------------|
| `http/detect/nginx-detect.yaml` | `nginx-server-detect` | — |
| `http/detect/apache-detect.yaml` | `apache-server-detect` | — |
| `http/detect/server-version-exposed.yaml` | `server-version-exposed` | — |
| `http/misconfig/missing-hsts.yaml` | `missing-hsts` | — |
| `http/misconfig/missing-x-frame-options.yaml` | `missing-x-frame-options` | — |
| `http/misconfig/missing-csp.yaml` | `missing-csp` | — |
| `http/cve/CVE-2021-23017-nginx-resolver.yaml` | — | `nginx.json` CVE-2021-23017 |
| `http/cve/CVE-2021-41773-apache-path-traversal.yaml` | — | `apache-httpd.json` CVE-2021-41773 |
| `http/cve/CVE-2021-42013-apache-rce.yaml` | — | `apache-httpd.json` CVE-2021-42013 |
| `network/CVE-2023-38408-openssh-agent.yaml` | — | `openssh.json` CVE-2023-38408 |
