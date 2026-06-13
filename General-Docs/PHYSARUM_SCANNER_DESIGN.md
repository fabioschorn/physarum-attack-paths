# physarum-scanner — Design and Evidence Model

**Status:** Implemented and validated through PF-2 and subsequent gates
**Binary:** `physarum-scan`
**References:** Issue #114, Gate L, Gate L.1, Gate L.2, Gate L.3

---

## 1. Architectural role

`physarum-scanner` is the organism's sensing organ. It converts raw TCP reachability into structured evidence that feeds directly into `physarum-llm`'s `DiscoveryQuery`.

```text
network stimulus
  -> physarum-scanner (async TCP connect + banner probe)
  -> SensingResult (structured evidence)
  -> physarum-llm DiscoveryQuery
  -> PropagationStrategy
```

The scanner does not decide what to do with its findings. It observes and reports. Decision authority stays in `physarum-llm` and `PolicyGate`.

---

## 2. Core design decision: profiles over flags

Classic port scanner CLIs expose raw parameters (`-T4`, `-F`, `-Pn`, `--min-rate`). This approach is incompatible with a policy-gated organism.

`physarum-scanner` replaces raw flags with **organism-native `SensingProfile` variants**. The organism selects a profile based on stimulus type, lineage scope, and risk context — not on operator-entered numbers.

This makes scanning behavior:
- Deterministic and policy-checkable
- Auditable in lineage (the profile name is recorded, not raw parameters)
- Immune to operator misconfiguration of concurrency or timeout values

---

## 3. SensingProfile variants

| Profile | Concurrency | Timeout | Port scope | Use case |
|---|---|---|---|---|
| `LowNoise` | Low | Long | Small | Conservative expansion, tight noise budget |
| `Balanced` | Moderate | Standard | Broad service ports | Default lab exploration, periodic discovery |
| `Fast` | High | Short | Top service ports | Quick initial sweep on a known-reachable subnet |
| `TopPorts` | Moderate | Standard | Top 1000 | Broad coverage for unknown targets |
| `Deep` | Low | Long | All 65535 | Thorough scan when prior evidence warrants it |
| `StimulusTargeted` | High | Short | Specific ports | Triggered by eBPF or ICMP stimulus on known ports |
| `NoDiscovery` | — | — | — | Skip host discovery; assume host is up |
| `RuntimeTcpEbpfFast` | High | Short | eBPF-observed ports | eBPF TCP flow stimulus at runtime |
| `RuntimeIcmpFast` | High | Short | Top service ports | ICMP stimulus at runtime |
| `StartupLocalDiscovery` | Moderate | Standard | Local subnet | Startup-time local subnet enumeration |

`StimulusTargeted`, `RuntimeTcpEbpfFast`, and `NoDiscovery` skip host-discovery entirely — they assume reachability is already known from the triggering event.

---

## 4. SensingResult — evidence structure

Each open port observation produces a `SensingResult`. The fields are shaped to map directly to `physarum_llm::DiscoveryQuery`:

| SensingResult field | DiscoveryQuery field |
|---|---|
| `port` + `protocol` + `state` | `ports[].port / protocol / state` |
| `service_guess` | `ports[].service_guess` |
| `banner_or_handshake_summary` | `ports[].banner` |
| `version_hint` | `ports[].version_hint` |
| `os_hint` | `os_hint` |

**Evidence sources** recorded per result:

- `ScheduledScan` — periodic subnet scan
- `StimulusTcp` — TCP eBPF flow triggered
- `StimulusIcmp` — ICMP packet triggered
- `ManualTarget` — operator-specified target

The `EvidenceSource` field makes the origin of each finding auditable in lineage.

---

## 5. Banner and service enrichment

After TCP connect confirms a port is open, the scanner optionally probes for:

- Raw banner (first bytes on connect)
- HTTP response headers (`Server:`, `X-Powered-By:`)
- TLS handshake metadata (CN, SAN, issuer)
- Protocol hints from response shape

These are summarized in `banner_or_handshake_summary` and `version_hint` — free-text fields kept intentionally loose to avoid false precision. The LLM receives hints, not authoritative version strings.

`OsHint` (optional) carries a best-effort OS guess with its source (`TtlHeuristic`, `BannerString`, `TlsCn`) and a confidence flag. It is never treated as ground truth.

---

## 6. Relationship to eBPF observers

`physarum-ebpf-observer` and `physarum-packet-observer` produce `FlowObservation` events from passive kernel-level traffic. These events can trigger a `StimulusTargeted` or `RuntimeTcpEbpfFast` scan — the eBPF layer narrows what ports to scan, and the scanner confirms reachability and enriches with banners.

The two layers are complementary: eBPF is passive and zero-connect; the scanner is active and evidence-rich.

---

## 7. What the scanner does not do

- Does not decide propagation targets
- Does not execute exploits or templates
- Does not store credentials or sensitive fields
- Does not perform UDP scanning
- Does not implement SYN/raw-socket scanning (async TCP connect only)
- Does not expose raw scan parameters to the organism caller
