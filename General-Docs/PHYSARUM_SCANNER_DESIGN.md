# physarum-scanner — Design and Evidence Model

**Status:** Implemented and validated through PF-2 and subsequent gates
**Binary:** `physarum-scan`
**References:** Issue #114, Gate L, Gate L.1, Gate L.2, Gate L.3

> **Scope distinction:** `SensingProfile` is the policy-checkable interface used
> by the organism through the `physarum-scanner` library. The standalone
> `physarum-scan` binary is an operator tool and intentionally exposes explicit
> targets, ports, timeout/concurrency controls, UDP scanning, scripts and output
> options. Statements about “profiles over flags” apply to organism callers, not
> to the standalone CLI.

---

## 1. Architectural role

`physarum-scanner` is the organism's reachability and sensing-model library. It
converts open-port observations into structured evidence. `physarum-maze` adds
the current banner-enrichment pass before mapping that evidence into
`physarum-llm`'s `DiscoveryQuery`.

```text
network stimulus
  -> physarum-scanner (async TCP connect + SensingResult)
  -> physarum-maze banner enrichment
  -> physarum-llm DiscoveryQuery
  -> PropagationStrategy
```

The scanner does not decide what to do with its findings. It observes and reports. Decision authority stays in `physarum-llm` and `PolicyGate`.

---

## 2. Core design decision: profiles over flags

Classic port scanner CLIs expose raw parameters (`-T4`, `-F`, `-Pn`, `--min-rate`). This approach is incompatible with a policy-gated organism.

The organism-facing `physarum-scanner` API replaces raw scan controls with
**organism-native `SensingProfile` variants**. The organism selects a profile
based on stimulus type, lineage scope, and risk context — not on arbitrary
operator-entered numbers.

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
| `TopPorts` | Moderate | Standard | Focused compiled service-port set | Broad coverage for unknown targets |
| `Deep` | Low | Long | Extended compiled service-port set | Thorough service characterization |
| `StimulusTargeted` | High | Short | Specific ports | Triggered by eBPF or ICMP stimulus on known ports |
| `NoDiscovery` | — | — | — | Skip host discovery; assume host is up |
| `RuntimeTcpEbpfFast` | High | Short | Top service ports | eBPF TCP flow stimulus at runtime |
| `RuntimeIcmpFast` | High | Short | Top service ports | ICMP stimulus at runtime |
| `StartupLocalDiscovery` | Moderate | Standard | Local subnet | Startup-time local subnet enumeration |
| `ServiceVersion` | Low | Long | Extended service-port set | Banner and version enrichment |

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
- `StartupSensing` — initial local-subnet sweep
- `TcpStimulus` — inbound TCP stimulus
- `IcmpStimulus` — inbound ICMP stimulus
- `EbpfObservation` — eBPF ring-buffer observation
- `PacketObservation` — raw packet observer evidence
- `LineageMemory` — evidence re-derived from lineage
- `ManualLabSeed` — manually seeded lab evidence

The `EvidenceSource` field makes the origin of each finding auditable in lineage.

---

## 5. Banner and service enrichment

After `physarum-scanner` confirms a TCP port is open, the current
`physarum-maze` sensing pipeline optionally enriches the result with:

- Raw banner (first bytes on connect)
- A minimal HTTP response, including headers such as `Server:`
- Protocol hints from response shape

These are summarized in `banner_or_handshake_summary` and `version_hint` — free-text fields kept intentionally loose to avoid false precision. The LLM receives hints, not authoritative version strings.

Raw TLS certificate inspection is not implemented in this scanner enrichment
path. TLS/SSL inspection belongs to `physarum-sporangium` protocol templates.

`OsHint` (optional) carries a best-effort OS guess with its source
(`SshBanner`, `HttpHeader`, `ServiceBanner`, or `Convention`) and a confidence
value. It is never treated as ground truth.

---

## 6. Relationship to eBPF observers

`physarum-ebpf-observer` produces `FlowObservation` records, while
`physarum-packet-observer` produces `PacketObservation` records from passive
kernel-level traffic. Runtime stimuli derived from these observers can trigger
targeted sensing profiles; the scanner confirms reachability and
`physarum-maze` enriches the results with banners.

The two layers are complementary: eBPF is passive and zero-connect; the scanner is active and evidence-rich.

---

## 7. What the scanner does not do

- Does not decide propagation targets
- Does not execute exploits or templates
- Does not store credentials or sensitive fields
- The organism-facing profile path does not currently use UDP scanning; the
  standalone `physarum-scan --udp` CLI does
- Does not implement SYN/raw-socket scanning (async TCP connect only)
- Does not expose raw scan parameters to the organism caller; the standalone CLI
  exposes them for explicit operator-driven scans
