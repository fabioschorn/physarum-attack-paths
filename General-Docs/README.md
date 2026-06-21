# General Documentation

Supporting documents for the physarum-attack-paths project. The main `README.md` covers vision, architecture summary, and quick-start. This directory holds design documents and technical deep-dives.

## Documents

The status column distinguishes operational documentation from historical design
records. Historical documents remain useful for rationale, but must not be read as
the current runtime contract.

| Document | Status | Purpose |
|---|---|---|
| [ROADMAP.md](./ROADMAP.md) | Current | Project state, evidence pipeline, labs, planned evolution, safety and scope |
| [CHANNEL_SECURITY_DESIGN.md](./CHANNEL_SECURITY_DESIGN.md) | Implemented baseline — v0.5.4 | AES-256-GCM lineage, SCP-first delivery, mTLS back-channel and HTTPS dashboard |
| [GATE_N0_THREAT_MODEL.md](./GATE_N0_THREAT_MODEL.md) | Historical baseline + current-state notes | Gate N threat model, target invariants and N.1–N.7 sequence |
| [PHYSARUM_SCANNER_DESIGN.md](./PHYSARUM_SCANNER_DESIGN.md) | Implemented; library/CLI distinction applies | Organism sensing profiles, evidence model and standalone `physarum-scan` boundary |
| [ROLE_FLUID_AGENT_ARCHITECTURE.md](./ROLE_FLUID_AGENT_ARCHITECTURE.md) | Historical design intent | eBPF direction and the architecture that led to the current organism model |
| [EBPF_FLOW_OBSERVATION_DESIGN.md](./EBPF_FLOW_OBSERVATION_DESIGN.md) | Historical design + implementation outcome | Aya stack, TCP state tracepoint, sidecar model and later gate outcome |
| [NUCLEI_REEVALUATION_FOR_PHYSARUM_SPORE.md](./NUCLEI_REEVALUATION_FOR_PHYSARUM_SPORE.md) | Architectural decision record | Why Nuclei concepts were ported into native Rust |
| [SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md](./SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md) | Current implementation reference | Embedded template catalog, runtime filtering and LLM integration |

## Crate-level design documents

Design documents that live inside specific crates:

| Document | Purpose |
|---|---|
| [crates/physarum-llm/DESIGN.md](../crates/physarum-llm/DESIGN.md) | physarum-llm architecture — two-turn LLM flow, PolicyGate, secret handling, evidence integration, phase status |
