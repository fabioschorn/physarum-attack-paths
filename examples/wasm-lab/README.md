# wasm-lab — Live Organism Graph Visualization

> **Status:** Active — Issue #161. Implementation pending.

This lab validates `physarum-maze --server`: the seed node exposes a live organism graph API (axum + SSE) and serves a Leptos WASM frontend embedded in the binary. A browser page shows each hop colonized in real time as the organism propagates through the lab topology.

Full spec: [Issue #161](https://github.com/fabioschorn/physarum-attack-paths/issues/161)

---

## Lab topology

```text
host-a  →  host-b  →  host-c
(seed)     (hop 1)    (hop 2)
--server
:8080
```

Three containers. host-a runs `physarum-maze --server 8080`. The operator opens a browser at `http://localhost:8080` and watches the graph grow: seed node appears, host-b colonized → first edge, host-c colonized → second edge with depth 2.

---

## What it demonstrates

- `physarum-maze --server` starts without error; WASM app loads from `/`
- `GET /events` (SSE) streams `ColonizationEvent` in real time
- Force-directed graph renders and stabilizes within 2 seconds for 3 nodes
- D_ij edge weights animate as evidence accumulates
- Node radius reflects LLM confidence; color reflects colonization state
- Zero external files — the same musl binary that propagates also serves the visualization

---

## Relationship to other labs

```text
docker/pf6-lab.sh          — chain propagation validation (4 containers, no --server)
examples/wasm-lab          — this lab: live graph visualization (3 containers, --server)
examples/aws-lab/          — AWS VPC labs (PF-1, PF-2 complete; LLM lab planned)
```
