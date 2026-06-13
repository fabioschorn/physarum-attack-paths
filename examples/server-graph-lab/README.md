# server-graph-lab — Live Organism Graph Visualization

> **Status:** Complete — Issue #161 / v0.5.0 / PR #170

`physarum-maze --server <PORT>` exposes a live organism graph API (axum + SSE) and serves a Canvas HTML frontend embedded in the binary via `include_str!`. A browser page shows each hop colonized in real time as the organism propagates through the lab topology.

Full spec: [Issue #161](https://github.com/fabioschorn/physarum-attack-paths/issues/161)

---

## Implementation note

The original spec described a Leptos WASM frontend. The implementation uses a vanilla Canvas HTML + JavaScript frontend embedded directly in the binary via `include_str!`. This avoids a WASM build dependency while delivering equivalent real-time visualization. The binary remains fully self-contained: no external files, no runtime assets.

---

## How to run (wired into pf6-lab)

`--server` is wired into the PF-6 four-container lab. No separate lab setup is needed.

```bash
# Build
docker buildx build --builder cloud-expertsonline-physarum-attack-paths \
  --platform linux/amd64 --output type=oci,dest=/tmp/physarum-maze-lab.tar \
  -f docker/physarum-maze-lab.Dockerfile .
docker load -i /tmp/physarum-maze-lab.tar && docker tag <sha> physarum-maze:lab

# Run Phase 2 with live graph
./docker/pf6-lab.sh --phase2

# Open in browser
open http://localhost:8080/
```

---

## Lab topology (pf6-lab)

```text
host-a (172.21.0.2)  →  host-b (172.21.0.3)  →  host-c (172.21.0.4)  →  host-d (172.21.0.5)
  seed                    CVE-2020-17530           CVE-2015-3306            CVE-2021-31805
  --server 8080           depth 1                  depth 2                  depth 3
```

The operator opens `http://localhost:8080/` and watches the graph grow in real time as each hop is colonized.

---

## What it demonstrates

- `physarum-maze --server 8080` starts alongside the agent — zero runtime files
- `GET /` serves the Canvas HTML frontend embedded via `include_str!`
- `GET /graph` returns a JSON snapshot of the current organism graph
- `GET /events` streams `ColonizationEvent` in real time via SSE
- Seed node appears first at center before any discovery events arrive
- Nodes positioned on depth rings — depth 1 inner, depth 2 middle, depth 3 outer
- CVE badges on colonized nodes; node radius reflects LLM confidence score
- Noise nodes (discovered but not colonized) appear on the outer ring, showing passive sensing activity
- Directed edges reflect propagation order (who colonized whom)
- Scrollable log panel — always-visible scrollbar; smart auto-scroll preserves manual history reading
- D_ij edge weights animate as evidence accumulates

---

## API

| Endpoint | Method | Response |
|---|---|---|
| `/` | GET | HTML — Canvas frontend (embedded in binary) |
| `/graph` | GET | JSON — `OrganismGraph` snapshot |
| `/events` | GET | SSE stream — `ColonizationEvent` per hop |

---

## Relationship to other labs

```text
docker/pf6-lab.sh            — PF-6 chain propagation (4 containers, Phase 1 + Phase 2)
docker/pf6-lab.sh --phase2   — same lab with --server 8080 and live graph UI ← this
examples/aws-lab/            — AWS VPC labs (PF-1, PF-2 complete; LLM lab planned after Gate N)
```
