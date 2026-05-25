# General Documentation

This directory contains general project documentation that supports the main `physarum-attack-paths` README.

## Available documents

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Full system architecture — all four generations (server/agent → eBPF → physarum-maze → physarum-llm) |
| [QUALITY_GATE.md](./QUALITY_GATE.md) | Gate definitions, acceptance criteria, evidence links (Gates A–PF-2) |
| [ROLE_FLUID_AGENT_ARCHITECTURE.md](./ROLE_FLUID_AGENT_ARCHITECTURE.md) | eBPF direction + role-fluid agent design intent (Issue #63) |
| [EBPF_FLOW_OBSERVATION_DESIGN.md](./EBPF_FLOW_OBSERVATION_DESIGN.md) | eBPF Stage 0 design — Aya stack, TCP state tracepoint, sidecar model |
| [INSIGHTS_AND_BRAINSTORM.md](./INSIGHTS_AND_BRAINSTORM.md) | Exploratory ideas, MCPM, MCTS, Micromouse framing — not authoritative |
| [DOCUMENTATION_GUIDELINES.md](./DOCUMENTATION_GUIDELINES.md) | Documentation ownership model and contribution rules |

## Purpose

The main `README.md` keeps the high-level project vision, architecture summary, and quick-start instructions.

This `General-Docs/` directory holds practical planning documents, design intent, implementation roadmaps, and lab operational notes that should not make the main README too long.
