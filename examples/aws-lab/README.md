# AWS Lab — Physarum Attack Paths

This directory contains AWS-based laboratories for validating `physarum-attack-paths` under real EC2/VPC network conditions.

The AWS labs complement the local and Docker labs by proving behavior that container-only environments cannot fully represent:

```text
real EC2 instance boundaries
real VPC subnets and routing
security group controlled reachability
measurable RTT and reachability differences
adaptive graph behavior under segmentation
autonomous organism expansion through PF-1 and PF-2
```

---

## Current AWS lab status

| Lab | Directory | Status |
|---|---|---|
| Mode 1 — full mesh A/B/C/D | `terraform/` | validated |
| Mode 2 — segmented B→C→D | `terraform/` | validated |
| Gate K/K.1 segmented adaptive path selection | `terraform/` + Ansible | validated |
| PF-1 organic expansion maze | `terraform-pf1/` + `ansible-pf1/` | validated |
| PF-2 adaptive re-routing | `terraform-pf2/` + `ansible-pf2/` | validated |

Historical A/B/C/D details are preserved by Git history and the related closed PRs/issues. The current authoritative architecture and gate status live in:

```text
General-Docs/ARCHITECTURE.md
General-Docs/QUALITY_GATE.md
README.md
```

---

## Relationship to other labs

```text
examples/local-lab   -> manual A/B/C developer debugging
examples/docker-lab  -> reproducible A/B/C/D container validation
examples/aws-lab     -> real EC2/VPC/subnet/security-group validation
```

Docker gives speed. AWS gives realism. Both remain useful.

---

## Legacy A/B/C/D AWS lab

The original AWS lab validated the server/agent model across EC2 instances.

Conceptual mapping:

```text
A = physarum-server    — coordinator EC2 instance
B = agent-b            — perimeter-like EC2 instance
C = agent-c            — application/gateway-like EC2 instance
D = agent-d            — crown-jewel/database-like EC2 instance
```

The important validated behaviors were:

```text
Mode 1: full mesh reachability
Mode 2: segmented B→C→D reachability
B→D direct path decays to score 0.0 when blocked by security groups
/paths selects B→C→D when direct B→D is unavailable
terraform destroy leaves no running lab instances
```

---

## PF-1 — Organic expansion maze

PF-1 validated autonomous organism expansion.

Validated behavior:

```text
single seed starts at Host A
organism discovers candidates from stimuli
organism propagates through the maze by SCP + SSH in the controlled lab
lineage is recorded at each hop
G is reached without giving the organism a predefined final target
```

PF-1 proved that the project moved beyond static server/client topology into organism-level behavior.

---

## PF-2 — Adaptive re-routing

PF-2 validated continued metabolism after baseline expansion.

Validated behavior:

```text
A discovers A.1 through local /24 discovery
X appears in another subnet after the baseline organism has formed
X stimulates A.1 with TCP SYN traffic toward A.1:22
A.1 captures the stimulus and discovers X
X finds G already colonized
G is not re-deployed
X→G is recorded as a secondary conduit
```

PF-2 proved that the organism does not freeze around the first discovered route. It continues sensing, adapting, and preserving useful secondary conduits.

---

## Safety controls

These labs create billable AWS resources. Use a non-production account and always destroy resources after validation.

Required controls:

```text
operator_cidr must be a narrow workstation /32
no Internet scanning
no public target probing
no production accounts
no broad 0.0.0.0/0 inbound access
no persistent infrastructure after lab completion
terraform destroy after every run
```

The current PF labs are controlled research labs, not production deployment patterns.

---

## Typical lifecycle

```bash
# Deploy a lab
terraform -chdir=examples/aws-lab/<terraform-dir> apply -auto-approve

# Run the corresponding Ansible verification
ansible-playbook -i examples/aws-lab/<ansible-dir>/aws_ec2.yml \
  examples/aws-lab/<ansible-dir>/<verify-playbook>.yml

# Destroy when done
terraform -chdir=examples/aws-lab/<terraform-dir> destroy -auto-approve
```

Use the exact commands documented in each lab-specific Terraform/Ansible directory or the relevant PR evidence.

---

## Explicitly not part of the current project direction

The following older backlog ideas are intentionally not part of the current AWS lab/project roadmap:

```text
Persistence / ClickHouse
TOON export
```

If either idea is ever reconsidered, it should require a new Owner/Architect decision and a dedicated issue explaining why it belongs in the project again.

---

## Current next tracks

The active/future project tracks are:

```text
Issue #106 — physarum-llm research/design for the Causal Continuity Paradox
Issue #89 / Gate N.0 — secure organism identity, mTLS, and lineage threat model after #106
```

Longer-term research ideas belong in:

```text
General-Docs/INSIGHTS_AND_BRAINSTORM.md
```
