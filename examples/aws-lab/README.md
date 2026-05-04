# AWS Lab — Terraform Skeleton Design for A/B/C/D Validation

This document defines the design for the AWS-based laboratory for `physarum-attack-paths`.

**Status: design only.** No Terraform files exist yet. This document defines what will be built in the next implementation gate.

---

## 1. Purpose

The AWS lab validates the adaptive graph under real cloud network conditions that Docker cannot represent:

```text
separate EC2 instances with real RTT differences
VPC subnets and routing
security group controlled reachability
D_ij decay/recovery when reachability changes
/paths behavior under segmented topology (B can reach D only through C)
```

The key difference from Docker is security group mode 2 (segmented path): in Docker the full mesh always forms. In AWS, security groups can enforce `B → C → D` as the only viable path, forcing the direct `B → D` edge to decay.

---

## 2. Relationship to other labs

```text
examples/local-lab  → manual A/B/C, single host, developer debugging
examples/docker-lab → reproducible A/B/C/D full mesh, fast CI-style validation
examples/aws-lab    → real EC2/VPC/subnet/security-group A/B/C/D validation
```

Docker gives speed. AWS gives realism. Both are required; neither replaces the other.

---

## 3. AWS A/B/C/D mapping

```text
A = physarum-server    — coordinator EC2 instance, management-like subnet
B = agent-b            — perimeter-like EC2 instance, outer subnet
C = agent-c            — application/gateway-like EC2 instance, middle subnet
D = agent-d            — crown-jewel/database-like EC2 instance, inner subnet
```

Conceptual VPC layout:

```text
VPC CIDR: 10.50.0.0/16

management subnet: 10.50.10.0/24
  A / physarum-server:  10.50.10.10

outer subnet: 10.50.20.0/24
  B / agent-b:          10.50.20.10

middle subnet: 10.50.30.0/24
  C / agent-c:          10.50.30.10

inner subnet: 10.50.40.0/24
  D / agent-d:          10.50.40.10
```

Exact CIDRs and IPs will be defined when Terraform is implemented.

---

## 4. Terraform skeleton layout

The future Terraform implementation should use this layout:

```text
examples/aws-lab/terraform/
├── versions.tf          # Terraform and provider version constraints
├── providers.tf         # AWS provider configuration, region variable
├── variables.tf         # region, instance_type, name_prefix, key_name
├── network.tf           # VPC, subnets, internet gateway, route tables
├── security-groups.tf   # per-agent security groups, SG modes documented as variables
├── instances.tf         # EC2 instances for A, B, C, D with user_data references
├── outputs.tf           # public/private IPs, curl validation commands
└── user-data/
    ├── server.sh        # bootstrap physarum-server on instance A
    └── agent.sh         # bootstrap physarum-agent (parameterized by agent_id)
```

No Terraform files are added in this design gate. The layout above defines the target for the implementation gate.

---

## 5. Minimal AWS resources

The Terraform skeleton should create only the following resources:

```text
1 VPC
4 subnets (management, outer, middle, inner)
1 internet gateway
4 route tables (one per subnet)
4–5 security groups (one per agent + coordinator, plus optional bastion)
4 EC2 instances (A, B, C, D)
4 user_data bootstrap scripts
1 IAM instance profile (only if SSM Session Manager is preferred over key pair)
outputs.tf exposing IPs and ready-to-run curl commands
```

Do not add these until explicitly needed:

```text
NAT Gateway
ALB or NLB
RDS
EKS / Kubernetes
SSM automation
CloudWatch log groups
multi-account setup
```

Instance type recommendation: `t3.micro` for prototype, `t3.small` if binary size requires it.

---

## 6. Security group validation modes

This is the core value of the AWS lab over Docker. Two modes must be defined.

### Mode 1 — Full mesh baseline

All agents can probe all other agents. Mirrors Docker lab behavior.

```text
B ↔ C  allowed (port 9001, 9002)
B ↔ D  allowed (port 9001, 9003)
C ↔ D  allowed (port 9002, 9003)
All agents → A allowed (port 8080)
```

Expected behavior:

```text
six directed edges form
all edges: probe_success=true, q_ema > 0, d_ij > 0
/paths?source=agent-b&target=agent-d returns both direct (B→D) and two-hop (B→C→D)
ranking depends on live d_ij values
```

### Mode 2 — Segmented logical path

Only the B→C→D chain is allowed. Direct B→D is blocked.

```text
B → C  allowed
C → B  allowed (or blocked for stricter one-way test)
C → D  allowed
D → C  allowed (or blocked for stricter one-way test)
B → D  BLOCKED
D → B  BLOCKED
All agents → A allowed (port 8080)
```

Expected behavior:

```text
B→D edge: probe_success=false, q_ema decays to 0, d_ij decays toward 0
B→C→D edges: probe_success=true, q_ema > 0, d_ij > 0
/paths?source=agent-b&target=agent-d returns only B→C→D
direct B→D path absent or near-zero score
```

This mode proves /paths reasoning over real network segmentation — the key capability AWS adds.

### Mode 3 — Restore connectivity (optional)

After running Mode 2, restore B↔D connectivity and observe d_ij recovery. Validates the separation between short-term sensing (q_ema) and long-term morphology (d_ij).

---

## 7. EC2 process startup

Server A:

```bash
physarum-server --listen 0.0.0.0:8080
```

Agent B:

```bash
physarum-agent \
  --id agent-b \
  --coordinator http://<A-private-ip>:8080 \
  --listen 0.0.0.0:9001 \
  --advertise-address <B-private-ip> \
  --probe-interval-seconds 5
```

Agent C:

```bash
physarum-agent \
  --id agent-c \
  --coordinator http://<A-private-ip>:8080 \
  --listen 0.0.0.0:9002 \
  --advertise-address <C-private-ip> \
  --probe-interval-seconds 5
```

Agent D:

```bash
physarum-agent \
  --id agent-d \
  --coordinator http://<A-private-ip>:8080 \
  --listen 0.0.0.0:9003 \
  --advertise-address <D-private-ip> \
  --probe-interval-seconds 5
```

`--advertise-address` must be the EC2 **private IP** so agents can probe each other without going through the internet gateway.

---

## 8. Validation commands

Run from any host with access to the coordinator (public IP or bastion):

```bash
# Health check
curl -s http://<A-public-ip>:8080/health | jq

# Agent registration
curl -s http://<A-public-ip>:8080/agents | jq

# Edge graph
curl -s http://<A-public-ip>:8080/graph | jq

# Adaptive path scoring — mode 1 (full mesh): expect both B→D and B→C→D
curl -s 'http://<A-public-ip>:8080/paths?source=agent-b&target=agent-d' | jq

# Adaptive path scoring — mode 2 (segmented): expect only B→C→D
curl -s 'http://<A-public-ip>:8080/paths?source=agent-b&target=agent-d' | jq
```

The `outputs.tf` should emit ready-to-run versions of these commands with real IPs substituted.

---

## 9. Success criteria

The AWS lab is validated when:

```text
Mode 1 (full mesh):
  - server A healthy
  - agents B, C, D registered
  - /graph shows 6 directed edges, all with probe_success=true, q_ema>0, d_ij>0
  - /paths returns both B→D (direct) and B→C→D (two-hop)

Mode 2 (segmented):
  - B→D edge absent or d_ij near zero after SG change
  - B→C and C→D edges remain healthy
  - /paths returns only B→C→D for source=agent-b target=agent-d
  - direct path score absent or near zero

Mode 3 (restore, optional):
  - after restoring B↔D, d_ij for B→D begins recovering
  - /paths eventually returns B→D again as d_ij climbs
```

---

## 10. Cost and safety controls

The future Terraform implementation must follow these rules:

```text
Instance types: t3.micro or t3.small only
Name prefix variable: all resources tagged/named with a common prefix for easy cleanup
Region variable: default to a low-cost region (e.g. us-east-1)
No NAT Gateway in the first version (use public subnets with restricted SGs)
No broad 0.0.0.0/0 inbound except SSH from known CIDR and :8080 for testing
terraform destroy clearly documented as the cleanup step
No production accounts
```

Required cleanup:

```bash
cd examples/aws-lab/terraform
terraform destroy
```

Watch for forgotten costs:

```text
EC2 instance-hours
EBS volumes (even after instance stop)
Elastic IPs if allocated
CloudWatch logs if configured
```

---

## 11. Security considerations

```text
Only deploy into owned and authorized AWS accounts.
Do not probe public targets.
Do not expose probe ports (9001–9003) to 0.0.0.0/0.
Restrict SSH to a known CIDR or use SSM Session Manager instead.
Restrict coordinator port 8080 to operator IP or bastion during testing.
Treat this as a controlled research lab, not a production system.
```

---

## 12. Out of scope

Explicitly deferred to later phases:

```text
Terraform implementation (this gate is design only)
Multi-account AWS
Kubernetes / EKS
ALB or NLB
RDS or ClickHouse
NAT Gateway (unless required for routing)
SSM automation (acceptable alternative to key pairs — decide at implementation time)
mTLS / Ed25519 agent authentication
Persistence and replay
eBPF telemetry
TOON export
MCPM-inspired path-density simulation
```

---

## 13. Terraform skeleton status

**Status: implemented — bootstrap placeholder only.**

The Terraform skeleton is created. It defines VPC, subnets, route tables, security groups, EC2 instances, user-data scripts, and outputs. The skeleton passes `terraform fmt` and `terraform validate`.

The bootstrap scripts (`user-data/server.sh` and `user-data/agent.sh`) install system dependencies but use placeholder systemd units — the `physarum-server` and `physarum-agent` binaries are not yet distributed via an artifact pipeline. The scripts document two installation paths (build on instance, or download from S3) that must be completed before the lab can run.

This skeleton is not yet runtime validated. It will be marked deployable once binaries are available and `terraform apply` succeeds with `/health`, `/graph`, and `/paths` returning expected results.

### Terraform commands

```bash
cd examples/aws-lab/terraform

# Initialize
terraform init

# Preview
terraform plan -var="operator_cidr=<your-ip>/32"

# Deploy
terraform apply -var="operator_cidr=<your-ip>/32"

# Destroy (always run when done — do not leave instances running)
terraform destroy -var="operator_cidr=<your-ip>/32"
```

**Cost/safety reminder:** EC2 instances run as `t3.micro` by default. Always run `terraform destroy` after testing. Watch for forgotten EBS volumes and Elastic IPs. Never deploy into a production account.

---

## 14. Implementation sequence (updated)

```text
✔ 1. Docker A/B/C lab implemented and validated.
✔ 2. Docker A/B/C/D lab implemented and validated.
✔ 3. GET /paths implemented and Docker-validated.
✔ 4. AWS lab design documented (this gate).
✔ 5. Terraform skeleton implemented — VPC, subnets, SGs, EC2 instances, user_data.
  6. Add binary artifact pipeline (S3 or build-on-instance) and deploy for real.
  7. Validate mode 1 (full mesh) — /health, /agents, /graph, /paths all pass.
  8. Switch to mode 2 (segmented B→C→D) and validate /paths reasoning.
  9. Optional: validate mode 3 (restore connectivity, observe d_ij recovery).
```
