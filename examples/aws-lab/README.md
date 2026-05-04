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

**This lab creates billable AWS resources. Use a non-production account. Always run `terraform destroy` when done.**

```text
Preferred instance type: t4g.micro (ARM/Graviton, Free Tier eligible in many accounts)
Fallback: t3.micro or t2.micro depending on account Free Tier eligibility
No NAT Gateway — public subnets with restricted security groups are used instead
No ALB/NLB — direct EC2 access via operator_cidr only
No Elastic IP — public IPs assigned at instance launch, released on destroy
Name prefix variable: all resources tagged/named with a common prefix for easy cleanup
Region variable: default to us-east-1 (low-cost, Free Tier eligible)
operator_cidr must be your own IP — never use 0.0.0.0/0
No production accounts
```

**Why public subnets without NAT Gateway:**
The first version uses public subnets with an internet gateway to allow operator access to the coordinator API and SSH. This avoids the ~$0.045/hour NAT Gateway cost. Security groups restrict all inbound access to `operator_cidr` or inter-agent SG references — no broad public inbound is allowed.

Required cleanup:

```bash
cd examples/aws-lab/terraform
terraform destroy -var="operator_cidr=<your-ip>/32"
```

Watch for forgotten costs:

```text
EC2 instance-hours (t4g.micro: ~$0.0042/hr, t3.micro: ~$0.0104/hr)
EBS volumes (even after instance stop)
Data transfer out
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
Binary artifact pipeline (S3 upload or CI build — required for real deployment)
Runtime validation of AWS lab (depends on binary pipeline)
Segmented SG mode automation (Mode 2 — documented in security-groups.tf comments)
S3 remote Terraform state backend (bootstrapped after skeleton is deployed)
Multi-account AWS
Kubernetes / EKS
ALB or NLB
RDS or ClickHouse
NAT Gateway
SSM automation (acceptable alternative to key pairs — decide at deployment time)
GitHub Actions deployment
mTLS / Ed25519 agent authentication
Persistence and replay
eBPF telemetry
TOON export
MCPM-inspired path-density simulation
```

---

## 13. Terraform skeleton

**Status: implemented — bootstrap placeholder only.**

The Terraform skeleton exists under `examples/aws-lab/terraform/`. It defines VPC, subnets, route tables, security groups, EC2 instances, user-data scripts, and outputs. The skeleton passes `terraform fmt` and `terraform validate`.

The bootstrap scripts (`user-data/server.sh` and `user-data/agent.sh`) install system dependencies but use placeholder systemd units. The `physarum-server` and `physarum-agent` binaries are not yet distributed via an artifact pipeline. The scripts document two installation options (build on instance or download from S3). Runtime validation is not claimed.

### Instance type and architecture

Default: **`t4g.micro`** (ARM/Graviton2, Free Tier eligible in many accounts).

If `t4g.micro` is used, the AMI and future Rust binaries must be **`arm64`/`aarch64`**. The AMI is resolved automatically via SSM public parameter for the selected architecture — no region-specific AMI ID is hard-coded.

To fall back to x86_64:

```hcl
instance_type = "t3.micro"
architecture  = "x86_64"
```

The AMI resolves to:

```text
arm64:  /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
x86_64: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
```

### AWS credentials

Credentials must come from outside the repository. Never commit `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `*.tfvars` containing secrets, or `terraform.tfstate`.

Option A — environment variables (temporary credentials):

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...   # if using STS/AssumeRole
```

Option B — named profile:

```bash
export AWS_PROFILE=<profile-name>
```

### Terraform: local execution

```bash
cd examples/aws-lab/terraform

terraform init
terraform fmt -recursive
terraform plan  -var="operator_cidr=$(curl -s https://checkip.amazonaws.com)/32"
terraform apply -var="operator_cidr=$(curl -s https://checkip.amazonaws.com)/32"

# Always destroy when done
terraform destroy -var="operator_cidr=$(curl -s https://checkip.amazonaws.com)/32"
```

### Terraform: Docker execution (no local Terraform install required)

Use a pinned image version. Replace `1.9.8` with the current stable release if different.

```bash
TF_IMAGE="hashicorp/terraform:1.9.8"
TF_DIR="$(pwd)/examples/aws-lab/terraform"

# fmt (read-only check)
docker run --rm -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" fmt -recursive -check

# init
docker run --rm \
  -v "$TF_DIR:/workspace" \
  -w /workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  "$TF_IMAGE" init

# plan
docker run --rm \
  -v "$TF_DIR:/workspace" \
  -w /workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  "$TF_IMAGE" plan -var="operator_cidr=<your-ip>/32"

# apply
docker run --rm -it \
  -v "$TF_DIR:/workspace" \
  -w /workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  "$TF_IMAGE" apply -var="operator_cidr=<your-ip>/32"

# destroy (always run when done)
docker run --rm -it \
  -v "$TF_DIR:/workspace" \
  -w /workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  "$TF_IMAGE" destroy -var="operator_cidr=<your-ip>/32"
```

For AWS named profile, replace the `-e AWS_*` flags with:

```bash
  -v "$HOME/.aws:/root/.aws:ro" \
  -e AWS_PROFILE=<profile-name>
```

### Terraform state: S3 remote backend plan

The current skeleton uses **local state** (`terraform.tfstate`). Local state is acceptable for an initial operator-driven lab but must not be shared or committed.

Planned S3 remote state (to be bootstrapped before team use):

```text
Bucket: physarum-terraform-state-<account-id>
  - versioning enabled
  - server-side encryption (SSE-S3 or SSE-KMS)
  - public access blocked
State key: physarum-attack-paths/aws-lab/terraform.tfstate
State locking: DynamoDB table (if using Terraform < 1.10) or native S3 locking (Terraform >= 1.10)
```

Bootstrap sequence:

```text
Phase A: create the S3 bucket and DynamoDB table using local state or AWS CLI
Phase B: add backend "s3" block to versions.tf and run terraform init -migrate-state
```

Do not create the backend bucket inside the same configuration that immediately uses it as a backend — this creates a chicken-and-egg problem. Phase A must complete before Phase B.

This is deferred. A follow-up issue will implement the bootstrap when team collaboration requires shared state.

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
