# AWS Lab — Terraform Skeleton Design for A/B/C/D Validation

This document defines the design for the AWS-based laboratory for `physarum-attack-paths`.

**Status: AWS Mode 1 Runtime Validation PASSED (PR #43).** Full-mesh A/B/C/D validated in real EC2/VPC environment via SSH + Ansible. All endpoints confirmed, all agents registered. Mode 2 segmented B→C→D is the next gate.

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

These CIDRs and IPs are implemented in `network.tf` and `instances.tf`.

---

## 4. Terraform skeleton layout

The Terraform skeleton currently uses this layout:

```text
examples/aws-lab/terraform/
├── versions.tf          # Terraform and provider version constraints
├── providers.tf         # AWS provider configuration, region variable
├── variables.tf         # region, instance_type, name_prefix, key_name, architecture
├── ami.tf               # SSM public parameter AMI lookup by architecture
├── network.tf           # VPC, subnets, internet gateway, route tables
├── security-groups.tf   # per-agent security groups, SG modes documented as variables
├── instances.tf         # EC2 instances for A, B, C, D with user_data references
├── outputs.tf           # public/private IPs, curl validation commands
└── user-data/
    ├── server.sh        # bootstrap physarum-server on instance A
    └── agent.sh         # bootstrap physarum-agent (parameterized by agent_id)
```

The skeleton is implemented. The EC2 bootstrap uses placeholder systemd units until the binary artifact pipeline is added.

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
Default instance type: t3.micro (Intel/x86_64, Free Tier-oriented)
Optional Graviton path: t4g.micro (arm64) — see architecture variable
t2.micro: fallback only where Free Tier eligible; do not assume
No NAT Gateway — public subnets with restricted security groups are used instead
No ALB/NLB — direct EC2 access via operator_cidr only
No Elastic IP — public IPs assigned at instance launch, released on destroy
Name prefix variable: all resources tagged/named with a common prefix for easy cleanup
Region variable: default to us-east-1 (low-cost, Free Tier-oriented)
operator_cidr must be your own IP — never use 0.0.0.0/0
No production accounts
```

**Why public subnets without NAT Gateway:**
The first version uses public subnets with an internet gateway to allow operator access to the coordinator API and SSH. This avoids the ~$0.045/hour NAT Gateway cost. Security groups restrict all inbound access to `operator_cidr` or inter-agent SG references — no broad public inbound is allowed.

**Why operator_cidr must be a single workstation IP:**
The coordinator API (port 8080) is not yet protected by authentication, mTLS, or an API gateway. The Security Group is the only access control. Using a narrow `/32` CIDR — your workstation IP — ensures that no other host on the internet can reach the API during tests. This will remain required until authentication is added.

Required cleanup:

```bash
cd examples/aws-lab/terraform
terraform destroy -var="operator_cidr=187.101.126.140/32"
```

Watch for forgotten costs:

```text
EC2 instance-hours (t3.micro: ~$0.0104/hr, t4g.micro: ~$0.0042/hr if using Graviton)
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
Runtime validation of AWS lab — Mode 1 full mesh (depends on binary upload to S3 and terraform apply with enable_artifact_download=true)
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

Default: **`t3.micro`** (Intel/x86_64, Free Tier-oriented).

The AMI is resolved automatically via SSM public parameter for the selected architecture — no region-specific AMI ID is hard-coded.

The AMI resolves to:

```text
x86_64: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
arm64:  /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
```

Optional Graviton path — use only when future Rust binaries are built for `aarch64`:

```hcl
instance_type = "t4g.micro"
architecture  = "arm64"
```

`t2.micro` may be used as a fallback only where it is Free Tier eligible in the target account and region. Free Tier eligibility depends on account age and AWS terms — do not assume.

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

The `operator_cidr` must be your workstation IP. The coordinator API (port 8080) is not
yet authenticated — the Security Group is the only access control. Use a `/32` CIDR.

Dev Lead test value: `187.101.126.140/32`. Other operators: substitute your own IP.

```bash
cd examples/aws-lab/terraform

terraform init
terraform fmt -recursive
terraform plan  -var="operator_cidr=187.101.126.140/32"
terraform apply -var="operator_cidr=187.101.126.140/32"

# Always destroy when done
terraform destroy -var="operator_cidr=187.101.126.140/32"
```

To auto-detect your current IP instead of hard-coding:

```bash
terraform plan -var="operator_cidr=$(curl -s https://checkip.amazonaws.com)/32"
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

# plan — substitute your operator CIDR; Dev Lead value: 187.101.126.140/32
docker run --rm \
  -v "$TF_DIR:/workspace" \
  -w /workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  "$TF_IMAGE" plan -var="operator_cidr=187.101.126.140/32"

# apply
docker run --rm -it \
  -v "$TF_DIR:/workspace" \
  -w /workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  "$TF_IMAGE" apply -var="operator_cidr=187.101.126.140/32"

# destroy (always run when done)
docker run --rm -it \
  -v "$TF_DIR:/workspace" \
  -w /workspace \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  "$TF_IMAGE" destroy -var="operator_cidr=187.101.126.140/32"
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
✔ 6. Terraform v0 smoke test — create/destroy validated, no runtime expected (Issue #32).
✔ 7. Design S3 artifact delivery, IAM role, and EC2 bootstrap (Issue #36, section 16).
✔ 8. Implement S3 artifact delivery + IAM role + real user_data behind enable_artifact_download flag (Issue #38, section 17).
  9. Build linux-x86_64 binaries, upload to S3, apply with enable_artifact_download=true.
 10. Validate mode 1 (full mesh) — /health, /agents, /graph, /paths all respond from EC2.
 11. Switch to mode 2 (segmented B→C→D) and validate /paths reasoning under real SG rules.
 12. Optional: validate mode 3 (restore connectivity, observe d_ij recovery).
```

---

## 15. Smoke test v0 — 2026-05-05

Infrastructure create/destroy validation. No runtime validation expected at this gate.

```text
Date:              2026-05-05
Region:            us-east-1
Terraform:         1.9.8 (Docker image hashicorp/terraform:1.9.8)
AWS provider:      6.43.0
instance_type:     t4g.micro
architecture:      arm64
AMI:               resolved via SSM public parameter (al2023-ami-kernel-default-arm64)
operator_cidr:     <operator-ip>/32 (restricted, not 0.0.0.0/0)
credentials:       AWS CLI named profile via ~/.aws mount (never committed)
```

### Phase 1 — Static checks

```text
terraform fmt -recursive -check  →  pass
terraform init                   →  success (AWS provider 6.43.0 installed)
terraform validate               →  Success! The configuration is valid.
```

### Phase 2 — Plan

```text
Plan: 32 to add, 0 to change, 0 to destroy.
No NAT Gateway, ALB/NLB, Elastic IP, RDS, or EKS in plan.
```

### Phase 3 — Apply

```text
Apply complete! Resources: 32 added, 0 changed, 0 destroyed.
```

Outputs:

```text
agent_b_private_ip = "10.50.20.10"
agent_c_private_ip = "10.50.30.10"
agent_d_private_ip = "10.50.40.10"
server_private_ip  = "10.50.10.10"
server_public_ip   = <redacted — instance destroyed>
curl_health / curl_agents / curl_graph / curl_paths_b_to_d: generated correctly
```

### Phase 4 — AWS resource inspection

```text
VPC:              physarum-lab-vpc (10.50.0.0/16) — created
Subnets:          management (10.50.10.0/24), outer (10.50.20.0/24),
                  middle (10.50.30.0/24), inner (10.50.40.0/24) — created
Internet Gateway: created and attached
EC2 instances:    4 running — physarum-server-a, physarum-agent-b, physarum-agent-c,
                  physarum-agent-d — all t4g.micro, arm64
NAT Gateway:      none (expected)
Load Balancers:   none (expected)
Elastic IPs:      none (expected)
```

### Phase 5 — Runtime endpoints

Not tested. Binary artifact pipeline not in place. `/health`, `/graph`, `/paths` not
expected at this gate. Placeholder systemd units are present on instances.

### Phase 6 — Destroy

```text
terraform destroy  →  Destroy complete! Resources: 32 destroyed.
terraform show     →  The state file is empty. No resources are represented.
AWS verify         →  0 instances running with project tag.
```

**Result: PASS** — infrastructure skeleton creates and destroys cleanly with zero leftover resources.

---

## 16. S3 Artifact Delivery and EC2 Runtime Bootstrap — Design (Issue #36)

**Status: design reference. IAM Role/Instance Profile and user_data feature flag implemented in Issue #38 (section 17). S3 bucket is pre-existing (operator-provided via artifact_bucket variable). No runtime validation is claimed in this section — see section 17 for the operator workflow.**

This section defines the intended path from Terraform skeleton to live binary deployment. The first target is `linux-x86_64`, aligned with the `t3.micro` default. An optional `linux-arm64` path is documented for future Graviton use.

---

### 16.1 Artifact strategy

Intended S3 artifact layout:

```text
s3://<artifact-bucket>/physarum-attack-paths/dev/linux-x86_64/physarum-server
s3://<artifact-bucket>/physarum-attack-paths/dev/linux-x86_64/physarum-agent
```

Future optional paths:

```text
s3://<artifact-bucket>/physarum-attack-paths/dev/linux-arm64/physarum-server
s3://<artifact-bucket>/physarum-attack-paths/dev/linux-arm64/physarum-agent

s3://<artifact-bucket>/physarum-attack-paths/releases/v0.1.0/linux-x86_64/physarum-server
s3://<artifact-bucket>/physarum-attack-paths/releases/v0.1.0/linux-x86_64/physarum-agent
```

The `dev/` prefix is operator-uploaded during testing. The `releases/` prefix is reserved for versioned builds. These paths are not yet provisioned.

---

### 16.2 Build strategy

Recommended Rust target for `t3.micro` (Intel/x86_64):

```text
x86_64-unknown-linux-gnu
```

Optional future Graviton target:

```text
aarch64-unknown-linux-gnu
```

Three build options, in preference order:

**Option A (recommended): Docker-based cross-compile from Dev Lead machine**

Build Linux x86_64 binaries in a Docker container running on the MacBook without requiring a separate EC2 builder. No GitHub Actions required yet.

Use a pinned Rust image version for reproducibility — do not use `latest`. Replace `1.85-bookworm` with the current stable release if different:

Primary target — `x86_64-unknown-linux-gnu` (dynamically linked, simpler build):

```bash
docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  rust:1.85-bookworm \
  cargo build --release --target x86_64-unknown-linux-gnu \
    -p physarum-server -p physarum-agent
```

Output location:

```text
target/x86_64-unknown-linux-gnu/release/physarum-server
target/x86_64-unknown-linux-gnu/release/physarum-agent
```

Optional — `x86_64-unknown-linux-musl` (fully static binary, easier to deploy but requires musl tooling in the container). The command below is illustrative only; exact linker packages needed may vary by base image and have not yet been validated:

```bash
# Illustrative — validate in implementation gate before use
docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  rust:1.85-bookworm \
  sh -c "apt-get install -y musl-tools && \
         rustup target add x86_64-unknown-linux-musl && \
         cargo build --release --target x86_64-unknown-linux-musl \
           -p physarum-server -p physarum-agent"
```

Output location (if musl path is used):

```text
target/x86_64-unknown-linux-musl/release/physarum-server
target/x86_64-unknown-linux-musl/release/physarum-agent
```

The S3 `linux-x86_64/` prefix accepts binaries from either target. The build method (gnu vs musl) must be documented in the upload step during the implementation gate.

**Exact Docker build commands must be validated in the implementation gate before use.**

**Option B: build on temporary EC2 x86_64 builder**

Launch a separate `t3.micro` EC2 instance, install Rust toolchain, clone the repo, build, upload to S3, terminate. Acceptable if Docker cross-compile is not viable.

**Option C (fallback only): build on instance during bootstrap**

Compile directly in `user_data` at instance launch. Not preferred — adds minutes of startup latency, requires internet access for `cargo`, and is fragile. Use only if Options A and B are not available.

Exact Docker build commands are follow-up implementation details once the design gate is merged.

---

### 16.3 S3 artifact bucket requirements

```text
Visibility:        private — no public access
Block public ACLs: enabled (BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets)
Encryption:        server-side encryption enabled (SSE-S3 minimum; SSE-KMS optional)
Versioning:        recommended — allows rollback of a bad binary without re-uploading
Bucket name:       variable-driven, not hard-coded in Terraform
No public object ACLs
No AWS credentials stored in the bucket
No secrets in object key names
```

Planned Terraform variable:

```hcl
variable "artifact_bucket" {
  description = "Name of the private S3 bucket storing physarum-server and physarum-agent binaries"
  type        = string
}
```

---

### 16.4 EC2 IAM Role requirements

EC2 instances must use an IAM Role and Instance Profile — no static AWS keys in `user_data`, no environment variables with credentials on EC2.

Minimum IAM permission:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::<artifact-bucket>/physarum-attack-paths/dev/linux-x86_64/*"
}
```

Scope is restricted to the artifact prefix only. Do not use `s3:*` or broad bucket-level access.

The Instance Profile attaches the IAM Role to the EC2 instances so that the AWS CLI inside `user_data` can authenticate without static credentials.

---

### 16.5 Terraform variables (future)

Variables required when the implementation gate begins:

```hcl
variable "artifact_bucket" {
  description = "Private S3 bucket name for physarum binaries"
  type        = string
}

variable "artifact_prefix" {
  description = "S3 key prefix for binaries, e.g. physarum-attack-paths/dev/linux-x86_64"
  type        = string
  default     = "physarum-attack-paths/dev/linux-x86_64"
}

variable "artifact_region" {
  description = "AWS region where the artifact bucket resides"
  type        = string
  default     = "us-east-1"
}
```

Optional:

```hcl
variable "enable_artifact_download" {
  description = "If true, user_data downloads binaries from S3 instead of using placeholder units"
  type        = bool
  default     = false
}
```

These variables are implemented in `variables.tf` (Issue #38). `artifact_bucket` defaults to `""`, `enable_artifact_download` defaults to `false` — a plain `terraform apply` without these variables set uses placeholder mode and does not attempt S3 access.

---

### 16.6 user_data bootstrap design

The systemd unit templates below are design sketches only. **The exact `ExecStart` flags must be verified against `physarum-server --help` and `physarum-agent --help` in the implementation gate** — the current binary CLI interface takes precedence over anything shown here.

**`user-data/server.sh` — future behavior (pseudocode):**

```bash
# Download physarum-server binary from S3
aws s3 cp "s3://${artifact_bucket}/${artifact_prefix}/physarum-server" \
  /usr/local/bin/physarum-server
chmod +x /usr/local/bin/physarum-server

# Create systemd unit
cat > /etc/systemd/system/physarum-server.service <<EOF
[Unit]
Description=Physarum Server
After=network.target

[Service]
ExecStart=/usr/local/bin/physarum-server --listen 0.0.0.0:8080
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable physarum-server
systemctl start physarum-server
```

**`user-data/agent.sh` — future behavior (pseudocode):**

```bash
# Download physarum-agent binary from S3
aws s3 cp "s3://${artifact_bucket}/${artifact_prefix}/physarum-agent" \
  /usr/local/bin/physarum-agent
chmod +x /usr/local/bin/physarum-agent

# Create systemd unit (agent_id, listen_port, coordinator_ip, advertise_address
# are injected by Terraform templatefile())
cat > /etc/systemd/system/physarum-agent.service <<EOF
[Unit]
Description=Physarum Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/physarum-agent \
  --id ${agent_id} \
  --coordinator http://${coordinator_ip}:8080 \
  --listen 0.0.0.0:${listen_port} \
  --advertise-address ${advertise_address} \
  --probe-interval-seconds 5
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable physarum-agent
systemctl start physarum-agent
```

The real `user-data/server.sh` and `user-data/agent.sh` now implement this pattern (Issue #38). AWS CLI presence is verified at runtime — `dnf install -y awscli2` is called if `aws` is not found. No static credentials are used; the IAM Instance Profile provides access.

---

### 16.7 Runtime validation plan

After binary deployment, validation commands must be run from `187.101.126.140/32` (Dev Lead workstation). The coordinator API (port 8080) is not yet authenticated — the Security Group is the only access control. Do not open `operator_cidr` to `0.0.0.0/0` for this validation.

```bash
SERVER_IP=$(terraform -chdir=examples/aws-lab/terraform output -raw server_public_ip)

# Health check
curl -s "http://${SERVER_IP}:8080/health" | jq

# Agent registration — expect agent-b, agent-c, agent-d
curl -s "http://${SERVER_IP}:8080/agents" | jq

# Edge graph — Mode 1: expect 6 directed edges, all probe_success=true
curl -s "http://${SERVER_IP}:8080/graph" | jq

# Adaptive paths — Mode 1: expect both B→D and B→C→D
curl -s "http://${SERVER_IP}:8080/paths?source=agent-b&target=agent-d" | jq
```

The `outputs.tf` already generates these commands with real IPs substituted. The commands above show the pattern for documentation purposes.

---

### 16.8 Success criteria (future runtime gate)

The runtime gate passes when:

```text
Mode 1 — full mesh:
  server-a systemd service active and healthy
  agent-b, agent-c, agent-d systemd services active and registered
  /health returns 200 OK
  /agents lists agent-b, agent-c, agent-d
  /graph shows 6 directed edges — all probe_success=true, q_ema>0, d_ij>0
  /paths?source=agent-b&target=agent-d returns both B→D and B→C→D paths
  terraform destroy succeeds after test — 0 resources remaining
  no secrets committed

Mode 2 — segmented B→C→D (subsequent gate):
  B→D security group rule removed
  B→D edge decays: probe_success=false, q_ema→0, d_ij→0
  B→C and C→D edges remain healthy
  /paths returns only B→C→D for source=agent-b target=agent-d
  terraform destroy succeeds
```

---

### 16.9 Remaining out of scope

The following remain deferred:

```text
S3 bucket Terraform resource (operator provides pre-existing bucket — Option B)
artifact upload automation or CI pipeline
AWS runtime apply and endpoint testing (Mode 1 — next gate)
GitHub Actions build/release pipeline
segmented B→C→D runtime validation (Mode 2)
remote Terraform state
mTLS or API authentication
persistence and replay
WASM simulator
```

Implemented in Issue #38 (no longer deferred):

```text
IAM Role and Instance Profile Terraform resources — iam.tf
artifact variables — variables.tf (artifact_bucket, artifact_prefix, artifact_region, enable_artifact_download)
real user_data download and systemd startup behind enable_artifact_download feature flag
```

---

## 17. S3 Artifact Delivery — Build, Upload, and Apply Workflow (Issue #38)

**Status: Terraform and user_data support implemented. Binary upload and AWS runtime validation are not yet performed — those are the next gate.**

This section documents the Terraform and user_data changes shipped in Issue #38 and the operator workflow that will be executed in the runtime validation gate. No binary has been uploaded to S3 and no EC2 runtime endpoints have been validated in this PR.

The S3 bucket must be created outside this Terraform stack (Option B from section 16.2). This keeps the artifact store separate from the disposable lab infrastructure — `terraform destroy` does not delete the bucket.

---

### 17.1 Prerequisites

```text
- Pre-existing private S3 bucket with server-side encryption and public access blocked
- AWS credentials with s3:PutObject on the bucket (for binary upload)
- AWS credentials for terraform apply (must be able to create EC2, IAM, VPC resources)
- operator_cidr set to your workstation IP — never 0.0.0.0/0
```

---

### 17.2 Step 1 — Verify CLI flags

Verified 2026-05-06 from source:

```bash
cargo run -p physarum-server -- --help
# Options:
#   --listen <LISTEN>  [default: 0.0.0.0:8080]

cargo run -p physarum-agent -- --help
# Options:
#   --id <ID>                           (required)
#   --coordinator <COORDINATOR>         (required)
#   --listen <LISTEN>                   (required)
#   --advertise-address <ADDR>          (required)
#   --probe-interval-seconds <N>        [default: 10]
```

The `user-data/` systemd units use these exact flags.

---

### 17.3 Step 2 — Build Linux x86_64 binaries

Use the pinned Rust image. Run from the repository root:

```bash
docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  rust:1.85-bookworm \
  cargo build --release --target x86_64-unknown-linux-gnu \
    -p physarum-server -p physarum-agent
```

Output:

```text
target/x86_64-unknown-linux-gnu/release/physarum-server
target/x86_64-unknown-linux-gnu/release/physarum-agent
```

---

### 17.4 Step 3 — Upload binaries to S3

```bash
BUCKET=<your-artifact-bucket>
PREFIX=physarum-attack-paths/dev/linux-x86_64

aws s3 cp target/x86_64-unknown-linux-gnu/release/physarum-server \
  s3://$BUCKET/$PREFIX/physarum-server

aws s3 cp target/x86_64-unknown-linux-gnu/release/physarum-agent \
  s3://$BUCKET/$PREFIX/physarum-agent
```

The `PREFIX` value must match `artifact_prefix` passed to Terraform (default: `physarum-attack-paths/dev/linux-x86_64`).

---

### 17.5 Step 4 — Apply with artifact download enabled

```bash
cd examples/aws-lab/terraform

terraform init
terraform plan \
  -var="operator_cidr=187.101.126.140/32" \
  -var="artifact_bucket=<your-artifact-bucket>" \
  -var="enable_artifact_download=true"

terraform apply \
  -var="operator_cidr=187.101.126.140/32" \
  -var="artifact_bucket=<your-artifact-bucket>" \
  -var="enable_artifact_download=true"
```

Dev Lead test value for `operator_cidr`: `187.101.126.140/32`. Other operators: substitute your own IP.

`artifact_region` defaults to `aws_region` (`us-east-1`). Set explicitly if the bucket is in a different region:

```bash
  -var="artifact_region=us-west-2"
```

**Safe default behavior:** a plain `terraform apply` without `artifact_bucket` or `enable_artifact_download` uses the placeholder systemd units. No S3 access is attempted.

---

### 17.6 Step 5 — Validate runtime (Mode 1)

Allow approximately 2 minutes for `user_data` to complete after `terraform apply`.

```bash
SERVER_IP=$(cd examples/aws-lab/terraform && terraform output -raw server_public_ip)

# Health check
curl -s "http://$SERVER_IP:8080/health" | jq

# Agent registration — expect agent-b, agent-c, agent-d
curl -s "http://$SERVER_IP:8080/agents" | jq

# Edge graph — Mode 1: expect 6 directed edges, all probe_success=true
curl -s "http://$SERVER_IP:8080/graph" | jq

# Adaptive paths — Mode 1: expect both B→D and B→C→D
curl -s "http://$SERVER_IP:8080/paths?source=agent-b&target=agent-d" | jq
```

The `outputs.tf` emits these commands with real IPs after apply.

---

### 17.7 Step 6 — Destroy

Always destroy after testing to avoid ongoing EC2 charges:

```bash
cd examples/aws-lab/terraform

terraform destroy \
  -var="operator_cidr=187.101.126.140/32" \
  -var="artifact_bucket=<your-artifact-bucket>" \
  -var="enable_artifact_download=true"
```

The S3 bucket and its contents are not destroyed — they exist outside this Terraform stack.

---

### 17.8 Terraform layout changes (Issue #38)

New and modified files:

```text
terraform/
├── iam.tf               # NEW — IAM role, instance profile, conditional s3:GetObject policy
├── variables.tf         # UPDATED — artifact_bucket, artifact_prefix, artifact_region,
│                        #           enable_artifact_download added
├── instances.tf         # UPDATED — iam_instance_profile on all 4 EC2 instances;
│                        #           new template vars passed to user-data
└── user-data/
    ├── server.sh        # UPDATED — feature flag: real download or placeholder
    └── agent.sh         # UPDATED — feature flag: real download or placeholder
```

IAM resources created by `iam.tf`:

```text
aws_iam_role            physarum-ec2-role        — assume role for ec2.amazonaws.com
aws_iam_instance_profile physarum-ec2-profile    — attached to all 4 EC2 instances
aws_iam_role_policy     physarum-s3-artifact     — s3:GetObject scoped to artifact prefix
                                                    (created only when enable_artifact_download=true
                                                     and artifact_bucket is non-empty)
```

EC2 instances authenticate to S3 via the Instance Profile. No static AWS credentials are placed in `user_data` or committed to this repository.

---

## 18. AWS Mode 1 Runtime Validation — PASS

**Result: PASSED**
**Date:** 2026-05-06
**Region:** us-east-1
**PR:** #43

### Environment

```text
instance_type      = t3.micro
architecture       = x86_64
AMI                = Amazon Linux 2023 (ami-027a2644c5c1d0aff)
artifact delivery  = S3 + EC2 IAM Instance Profile (no static credentials)
operator access    = SSH only from 187.101.126.140/32
public port 8080   = NOT exposed (removed in PR #42)
validation method  = Ansible playbook via SSH (validate-runtime.yml)
```

### Root cause of first failed run

```text
user_data contained: dnf install -y jq curl
AL2023 ships curl-minimal which conflicts with curl (full package)
DNF exited non-zero
set -euxo pipefail aborted the bootstrap script
systemd units were never written; binaries never downloaded
agents never registered
fix: install jq only; curl-minimal already provides the curl binary
```

### Ansible recap

```text
server-a  ok=24  changed=0  unreachable=0  failed=0  skipped=0
agent-b   ok=13  changed=0  unreachable=0  failed=0  skipped=2
agent-c   ok=12  changed=0  unreachable=0  failed=0  skipped=3
agent-d   ok=12  changed=0  unreachable=0  failed=0  skipped=3
```

### Assertions passed

```text
/health                    OK — non-empty response
/agents                    agent-b registered
/agents                    agent-c registered
/agents                    agent-d registered
/graph                     OK — non-empty response
/paths?source=agent-b&target=agent-d  OK — non-empty, contains agent-b and agent-d
agent-b listener port 9001 confirmed
agent-c listener port 9002 confirmed
agent-d listener port 9003 confirmed
terraform destroy          39 resources destroyed cleanly
```

### Mode 2 next

AWS Mode 2 (segmented B→C→D) is the next validation gate. Security group rules blocking direct B↔D traffic will be added; `/paths` must route exclusively through C.
