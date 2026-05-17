# AWS Lab — Ansible Runtime Validation

Ansible replaces public `curl` for runtime validation. All checks run through SSH from the Dev Lead workstation; port 8080 is no longer exposed publicly.

## Prerequisites

- Ansible >= 2.14 installed locally (`pip install ansible`)
- SSH key generated at `examples/aws-lab/.keys/physarum-lab-devlead` (see below — **must exist before `terraform plan`**)
- Terraform applied with `enable_artifact_download=true`
- Your IP matches `operator_cidr` (SSH is the only public access)

## SSH key setup

**Generate the key before `terraform plan` or `terraform apply`.** Terraform will fail immediately if the public key file does not exist (validation is enforced in `variables.tf`).

```bash
mkdir -p examples/aws-lab/.keys
ssh-keygen -t ed25519 \
  -f examples/aws-lab/.keys/physarum-lab-devlead \
  -C "physarum-aws-lab" \
  -N ""
```

The public key is consumed by Terraform (`ssh_public_key_path` variable). Both files are gitignored — never commit them.

## Inventory

Two inventory options are available. The dynamic inventory is preferred for normal lab runs.

### Option A — Dynamic inventory (recommended)

No manual IP editing required. EC2 public IPs are read from AWS at runtime via instance tags set by Terraform.

**Additional prerequisites:**

```bash
pip install boto3 botocore
ansible-galaxy collection install amazon.aws
```

AWS credentials must be available (environment variables, `~/.aws/credentials`, or an IAM role on the workstation).

**Verify discovery after `terraform apply`:**

```bash
ansible-inventory \
  -i examples/aws-lab/ansible/aws_ec2.yml \
  --graph
```

Expected output for gate-l2:

```
@all:
  |--@server:
  |  |--<agent-b public IP>
  |--@node_a:
  |  |--<agent-b public IP>     # same host, two groups
  |--@node_b:
  |  |--<agent-c public IP>
  |--@node_c:
  |  |--<agent-d public IP>
```

**Run validation playbook:**

```bash
ansible-playbook \
  -i examples/aws-lab/ansible/aws_ec2.yml \
  examples/aws-lab/ansible/validate-gate-l2-local-interface.yml
```

The `aws_ec2.yml` file currently hardcodes gate-l2 private IPs (`coordinator_ip`, `node_a_ip`). These are deterministic (set by `cidrhost` in Terraform) and do not change between apply/destroy cycles. Public IPs are always resolved dynamically.

### Option B — Static inventory (fallback)

Use when AWS credentials are unavailable or for offline syntax checks.

After `terraform apply`, collect outputs:

```bash
cd examples/aws-lab/terraform
terraform output -json > ../ansible/terraform-outputs.local.json
```

For gate-l2, update `examples/aws-lab/ansible/inventory.local.ini` with the three public IPs:

```bash
# Get the IPs
terraform -chdir=examples/aws-lab/terraform output agent_b_public_ip
terraform -chdir=examples/aws-lab/terraform output agent_c_public_ip
terraform -chdir=examples/aws-lab/terraform output agent_d_public_ip
```

Replace `REPLACE_AGENT_B_PUBLIC_IP`, `REPLACE_AGENT_C_PUBLIC_IP`, `REPLACE_AGENT_D_PUBLIC_IP` in `inventory.local.ini`.

`inventory.local.ini` is gitignored.

**Run validation playbook:**

```bash
ansible-playbook \
  -i examples/aws-lab/ansible/inventory.local.ini \
  examples/aws-lab/ansible/validate-gate-l2-local-interface.yml
```

## What the gate-l2 playbook checks

`validate-gate-l2-local-interface.yml` collects five evidence blocks (Issue #86 acceptance criteria):

1. **Node A derives local-interface scope** — `/agents` API + journal shows `10.50.20.0/24` derived from eth0
2. **B and C send inbound TCP stimulus to A** — stimulus sent via `/dev/tcp`, flow observations verified via `/flow-observations`
3. **ebpf_seed_loop creates seeds** — journal shows eBPF cues + trigger provenance reports for B and C IPs
4. **Candidates carry trigger=ebpf_new_inbound_host** — `/candidate-discoveries` assertions per IP
5. **Probe validation and graph safety** — `/graph` and `/paths` confirm edges only after probe success

## SSH tunnel for manual curl (optional)

Port 8080 is not publicly exposed. Use an SSH tunnel to run `curl` manually:

```bash
# gate-l2: coordinator is agent-b
ssh -i examples/aws-lab/.keys/physarum-lab-devlead \
  -L 18080:127.0.0.1:8080 \
  ec2-user@<agent_b_public_ip>
```

Then in another terminal:

```bash
curl -s http://127.0.0.1:18080/health | jq
curl -s http://127.0.0.1:18080/agents | jq
curl -s http://127.0.0.1:18080/graph | jq
curl -s 'http://127.0.0.1:18080/candidate-discoveries?agent_id=agent-b' | jq
```

## Syntax check (CI / pre-apply)

```bash
ansible-playbook --syntax-check \
  -i examples/aws-lab/ansible/inventory.gate-l2.example.ini \
  examples/aws-lab/ansible/validate-gate-l2-local-interface.yml
```
