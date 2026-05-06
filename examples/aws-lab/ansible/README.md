# AWS Lab — Ansible Runtime Validation

Ansible replaces public `curl` for runtime validation. All checks run through SSH from the Dev Lead workstation; port 8080 is no longer exposed publicly.

## Prerequisites

- Ansible >= 2.14 installed locally (`pip install ansible`)
- SSH key generated at `examples/aws-lab/.keys/physarum-lab-devlead` (see below)
- Terraform applied with `enable_artifact_download=true`
- Your IP matches `operator_cidr` (SSH is the only public access)

## SSH key setup

Generate once, before the first `terraform apply`:

```bash
mkdir -p examples/aws-lab/.keys
ssh-keygen -t ed25519 \
  -f examples/aws-lab/.keys/physarum-lab-devlead \
  -C "physarum-aws-lab" \
  -N ""
```

The public key is consumed by Terraform (`ssh_public_key_path` variable). Both files are gitignored — never commit them.

## Inventory

After `terraform apply`, collect outputs and create a local inventory:

```bash
cd examples/aws-lab/terraform
terraform output -json > ../ansible/terraform-outputs.local.json
```

Then create `examples/aws-lab/ansible/inventory.local.ini` using `inventory.aws-lab.example.ini` as template. Replace `<server_public_ip>`, `<agent_b_public_ip>`, etc. with values from `terraform-outputs.local.json`.

`inventory.local.ini` is gitignored.

## Run the playbook

From the repo root:

```bash
ansible-playbook \
  -i examples/aws-lab/ansible/inventory.local.ini \
  examples/aws-lab/ansible/validate-runtime.yml
```

## What the playbook checks

**All nodes:**
- `physarum-server` and `physarum-agent` systemd status
- Cloud-init output log (artifact download diagnostics)
- Journal excerpts for both services

**server-a (coordinator):**
- `GET /health` — server liveness
- `GET /agents` — agent-b, agent-c, agent-d registered
- `GET /graph` — Mode 1 full-mesh edges present
- `GET /paths?source=agent-b&target=agent-d` — path scoring

**agent-b / c / d:**
- Listener port check: 9001 (B), 9002 (C), 9003 (D)

## SSH tunnel for manual curl (optional)

If you want to run `curl` manually without opening port 8080:

```bash
ssh -i examples/aws-lab/.keys/physarum-lab-devlead \
  -L 18080:127.0.0.1:8080 \
  ec2-user@<server_public_ip>
```

Then in another terminal:

```bash
curl -s http://127.0.0.1:18080/health | jq
curl -s http://127.0.0.1:18080/agents | jq
curl -s http://127.0.0.1:18080/graph | jq
curl -s 'http://127.0.0.1:18080/paths?source=agent-b&target=agent-d' | jq
```

## Syntax check (CI / pre-apply)

```bash
ansible-playbook --syntax-check \
  -i examples/aws-lab/ansible/inventory.aws-lab.example.ini \
  examples/aws-lab/ansible/validate-runtime.yml
```
