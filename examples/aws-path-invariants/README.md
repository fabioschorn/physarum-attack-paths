# AWS Path Invariants Lab

This lab is a Gate K.1-inspired AWS topology for validating Issue #201 path
selection behavior in the current `physarum-maze` runtime.

It intentionally starts with infrastructure only:

- Terraform creates the VPC, public subnets, Internet Gateway, route tables,
  EC2 instances and security groups.
- Ansible will later install `physarum-maze`, vulnerable services, and
  validation checks.
- No CVE software is installed by this first layer.

## Goal

Validate `physarum-maze` `/paths` behavior under a real AWS VPC topology:

```text
seed/source → target-e              direct path
seed/source → target-c → target-d → target-e
```

The intended invariant tests are:

- healthy direct path wins over an equally healthy longer path;
- degraded direct path loses to a healthy indirect path;
- recovered direct path becomes preferred again;
- dead-end/degraded edges do not outrank live alternatives.

## Topology

The old Gate K.1 lab used a separate `physarum-server` coordinator plus agents.
This lab collapses that shape for `physarum-maze`: the seed instance is both the
operator-visible controller and the graph/dashboard server.

```text
VPC: 10.50.0.0/16

outer subnet:      10.50.20.0/24
  seed-b:          10.50.20.10   physarum-maze seed, dashboard :8443

middle subnet:     10.50.30.0/24
  target-c:        10.50.30.10

inner subnet:      10.50.40.0/24
  target-d:        10.50.40.10

secondary subnet:  10.50.50.0/24
  target-e:        10.50.50.10
```

Security-group intent:

```text
laptop → seed-b:     SSH 22, HTTPS dashboard 8443
laptop → targets:    SSH 22, for Ansible bootstrap/inspection
targets → seed-b:    internal mTLS/report/bootstrap ports + ICMP stimulus
seed-b → target-c:   internal lab traffic
seed-b → target-e:   internal lab traffic
target-c → target-d: internal lab traffic
target-d → target-e: internal lab traffic
target-c → target-e: blocked by omission, preserving the Gate K.1 shape
```

All instances receive public IPs and have outbound Internet access through the
VPC Internet Gateway. This is required for package installation, artifact
download, and the seed's LLM endpoint access.

## Operator IP

Before running Terraform, determine the current public IP of the laptop:

```bash
curl -s https://checkip.amazonaws.com
```

Then pass it as a `/32` CIDR:

```bash
terraform apply \
  -var="operator_cidr=$(curl -s https://checkip.amazonaws.com | tr -d '\n')/32"
```

Do not use `0.0.0.0/0`. The Terraform variable validation rejects it.

## First run: Terraform only

From this directory:

```bash
mkdir -p examples/aws-path-invariants/.keys
cp examples/aws-lab/.keys/physarum-lab-devlead \
  examples/aws-path-invariants/.keys/physarum-path-invariants
cp examples/aws-lab/.keys/physarum-lab-devlead.pub \
  examples/aws-path-invariants/.keys/physarum-path-invariants.pub
chmod 600 examples/aws-path-invariants/.keys/physarum-path-invariants

cd examples/aws-path-invariants/terraform
terraform init
terraform plan \
  -var="operator_cidr=<YOUR_PUBLIC_IP>/32"
terraform apply \
  -var="operator_cidr=<YOUR_PUBLIC_IP>/32"
```

This first run should prove only that infrastructure is correct:

- VPC and public subnets exist;
- each instance has a public IP;
- the seed downloaded `/usr/local/bin/physarum-maze` from S3;
- the seed allows `8443` only from the operator CIDR;
- the seed allows ICMP only from the lab target security groups;
- all instances have outbound Internet connectivity;
- SSH from the operator works for Ansible.

## Later layers

The next layers should be added separately:

1. Ansible launch of the already-installed seed `physarum-maze` binary.
2. `/paths` validation playbook using HTTPS + Basic Auth:

   ```bash
   curl -sk --netrc-file /path/to/local/netrc \
     'https://127.0.0.1:8443/paths?source=<source>&target=<target>'
   ```

   Prefer running this check from the seed over SSH so validation does not
   depend on public Internet routing to `8443`.
   Use a local, uncommitted `.netrc` entry with the lab dashboard credential
   configured for the run; do not commit real login values or copied
   `sensitive-info` files.

3. CVE service installation playbooks.
4. Real AWS evidence capture for Issue #201 item 5.

## PolicyGate CIDR

`physarum-maze` does not need AWS-specific hardcoded ranges. For this VPC, run
the seed with:

```bash
--llm-allowed-cidr 10.50.0.0/16
```

`PolicyGate` will reject LLM-assisted propagation attempts outside this VPC CIDR.

For manual AWS sessions, prefer the longer dormancy window used by the lab
outputs:

```bash
sudo --preserve-env=LLM_API_KEY \
  /usr/local/bin/physarum-maze \
  --llm-endpoint https://api.openai.com \
  --llm-model gpt-4o-mini \
  --llm-allowed-cidr 10.50.0.0/16 \
  --exploit-enabled \
  --server 8443 \
  --tls \
  --stimulus-timeout-secs 3600
```

## Observed discovery and stimulus behavior

The `--llm-allowed-cidr` value is a policy boundary, not a full proactive
discovery scope. In this lab, `10.50.0.0/16` allows the LLM and `PolicyGate` to
reason about the whole VPC, but the current startup sweep still follows the
selected local interface prefix. On the seed instance this means the first sweep
is local to `10.50.20.0/24`, so it does not automatically discover targets in
`10.50.30.0/24`, `10.50.40.0/24`, or `10.50.50.0/24`.

This is expected with the current Docker-lab-oriented discovery model and is a
useful AWS finding for Issue #201: future AWS validation should introduce an
explicit discovery scope, target inventory, or Terraform/Ansible-generated seed
hints that are separate from the policy CIDR.

The packet and eBPF paths are also stimulus-driven:

- ICMP and TCP-SYN listeners react to inbound traffic received by the seed.
- eBPF observation is enabled only when the seed is launched with a compiled
  `--bpf-bytecode` artifact.
- Passive observation alone does not create traffic. To exercise the current
  stimulus path, a target should send traffic toward the seed, for example
  `ping -c 1 10.50.20.10`.

Terraform now allows ICMP ingress from the target security groups to the seed,
so a target-to-seed ping can reach the ICMP listener and become a real
`physarum-maze` stimulus. TCP-SYN stimuli follow the same rule: if a later test
uses a TCP connection attempt, the seed security group must allow the tested
destination port from the target security group.

After `terraform apply`, use the `manual_stimulus_checks` output as the
operator-facing checklist. Each command SSHes into one target and sends one ICMP
echo request to the seed private IP.

The binary also has an inactivity dormancy timer. By default,
`--stimulus-timeout-secs` is `360`, and the process exits after that many
seconds without ICMP, TCP-SYN, eBPF, or discovered-candidate stimulus. Periodic
sweeps run every `--discovery-interval-secs` seconds, default `180`, but a sweep
that finds no candidates does not renew the dormancy timer. For longer manual
AWS sessions, launch the seed with a larger value such as:

```bash
--stimulus-timeout-secs 3600
```

## Seed binary delivery

The seed follows the historical AWS lab pattern: Terraform attaches an EC2 IAM
instance profile and user data downloads the binary from S3 without static AWS
credentials.

Default object:

```text
s3://physarum-artifacts-168740128169/physarum-attack-paths/issue-201/aws-path-invariants/amazonlinux2023-x86_64/physarum-maze
```

Override these when testing a different build:

```bash
terraform apply \
  -var="operator_cidr=<YOUR_PUBLIC_IP>/32" \
  -var="artifact_bucket=<BUCKET>" \
  -var="artifact_prefix=<PREFIX>" \
  -var="artifact_region=us-east-1"
```
