# AWS Lab — Future EC2/VPC Test Plan

This document defines the future AWS-based laboratory for `physarum-attack-paths`.

The AWS lab is intended to validate the project in a more realistic network environment than local processes or Docker containers. It should use EC2 instances, VPC networking, subnets, routing, and security groups to simulate segmented infrastructure and observe how the adaptive graph responds to real network reachability and blocking conditions.

This document is only a test plan. It intentionally does not include Terraform code yet.

---

## 1. Purpose

The purpose of the AWS lab is to validate the behavior of the adaptive graph in real cloud network conditions:

```text
separate EC2 instances
separate subnets
security groups
controlled reachability
blocked traffic
restored traffic
real RTT differences
future onion-layer simulation
```

The AWS lab should eventually prove that:

```text
D_ij increases when agents can reach each other
q_ema increases under stable successful probes
D_ij decays when reachability is blocked
q_ema decays when recent local observations fail
/graph reflects asymmetric network behavior
future /paths can reason over real segmentation
```

---

## 2. Relationship to other labs

```text
examples/local-lab
  Manual single-host, multi-terminal execution.

examples/docker-lab
  Fast and reproducible containerized A/B/C execution.

examples/aws-lab
  Realistic EC2/VPC/subnet/security-group execution.
```

Docker is for speed. AWS is for realism.

The AWS lab should not replace the Docker lab. It should validate behavior that Docker cannot represent well, especially real segmentation and security-group-driven reachability.

---

## 3. Recommended implementation sequence

Do not implement the full AWS lab immediately.

Recommended order:

```text
1. Finish Docker A/B/C lab.
2. Validate the Docker lab repeatedly.
3. Keep A/B/C AWS lab design documented.
4. Later add Terraform skeleton.
5. Later implement minimal AWS A/B/C deployment.
6. Later extend to A/B/C/D.
7. Later connect A/B/C/D to /paths and path scoring.
```

---

## 4. Initial AWS topology — A/B/C

The first AWS lab should use three EC2 instances:

```text
A = physarum-server
B = physarum-agent
C = physarum-agent
```

Suggested logical placement:

```text
A = management/coordinator subnet
B = application/perimeter-like subnet
C = data/internal-like subnet
```

Example VPC plan:

```text
VPC CIDR: 10.50.0.0/16

management subnet: 10.50.10.0/24
  A / physarum-server: 10.50.10.10

app subnet: 10.50.20.0/24
  B / physarum-agent: 10.50.20.10

data subnet: 10.50.30.0/24
  C / physarum-agent: 10.50.30.10
```

This placement is conceptual. Exact CIDRs and IPs may change when Terraform is introduced.

---

## 5. Future AWS topology — A/B/C/D

After the A/B/C AWS lab works, add a fourth agent:

```text
A = physarum-server / coordinator
B = perimeter-like agent
C = application/gateway-like agent
D = crown-jewel/database-like agent
```

Suggested logical placement:

```text
B = outer or app-facing layer
C = middle application/service layer
D = inner data/crown-jewel layer
```

This is the topology that will become more useful for:

```text
/paths
path scoring
onion-layer modeling
future path-density exploration
```

---

## 6. Security group test scenarios

The most important value of the AWS lab is controlled reachability.

### Scenario 1 — symmetric reachability

Allow B and C to probe each other:

```text
B -> C allowed
C -> B allowed
```

Expected result:

```text
agent-b -> agent-c exists
agent-c -> agent-b exists
probe_success == true for both edges
q_ema > 0.0 for both edges
D_ij > 0.0 for both edges
```

### Scenario 2 — asymmetric reachability

Allow only B to probe C:

```text
B -> C allowed
C -> B blocked
```

Expected result:

```text
agent-b -> agent-c reinforced
agent-c -> agent-b weak or decaying
/graph shows directional asymmetry
```

This is important because attack paths are directed.

### Scenario 3 — full block

Block B and C from probing each other:

```text
B -> C blocked
C -> B blocked
```

Expected result:

```text
probe_success == false after new reports
q_ema trends down
D_ij decays over time
```

### Scenario 4 — restore connectivity

Restore B and C connectivity after a blocked period:

```text
B -> C restored
C -> B restored
```

Expected result:

```text
success_rate recovers in the agent short-term window
q_ema begins rising again
D_ij begins reinforcing again
```

This scenario validates the separation between short-term sensing and long-term morphology.

---

## 7. Expected process commands on EC2

Server A should run:

```bash
physarum-server --listen 0.0.0.0:8080
```

Agent B should run:

```bash
physarum-agent \
  --id agent-b \
  --coordinator http://<server-private-ip>:8080 \
  --listen 0.0.0.0:9001 \
  --advertise-address <agent-b-private-ip> \
  --probe-interval-seconds 5
```

Agent C should run:

```bash
physarum-agent \
  --id agent-c \
  --coordinator http://<server-private-ip>:8080 \
  --listen 0.0.0.0:9002 \
  --advertise-address <agent-c-private-ip> \
  --probe-interval-seconds 5
```

For AWS, `advertise-address` should normally be the EC2 private IP address, not the public IP.

---

## 8. Coordinator validation commands

From a machine that can reach the coordinator:

```bash
curl -s http://<server-private-or-public-ip>:8080/health | jq
curl -s http://<server-private-or-public-ip>:8080/agents | jq
curl -s http://<server-private-or-public-ip>:8080/peers/agent-b | jq
curl -s http://<server-private-or-public-ip>:8080/graph | jq
```

Expected properties:

```text
agent-b is registered
agent-c is registered
agent-b sees agent-c as peer
agent-c sees agent-b as peer
/graph shows directed edges according to security group reachability
q_ema responds to recent success/failure
d_ij responds to q_ema over time
```

---

## 9. Future Terraform scope

Terraform should eventually create:

```text
VPC
subnets
route tables
security groups
EC2 instances
IAM role for SSM Session Manager
user_data or cloud-init scripts
outputs for private IPs and validation commands
```

The first Terraform implementation should be intentionally minimal.

Suggested future directory:

```text
examples/aws-lab/terraform/
├── versions.tf
├── providers.tf
├── variables.tf
├── outputs.tf
├── vpc.tf
├── security-groups.tf
├── ec2.tf
└── user-data/
    ├── server.sh
    ├── agent-b.sh
    └── agent-c.sh
```

Do not add this Terraform code until the Docker lab is implemented and validated.

---

## 10. Cost and cleanup considerations

Any future AWS lab must include clear cleanup instructions.

Required cleanup command once Terraform exists:

```bash
terraform destroy
```

The README should eventually warn about:

```text
EC2 hourly costs
EBS volumes
Elastic IPs if used
NAT Gateway costs if used
CloudWatch logs if configured
forgotten resources
```

Avoid NAT Gateway in the first version unless absolutely necessary. Prefer private subnets with SSM or a very simple public test lab during early experiments.

---

## 11. Security considerations

This lab must remain controlled and authorized.

Rules:

```text
Only deploy into owned AWS accounts.
Do not scan public targets.
Do not expose probe ports broadly to the Internet.
Restrict SSH/SSM access.
Restrict coordinator access.
Use security groups intentionally.
Treat this as a controlled research lab.
```

The first AWS lab is not a penetration testing platform. It is a controlled network-behavior validation environment for the adaptive graph model.

---

## 12. Out of scope for now

Do not implement these in the first AWS lab:

```text
production deployment
multi-account AWS architecture
EKS
Kubernetes
Helm
autoscaling
RDS
ClickHouse
mTLS
Ed25519
attestation
eBPF
real vulnerability scanning
TOON export
MCPM-inspired simulation
```

The first AWS lab should focus only on real EC2 network behavior and graph response.

---

## 13. Manager recommendation

The AWS lab is important, but it should come after Docker lab implementation.

Recommended next steps:

```text
1. Implement examples/docker-lab.
2. Validate Docker A/B/C repeatedly.
3. Review this AWS lab plan.
4. Create Terraform skeleton in a later issue.
5. Implement minimal AWS A/B/C.
6. Extend to A/B/C/D.
```

The key principle:

```text
Docker gives speed.
AWS gives realism.
Use both, but in the right order.
```
