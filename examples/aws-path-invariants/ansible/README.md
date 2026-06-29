# Ansible Layer

This directory is intentionally empty except for this note.

The first implementation step for the AWS Path Invariants Lab is Terraform-only:
create the VPC, subnets, Internet Gateway, route tables, EC2 instances and
security groups.

Future Ansible playbooks should be added in separate steps:

1. bootstrap `physarum-maze` on the seed;
2. install validation dependencies;
3. query `/paths` through the seed over SSH;
4. apply and clean up `tc/netem` degradation;
5. install vulnerable services for later CVE/LLM experiments.

Do not install CVE software in the initial Terraform-only run.
