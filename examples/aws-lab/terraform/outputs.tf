output "lab_phase" {
  description = "Active lab phase (phase1 = full-mesh, phase2 = segmented B→C→D)"
  value       = var.lab_phase
}

output "lab_mode" {
  description = "Human-readable mode for the active lab phase"
  value       = local.phase_mode[var.lab_phase]
}

output "server_public_ip" {
  description = "Public IP of physarum coordinator — server-a for most phases; agent-b for gate-l2"
  value       = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? aws_instance.agent_b.public_ip : aws_instance.server_a[0].public_ip
}

output "server_private_ip" {
  description = "Private IP of physarum coordinator"
  value       = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? aws_instance.agent_b.private_ip : aws_instance.server_a[0].private_ip
}

output "agent_b_public_ip" {
  description = "Public IP of agent-b — SSH access for Ansible"
  value       = aws_instance.agent_b.public_ip
}

output "agent_c_public_ip" {
  description = "Public IP of agent-c — SSH access for Ansible"
  value       = aws_instance.agent_c.public_ip
}

output "agent_d_public_ip" {
  description = "Public IP of agent-d — SSH access for Ansible"
  value       = aws_instance.agent_d.public_ip
}

output "agent_b_private_ip" {
  description = "Private IP of agent-b"
  value       = aws_instance.agent_b.private_ip
}

output "agent_c_private_ip" {
  description = "Private IP of agent-c"
  value       = aws_instance.agent_c.private_ip
}

output "agent_d_private_ip" {
  description = "Private IP of agent-d"
  value       = aws_instance.agent_d.private_ip
}

output "agent_e_public_ip" {
  description = "Public IP of agent-e — SSH access for Ansible (weighted-paths and gate-k phases only; null otherwise)"
  value       = contains(["weighted-paths", "gate-k"], var.lab_phase) ? aws_instance.agent_e[0].public_ip : null
}

output "agent_e_private_ip" {
  description = "Private IP of agent-e (weighted-paths and gate-k phases only; null otherwise)"
  value       = contains(["weighted-paths", "gate-k"], var.lab_phase) ? aws_instance.agent_e[0].private_ip : null
}

output "ssh_coordinator" {
  description = "SSH command to connect to the coordinator (server-a for most phases; agent-b for gate-l2)"
  value       = "ssh -i examples/aws-lab/.keys/physarum-lab-devlead ec2-user@${contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? aws_instance.agent_b.public_ip : aws_instance.server_a[0].public_ip}"
}

output "ssh_tunnel_8080" {
  description = "SSH tunnel command — forwards coordinator:8080 to localhost:18080 for manual curl"
  value       = "ssh -i examples/aws-lab/.keys/physarum-lab-devlead -L 18080:127.0.0.1:8080 ec2-user@${contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? aws_instance.agent_b.public_ip : aws_instance.server_a[0].public_ip}"
}

output "ansible_run" {
  description = "Ansible validation command — uses dynamic inventory for gate-l2/gate-l3/gate-m, static otherwise"
  value = (
    var.lab_phase == "gate-m" ? "ansible-playbook -i examples/aws-lab/ansible/aws_ec2.yml examples/aws-lab/ansible/validate-gate-m-node-runtime.yml" :
    contains(["gate-l2", "gate-l3"], var.lab_phase) ? "ansible-playbook -i examples/aws-lab/ansible/aws_ec2.yml examples/aws-lab/ansible/validate-gate-l3-icmp-stimulus.yml" :
    "ansible-playbook -i examples/aws-lab/ansible/inventory.local.ini examples/aws-lab/ansible/validate-runtime.yml"
  )
}

output "ansible_weighted_paths" {
  description = "Ansible weighted-paths validation command (weighted-paths phase only)"
  value       = "ansible-playbook -i examples/aws-lab/ansible/inventory.local.ini examples/aws-lab/ansible/validate-weighted-paths-aws.yml"
}

output "ansible_dynamic_inventory_check" {
  description = "Check dynamic inventory groups after terraform apply (gate-l2/gate-l3 only)"
  value       = contains(["gate-l2", "gate-l3", "gate-m"], var.lab_phase) ? "ansible-inventory -i examples/aws-lab/ansible/aws_ec2.yml --graph" : null
}
