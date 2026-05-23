output "maze_topology" {
  description = "PF-1 maze topology summary"
  value = {
    front  = { host_a = local.host_a_ip }
    layer1 = { host_b = local.host_b_ip, host_c = local.host_c_ip }
    layer2 = { host_d = local.host_d_ip, host_e = local.host_e_ip, host_f = local.host_f_ip }
    layer3 = { host_g = local.host_g_ip }
  }
}

output "host_a_public_ip" {
  description = "Public IP of Host A (seed) — SSH access and organism entry point"
  value       = aws_instance.host_a.public_ip
}

output "host_b_public_ip" {
  description = "Public IP of Host B (layer-1)"
  value       = aws_instance.host_b.public_ip
}

output "host_c_public_ip" {
  description = "Public IP of Host C (layer-1 bifurcation)"
  value       = aws_instance.host_c.public_ip
}

output "host_d_public_ip" {
  description = "Public IP of Host D (layer-2 dead end)"
  value       = aws_instance.host_d.public_ip
}

output "host_e_public_ip" {
  description = "Public IP of Host E (layer-2 loop risk)"
  value       = aws_instance.host_e.public_ip
}

output "host_f_public_ip" {
  description = "Public IP of Host F (layer-2 valid corridor)"
  value       = aws_instance.host_f.public_ip
}

output "host_g_public_ip" {
  description = "Public IP of Host G (layer-3 expansion milestone)"
  value       = aws_instance.host_g.public_ip
}

output "ssh_host_a" {
  description = "SSH command to connect to Host A (seed)"
  value       = "ssh -i examples/aws-lab/.keys/physarum-lab-devlead ec2-user@${aws_instance.host_a.public_ip}"
}

output "maze_propagation_topology" {
  description = "IP-based propagation topology — source IP is the credential, no SSH key used"
  value = {
    host_b = "allowed_source: ${local.host_a_ip} (A can propagate via empty-password SSH)"
    host_c = "allowed_source: ${local.host_a_ip} (A can propagate via empty-password SSH)"
    host_d = "allowed_source: none (dead end — sshd rejects all organism IPs)"
    host_e = "allowed_source: ${local.host_c_ip} (C can propagate; loop risk for organism)"
    host_f = "allowed_source: ${local.host_c_ip} (C can propagate; valid corridor to G)"
    host_g = "allowed_source: ${local.host_f_ip} (F only; D and E rejected at sshd)"
  }
}

output "ansible_connectivity_check" {
  description = "Ansible command to run the maze connectivity verification playbook"
  value       = "ansible-playbook -i examples/aws-lab/ansible-pf1/aws_ec2.yml examples/aws-lab/ansible-pf1/verify-maze-connectivity.yml"
}

output "terraform_destroy" {
  description = "Destroy command — run after evidence collection to avoid charges"
  value       = "terraform -chdir=examples/aws-lab/terraform-pf1 destroy -var='operator_cidr=YOUR_IP/32'"
}
