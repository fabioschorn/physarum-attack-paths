output "maze_topology" {
  description = "PF-2 maze topology summary"
  value = {
    front  = { host_a = local.host_a_ip, host_a1 = local.host_a1_ip }
    layer1 = { host_b = local.host_b_ip, host_c = local.host_c_ip }
    layer2 = { host_d = local.host_d_ip, host_e = local.host_e_ip, host_f = local.host_f_ip }
    layer3 = { host_g = local.host_g_ip }
    cross  = { host_x = local.host_x_ip }
  }
}

output "host_a_public_ip" {
  description = "Public IP of Host A (seed)"
  value       = aws_instance.host_a.public_ip
}

output "host_a1_public_ip" {
  description = "Public IP of Host A.1 (front lateral — discovered via /24 scan)"
  value       = aws_instance.host_a1.public_ip
}

output "host_b_public_ip" {
  value = aws_instance.host_b.public_ip
}

output "host_c_public_ip" {
  value = aws_instance.host_c.public_ip
}

output "host_d_public_ip" {
  value = aws_instance.host_d.public_ip
}

output "host_e_public_ip" {
  value = aws_instance.host_e.public_ip
}

output "host_f_public_ip" {
  value = aws_instance.host_f.public_ip
}

output "host_g_public_ip" {
  description = "Public IP of Host G (expansion milestone — colonized by PF-1 path; secondary conduit via X)"
  value       = aws_instance.host_g.public_ip
}

output "host_x_public_ip" {
  description = "Public IP of Host X (cross-subnet adaptive probe)"
  value       = aws_instance.host_x.public_ip
}

output "ssh_host_a" {
  description = "SSH command to connect to Host A (seed)"
  value       = "ssh -i examples/aws-lab/.keys/physarum-lab-devlead ec2-user@${aws_instance.host_a.public_ip}"
}

output "maze_propagation_topology" {
  description = "PF-2 propagation paths — primary (A→G) and secondary (A→A.1→X→G conduit)"
  value = {
    host_a1 = "allowed_source: ${local.host_a_ip} (A discovers A.1 via /24 nmap)"
    host_b  = "allowed_source: ${local.host_a_ip}"
    host_c  = "allowed_source: ${local.host_a_ip}"
    host_d  = "allowed_source: none (dead end)"
    host_e  = "allowed_source: ${local.host_c_ip} (loop risk)"
    host_f  = "allowed_source: ${local.host_c_ip} (valid corridor to G)"
    host_g  = "allowed_source: ${local.host_f_ip} primary | ${local.host_x_ip} colonized-check"
    host_x  = "allowed_source: ${local.host_a1_ip} (A.1→X via TCP SYN stimulus)"
  }
}

output "pf2_expected_events" {
  description = "Sequence of observable events proving PF-2 adaptive behaviour"
  value = [
    "T+0s:  A starts — /24 nmap scans front subnet, finds A.1 at ${local.host_a1_ip}",
    "T+0s:  A propagates to A.1 (SCP + systemd-run)",
    "T+0s:  A follows main path A→B/C→F→G (via ICMP stimulus from B/C/F)",
    "T+~60s: A.1 propagates via main path; also waits for X TCP stimulus",
    "T+5min: X TCP stimulus timer fires — sends TCP SYN to A.1:22 every 30s",
    "T+5min: A.1 captures TCP SYN → discovers X at ${local.host_x_ip}",
    "T+5min: A.1 propagates to X (SCP + systemd-run)",
    "T+5min: G pings X via ICMP timer — X captures stimulus, discovers G",
    "T+5min: X calls propagate(G) → already_colonized check → OCCUPIED",
    "T+5min: X records G as secondary conduit in lineage (X→G edge score ×1.2)",
    "RESULT: lineage.secondary_conduits = [[X_IP, G_IP]]; G not re-deployed",
  ]
}

output "terraform_destroy" {
  description = "Destroy command — run after evidence collection"
  value       = "terraform -chdir=examples/aws-lab/terraform-pf2 destroy -var='operator_cidr=YOUR_IP/32'"
}
