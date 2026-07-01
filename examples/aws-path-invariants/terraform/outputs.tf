output "operator_cidr" {
  description = "Operator CIDR allowed to reach SSH and seed dashboard."
  value       = var.operator_cidr
}

output "vpc_cidr" {
  description = "VPC CIDR to pass to physarum-maze --llm-allowed-cidr."
  value       = var.vpc_cidr
}

output "seed" {
  description = "Seed/source instance addresses."
  value = {
    public_ip  = aws_instance.seed.public_ip
    private_ip = aws_instance.seed.private_ip
    ssh        = "ssh ec2-user@${aws_instance.seed.public_ip}"
    dashboard  = "https://${aws_instance.seed.public_ip}:8443/"
  }
}

output "targets" {
  description = "Target instance addresses."
  value = {
    target_c = {
      public_ip  = aws_instance.target_c.public_ip
      private_ip = aws_instance.target_c.private_ip
      ssh        = "ssh ec2-user@${aws_instance.target_c.public_ip}"
    }
    target_d = {
      public_ip  = aws_instance.target_d.public_ip
      private_ip = aws_instance.target_d.private_ip
      ssh        = "ssh ec2-user@${aws_instance.target_d.public_ip}"
    }
    target_e = {
      public_ip  = aws_instance.target_e.public_ip
      private_ip = aws_instance.target_e.private_ip
      ssh        = "ssh ec2-user@${aws_instance.target_e.public_ip}"
    }
  }
}

output "future_seed_command_shape" {
  description = "Reference command shape for the later Ansible layer. User data installs the binary when enable_seed_artifact_download=true."
  value       = "sudo --preserve-env=LLM_API_KEY /usr/local/bin/physarum-maze --llm-endpoint https://api.openai.com --llm-model gpt-4o-mini --llm-allowed-cidr ${var.vpc_cidr} --exploit-enabled --server 8443 --tls --stimulus-timeout-secs 3600"
}

output "seed_artifact" {
  description = "S3 object used by seed user_data when artifact download is enabled."
  value       = "s3://${var.artifact_bucket}/${var.artifact_prefix}/physarum-maze"
}

output "manual_stimulus_checks" {
  description = "Manual target-to-seed ICMP stimulus commands for the next AWS validation pass."
  value = {
    target_c_icmp = "ssh ec2-user@${aws_instance.target_c.public_ip} 'ping -c 1 ${aws_instance.seed.private_ip}'"
    target_d_icmp = "ssh ec2-user@${aws_instance.target_d.public_ip} 'ping -c 1 ${aws_instance.seed.private_ip}'"
    target_e_icmp = "ssh ec2-user@${aws_instance.target_e.public_ip} 'ping -c 1 ${aws_instance.seed.private_ip}'"
  }
}
