output "server_public_ip" {
  description = "Public IP of physarum-server (A)"
  value       = aws_instance.server_a.public_ip
}

output "server_private_ip" {
  description = "Private IP of physarum-server (A)"
  value       = aws_instance.server_a.private_ip
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

output "curl_health" {
  description = "Health check command"
  value       = "curl -s http://${aws_instance.server_a.public_ip}:8080/health | jq"
}

output "curl_agents" {
  description = "Agent registration check command"
  value       = "curl -s http://${aws_instance.server_a.public_ip}:8080/agents | jq"
}

output "curl_graph" {
  description = "Edge graph check command"
  value       = "curl -s http://${aws_instance.server_a.public_ip}:8080/graph | jq"
}

output "curl_paths_b_to_d" {
  description = "Adaptive path scoring — agent-b to agent-d"
  value       = "curl -s 'http://${aws_instance.server_a.public_ip}:8080/paths?source=agent-b&target=agent-d' | jq"
}
