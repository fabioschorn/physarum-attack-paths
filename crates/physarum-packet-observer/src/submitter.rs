use anyhow::Result;
use physarum_protocol::PacketObservation;
use reqwest::Client;
use std::time::Duration;

pub struct Submitter {
    client: Client,
    pub endpoint: String,
}

impl Submitter {
    pub fn new(coordinator_url: &str, timeout_ms: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()?;
        let endpoint = format!(
            "{}/packet-observations",
            coordinator_url.trim_end_matches('/')
        );
        Ok(Self { client, endpoint })
    }

    pub async fn submit(&self, obs: &PacketObservation) -> Result<()> {
        let resp = self.client.post(&self.endpoint).json(obs).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            anyhow::bail!("coordinator returned {status}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_strips_trailing_slash() {
        let s = Submitter::new("http://127.0.0.1:8080/", 5000).unwrap();
        assert_eq!(s.endpoint, "http://127.0.0.1:8080/packet-observations");
    }

    #[test]
    fn endpoint_built_without_slash() {
        let s = Submitter::new("http://10.0.0.1:8080", 5000).unwrap();
        assert_eq!(s.endpoint, "http://10.0.0.1:8080/packet-observations");
    }

    #[test]
    fn endpoint_with_custom_coordinator_url() {
        let s = Submitter::new("http://agent-a.internal:9090", 1000).unwrap();
        assert_eq!(
            s.endpoint,
            "http://agent-a.internal:9090/packet-observations"
        );
    }
}
