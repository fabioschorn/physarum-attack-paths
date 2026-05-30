use serde::{Deserialize, Serialize};

/// Controls what templates can run and how aggressively.
///
/// The allowlist is the primary safety control: templates not in `allowed_check_ids`
/// are rejected before any network I/O occurs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunPolicy {
    /// Explicit set of template IDs that may be executed.
    /// Empty = deny all (default-deny principle).
    pub allowed_check_ids: Vec<String>,
    /// Response body is truncated at this many bytes before matching/extraction.
    pub max_response_bytes: usize,
    /// Per-request total timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// Maximum number of HTTP redirects to follow.
    pub max_redirects: u8,
}

impl Default for RunPolicy {
    fn default() -> Self {
        Self {
            allowed_check_ids: vec![],
            max_response_bytes: 64 * 1024, // 64 KiB
            request_timeout_ms: 5_000,
            max_redirects: 3,
        }
    }
}

impl RunPolicy {
    /// Return Ok if `check_id` is in the allowlist, error otherwise.
    pub fn check_allowed(&self, check_id: &str) -> anyhow::Result<()> {
        if self.allowed_check_ids.iter().any(|id| id == check_id) {
            Ok(())
        } else {
            anyhow::bail!(
                "template '{}' is not in the RunPolicy allowlist — refusing to run",
                check_id
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_denies_all() {
        let policy = RunPolicy::default();
        assert!(policy.check_allowed("any-template").is_err());
    }

    #[test]
    fn allowlisted_id_passes() {
        let policy = RunPolicy {
            allowed_check_ids: vec!["nginx-detect".into(), "http-status-ok".into()],
            ..Default::default()
        };
        assert!(policy.check_allowed("nginx-detect").is_ok());
        assert!(policy.check_allowed("http-status-ok").is_ok());
    }

    #[test]
    fn non_allowlisted_id_fails() {
        let policy = RunPolicy {
            allowed_check_ids: vec!["nginx-detect".into()],
            ..Default::default()
        };
        assert!(policy.check_allowed("exploit-rce").is_err());
    }

    #[test]
    fn max_response_bytes_default_is_64k() {
        assert_eq!(RunPolicy::default().max_response_bytes, 64 * 1024);
    }
}
