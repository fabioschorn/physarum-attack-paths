//! Lightweight Internet connectivity check.
//!
//! Uses a HEAD request to a well-known stable endpoint.
//! Bounded by the client's configured timeout — non-blocking for the organism.

/// Returns `true` when an outbound HTTP HEAD to a stable endpoint succeeds.
///
/// Uses the same `reqwest::Client` already configured with `timeout_ms` so
/// the check is automatically bounded. A `false` result triggers graceful
/// fallback to offline-only mode in `VulnerabilityIntelService`.
pub async fn is_internet_available(client: &reqwest::Client) -> bool {
    // HEAD to osv.dev — same host we'd query for online advisory lookup.
    // Any 2xx/3xx/4xx response confirms connectivity; only a network error
    // or timeout counts as "no Internet".
    match client.head("https://api.osv.dev/").send().await {
        Ok(_) => true,
        Err(e) => {
            tracing::debug!(err = %e, "internet connectivity check failed");
            false
        }
    }
}
