//! Authentication providers — ported from Nuclei `pkg/authprovider`.
//!
//! Supports five authentication strategies, all applied by mutating an
//! in-flight `reqwest::RequestBuilder`:
//! - **Basic** — `Authorization: Basic base64(user:pass)`
//! - **Bearer** — `Authorization: Bearer <token>`
//! - **Headers** — arbitrary custom request headers
//! - **Cookies** — `Cookie: name=value; ...`
//! - **Query** — URL query parameter injection
//!
//! Authentication is loaded from a secrets file or configured inline in
//! the template. Multiple strategies can be stacked on one request.

use std::collections::HashMap;
use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

// ── Strategy definitions ──────────────────────────────────────────────────────

/// A single authentication strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthStrategy {
    /// HTTP Basic authentication.
    Basic { username: String, password: String },
    /// Bearer token authentication.
    Bearer { token: String },
    /// Inject custom request headers.
    Headers { headers: HashMap<String, String> },
    /// Inject cookies into the `Cookie` header.
    Cookies { cookies: HashMap<String, String> },
    /// Append query parameters to the request URL.
    Query { params: HashMap<String, String> },
}

impl AuthStrategy {
    /// Apply this strategy to a `reqwest::RequestBuilder`.
    pub fn apply(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            AuthStrategy::Basic { username, password } => {
                let credentials = format!("{username}:{password}");
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
                builder = builder.header("Authorization", format!("Basic {encoded}"));
            }

            AuthStrategy::Bearer { token } => {
                builder = builder.header("Authorization", format!("Bearer {token}"));
            }

            AuthStrategy::Headers { headers } => {
                for (k, v) in headers {
                    builder = builder.header(k.as_str(), v.as_str());
                }
            }

            AuthStrategy::Cookies { cookies } => {
                let cookie_header = cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                builder = builder.header("Cookie", cookie_header);
            }

            AuthStrategy::Query { params } => {
                let pairs: Vec<(&str, &str)> = params
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                builder = builder.query(&pairs);
            }
        }
        builder
    }

    /// Apply this strategy by injecting values into a mutable header map.
    /// Used by TCP/WebSocket protocols that build raw headers separately.
    pub fn inject_headers(&self, headers: &mut HashMap<String, String>) {
        match self {
            AuthStrategy::Basic { username, password } => {
                let credentials = format!("{username}:{password}");
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
                headers.insert("Authorization".into(), format!("Basic {encoded}"));
            }
            AuthStrategy::Bearer { token } => {
                headers.insert("Authorization".into(), format!("Bearer {token}"));
            }
            AuthStrategy::Headers { headers: h } => {
                headers.extend(h.clone());
            }
            AuthStrategy::Cookies { cookies } => {
                let cookie_header = cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                headers.insert("Cookie".into(), cookie_header);
            }
            AuthStrategy::Query { .. } => {
                // Query params can't be injected as headers — caller must handle.
            }
        }
    }
}

// ── AuthProvider ─────────────────────────────────────────────────────────────

/// Container for one or more stacked authentication strategies.
///
/// Strategies are applied in declaration order. Multiple strategies are
/// supported (e.g., custom header + cookie).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthProvider {
    pub strategies: Vec<AuthStrategy>,
}

impl AuthProvider {
    /// Apply all strategies to a `reqwest::RequestBuilder`.
    pub fn apply(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        for strategy in &self.strategies {
            builder = strategy.apply(builder);
        }
        builder
    }

    /// Inject all strategies into a header map (non-HTTP protocols).
    pub fn inject_headers(&self, headers: &mut HashMap<String, String>) {
        for strategy in &self.strategies {
            strategy.inject_headers(headers);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }
}

// ── File-based secrets loading ────────────────────────────────────────────────

/// Secrets file entry — domain-scoped authentication configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretsEntry {
    /// Domain or host pattern this secret applies to (e.g. `"example.com"`).
    pub domain: String,
    /// Authentication strategies for requests to `domain`.
    pub auth: Vec<AuthStrategy>,
}

/// Load authentication secrets from a YAML file.
///
/// File format:
/// ```yaml
/// - domain: "api.example.com"
///   auth:
///     - type: bearer
///       token: "your-token-here"
/// - domain: "app.example.com"
///   auth:
///     - type: basic
///       username: admin
///       password: secret
/// ```
pub fn load_secrets_file(path: impl AsRef<Path>) -> anyhow::Result<Vec<SecretsEntry>> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| anyhow::anyhow!("load secrets {:?}: {}", path.as_ref(), e))?;
    let entries: Vec<SecretsEntry> = serde_yaml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("parse secrets {:?}: {}", path.as_ref(), e))?;
    Ok(entries)
}

/// Look up auth strategies for a given hostname from a loaded secrets list.
pub fn lookup_auth(secrets: &[SecretsEntry], host: &str) -> AuthProvider {
    for entry in secrets {
        if host.contains(&entry.domain) || entry.domain == "*" {
            return AuthProvider {
                strategies: entry.auth.clone(),
            };
        }
    }
    AuthProvider::default()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_encodes_credentials() {
        let strategy = AuthStrategy::Basic {
            username: "admin".into(),
            password: "secret".into(),
        };
        let mut headers = HashMap::new();
        strategy.inject_headers(&mut headers);
        let auth = headers.get("Authorization").unwrap();
        assert!(auth.starts_with("Basic "));
        // Decode and verify
        let b64 = auth.strip_prefix("Basic ").unwrap();
        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, "admin:secret");
    }

    #[test]
    fn bearer_auth_injects_token() {
        let strategy = AuthStrategy::Bearer {
            token: "my-jwt-token".into(),
        };
        let mut headers = HashMap::new();
        strategy.inject_headers(&mut headers);
        assert_eq!(headers.get("Authorization").unwrap(), "Bearer my-jwt-token");
    }

    #[test]
    fn headers_auth_adds_custom_headers() {
        let strategy = AuthStrategy::Headers {
            headers: [("X-Api-Key".to_string(), "abc123".to_string())]
                .into_iter()
                .collect(),
        };
        let mut headers = HashMap::new();
        strategy.inject_headers(&mut headers);
        assert_eq!(headers.get("X-Api-Key").unwrap(), "abc123");
    }

    #[test]
    fn cookies_auth_formats_cookie_header() {
        let strategy = AuthStrategy::Cookies {
            cookies: [
                ("session".to_string(), "tok1".to_string()),
                ("user".to_string(), "admin".to_string()),
            ]
            .into_iter()
            .collect(),
        };
        let mut headers = HashMap::new();
        strategy.inject_headers(&mut headers);
        let cookie = headers.get("Cookie").unwrap();
        assert!(cookie.contains("session=tok1"));
        assert!(cookie.contains("user=admin"));
    }

    #[test]
    fn provider_stacks_multiple_strategies() {
        let provider = AuthProvider {
            strategies: vec![
                AuthStrategy::Bearer {
                    token: "tok".into(),
                },
                AuthStrategy::Headers {
                    headers: [("X-Tenant".to_string(), "acme".to_string())]
                        .into_iter()
                        .collect(),
                },
            ],
        };
        let mut headers = HashMap::new();
        provider.inject_headers(&mut headers);
        assert!(headers.contains_key("Authorization"));
        assert_eq!(headers.get("X-Tenant").unwrap(), "acme");
    }
}
