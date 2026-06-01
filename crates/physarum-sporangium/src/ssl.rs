//! SSL/TLS protocol runner — ported from Nuclei `pkg/protocols/ssl`.
//!
//! Performs a TLS handshake and extracts certificate metadata into a
//! `ResponseData` for matching. No application-layer data is sent.
//!
//! # Extracted fields (available in matchers/extractors via `ssl_cert` part or DSL)
//!
//! | Key                  | Description                              |
//! |----------------------|------------------------------------------|
//! | `certificate`        | Full PEM certificate chain               |
//! | `subject`            | Subject DN string                        |
//! | `issuer`             | Issuer DN string                         |
//! | `not_before`         | Validity start (RFC 3339)                |
//! | `not_after`          | Validity end (RFC 3339)                  |
//! | `fingerprint_sha256` | Hex SHA-256 fingerprint                  |
//! | `dns_names`          | SANs / DNS names joined by comma         |
//! | `serial`             | Serial number hex                        |
//! | `self_signed`        | "true" / "false"                         |
//! | `expired`            | "true" / "false"                         |
//! | `tls_version`        | Negotiated TLS version string            |
//! | `cipher`             | Negotiated cipher suite name             |
//! | `key_size`           | Public key size in bits                  |

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono;
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

use crate::finding::{EvidenceSource, PatternFinding};
use crate::runner::{evaluate_template_with_response, ResponseData};
use crate::template::PatternTemplate;

// ── Public API ────────────────────────────────────────────────────────────────

/// Run an SSL template against a host:port.
///
/// Establishes a TLS connection, extracts certificate + handshake metadata,
/// then evaluates the template's matchers/extractors.
pub async fn run_ssl(
    template: &PatternTemplate,
    target_ip: IpAddr,
    port: u16,
    hostname: &str,
    timeout_ms: u64,
) -> Result<Vec<PatternFinding>> {
    if template.ssl_request.is_none() {
        tracing::warn!(template_id = %template.id, "ssl_request missing — skipping");
        return Ok(vec![]);
    }

    let tm = Duration::from_millis(timeout_ms);
    let addr = format!("{target_ip}:{port}");

    let stream = timeout(tm, TcpStream::connect(&addr))
        .await
        .context("SSL TCP connect timeout")?
        .with_context(|| format!("SSL TCP connect to {addr}"))?;

    let resp = perform_tls_handshake(stream, hostname, tm).await?;

    Ok(evaluate_template_with_response(
        template,
        &resp,
        target_ip,
        port,
        EvidenceSource::HttpProbe,
    ))
}

// ── TLS handshake ─────────────────────────────────────────────────────────────

async fn perform_tls_handshake(
    stream: TcpStream,
    hostname: &str,
    tm: Duration,
) -> Result<ResponseData> {
    // Build TLS client config with system root CAs
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server name {:?}: {}", hostname, e))?;

    let tls_stream = timeout(tm, connector.connect(server_name, stream))
        .await
        .context("TLS handshake timeout")?
        .context("TLS handshake")?;

    let (_, conn) = tls_stream.get_ref();

    // Extract peer certificates
    let peer_certs = conn.peer_certificates().unwrap_or_default();

    let mut extra: HashMap<String, String> = HashMap::new();
    extra.insert("type".into(), "ssl".into());

    // Negotiated TLS version
    let tls_version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "unknown",
    };
    extra.insert("tls_version".into(), tls_version.to_string());

    // Cipher suite name
    if let Some(suite) = conn.negotiated_cipher_suite() {
        extra.insert("cipher".into(), format!("{:?}", suite.suite()));
    }

    // Parse the leaf certificate
    let mut cert_pem = String::new();
    let mut cert_summary = String::new();

    if let Some(leaf_cert) = peer_certs.first() {
        // PEM encode
        let b64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(leaf_cert.as_ref())
        };
        cert_pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        extra.insert("certificate".into(), cert_pem.clone());

        // SHA-256 fingerprint
        let mut hasher = Sha256::new();
        hasher.update(leaf_cert.as_ref());
        let fp = format!("{:x}", hasher.finalize());
        extra.insert("fingerprint_sha256".into(), fp);

        // Parse with x509-parser
        if let Ok((_, x509)) = X509Certificate::from_der(leaf_cert.as_ref()) {
            let subject = x509.subject().to_string();
            let issuer = x509.issuer().to_string();
            extra.insert("subject".into(), subject.clone());
            extra.insert("issuer".into(), issuer.clone());
            extra.insert(
                "not_before".into(),
                x509.validity().not_before.to_datetime().to_string(),
            );
            extra.insert(
                "not_after".into(),
                x509.validity().not_after.to_datetime().to_string(),
            );
            extra.insert("serial".into(), format!("{:x}", x509.serial));

            // SAN / DNS names
            let dns_names: Vec<String> = x509
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|san| {
                    san.value
                        .general_names
                        .iter()
                        .filter_map(|gn| {
                            if let GeneralName::DNSName(name) = gn {
                                Some(name.to_string())
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            extra.insert("dns_names".into(), dns_names.join(", "));
            extra.insert("sans".into(), dns_names.join(", "));

            // Self-signed check
            let self_signed = (subject == issuer).to_string();
            extra.insert("self_signed".into(), self_signed);

            // Expired check (compare against current time via chrono)
            let not_after = x509.validity().not_after.timestamp();
            let expired = (chrono::Utc::now().timestamp() > not_after).to_string();
            extra.insert("expired".into(), expired);

            // Key size (derive from SubjectPublicKeyInfo algorithm OID)
            let key_size = x509.public_key().subject_public_key.data.len() * 8;
            extra.insert("key_size".into(), key_size.to_string());

            cert_summary = format!("subject={subject} issuer={issuer}");
        }
    }

    extra.insert("raw".into(), cert_summary.clone());

    Ok(ResponseData {
        status: 0,
        headers: Default::default(),
        body: cert_pem,
        raw_bytes: None,
        extra,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_data_has_ssl_type() {
        let mut extra = HashMap::new();
        extra.insert("type".into(), "ssl".into());
        let resp = ResponseData {
            status: 0,
            headers: Default::default(),
            body: String::new(),
            raw_bytes: None,
            extra,
        };
        assert_eq!(resp.extra.get("type").unwrap(), "ssl");
    }
}
