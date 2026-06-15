//! Ephemeral PKI for mTLS back-channel (Issue #189) and browser HTTPS (Issue #190).
//!
//! One CA is generated per seed startup. It signs two server certs:
//!   - `physarum-seed` (DNS SAN) — for the mTLS back-channel (port+1)
//!   - `localhost` + `127.0.0.1` (DNS + IP SAN) — for the browser HTTPS server (port)
//!
//! Per-agent client certs are issued by `issue_agent_cert` before each propagation.
//! The CA PEM + client cert + key travel in the AES-GCM lineage so propagated agents
//! can authenticate to the mTLS port.
//!
//! `STORE` is set once in main.rs when `--server` is active.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};

/// Process-global TLS store — set once by main.rs, read by llm_loop.rs.
pub static STORE: OnceLock<Arc<TlsStore>> = OnceLock::new();

pub struct TlsStore {
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
    /// PEM of the CA cert — embedded in lineage so propagated agents can trust the server.
    pub ca_cert_pem: String,
    /// DER of the CA cert — used to build the server-side RootCertStore.
    ca_cert_der: Vec<u8>,
    /// mTLS back-channel server cert — SAN = "physarum-seed" (DNS).
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
    /// Browser HTTPS server cert — SAN = "localhost" (DNS) + 127.0.0.1 (IP).
    browser_cert_der: Vec<u8>,
    browser_key_der: Vec<u8>,
}

impl TlsStore {
    /// Generate an ephemeral CA and two server certs (mTLS back-channel + browser HTTPS).
    pub fn new() -> Result<Self> {
        // reqwest's rustls-tls feature brings in ring but does not install it as
        // process-level default until the first Client is built.  We install it here
        // so ServerConfig::builder() can find a CryptoProvider at server startup.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok(); // silently ignored if already installed

        // ── Ephemeral CA ─────────────────────────────────────────────────────────
        let ca_key = KeyPair::generate().context("CA KeyPair::generate")?;
        let mut ca_params = CertificateParams::new(vec![]).context("CA CertificateParams::new")?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "Physarum Attack Path CA");
        ca_dn.push(DnType::OrganizationName, "Physarum Attack Path");
        ca_params.distinguished_name = ca_dn;
        let ca_cert = ca_params.self_signed(&ca_key).context("CA self_signed")?;
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = ca_cert.der().to_vec();

        // ── mTLS back-channel server cert (SAN = "physarum-seed") ───────────────
        let server_key = KeyPair::generate().context("server KeyPair::generate")?;
        let mut server_params = CertificateParams::new(vec!["physarum-seed".to_string()])
            .context("server CertificateParams::new")?;
        let mut server_dn = DistinguishedName::new();
        server_dn.push(DnType::CommonName, "physarum-seed");
        server_dn.push(DnType::OrganizationName, "Physarum Attack Path");
        server_params.distinguished_name = server_dn;
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .context("server cert signed_by")?;
        let server_cert_der = server_cert.der().to_vec();
        let server_key_der = server_key.serialize_der();

        // ── Browser HTTPS server cert (SAN = "localhost" + 127.0.0.1) ───────────
        let browser_key = KeyPair::generate().context("browser KeyPair::generate")?;
        let mut browser_params = CertificateParams::new(vec!["localhost".to_string()])
            .context("browser CertificateParams::new")?;
        // Add 127.0.0.1 as IP SAN so Chrome accepts connections to 127.0.0.1:port.
        browser_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        let mut browser_dn = DistinguishedName::new();
        browser_dn.push(DnType::CommonName, "Physarum Attack Path");
        browser_dn.push(DnType::OrganizationName, "Physarum Attack Path");
        browser_params.distinguished_name = browser_dn;
        let browser_cert = browser_params
            .signed_by(&browser_key, &ca_cert, &ca_key)
            .context("browser cert signed_by")?;
        let browser_cert_der = browser_cert.der().to_vec();
        let browser_key_der = browser_key.serialize_der();

        // ── Export CA cert for optional browser trust import ────────────────────
        let ca_path = std::path::Path::new("/tmp/physarum/ca.pem");
        if let Some(parent) = ca_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(ca_path, &ca_cert_pem) {
            Ok(_) => tracing::info!(
                path = %ca_path.display(),
                "ephemeral CA cert written — import to silence browser warning"
            ),
            Err(_) => tracing::debug!(
                path = %ca_path.display(),
                "could not write CA cert (directory may not exist)"
            ),
        }

        tracing::info!("ephemeral PKI ready — CA + server cert + browser cert generated");

        Ok(Self {
            ca_key,
            ca_cert,
            ca_cert_pem,
            ca_cert_der,
            server_cert_der,
            server_key_der,
            browser_cert_der,
            browser_key_der,
        })
    }

    /// Issue a unique client cert for a propagated agent at `agent_ip`.
    /// Returns `(cert_pem, key_pem)` to embed in the lineage.
    pub fn issue_agent_cert(&self, agent_ip: &str) -> Result<(String, String)> {
        let key = KeyPair::generate().context("agent KeyPair::generate")?;
        let params = CertificateParams::new(vec![agent_ip.to_string()])
            .context("agent CertificateParams::new")?;
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .context("agent cert signed_by")?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Build a `rustls::ServerConfig` for the mTLS back-channel:
    ///   - server presents its cert (signed by the ephemeral CA)
    ///   - client MUST present a cert also signed by the ephemeral CA
    pub fn server_rustls_config(&self) -> Result<ServerConfig> {
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(self.ca_cert_der.clone()))
            .context("add CA to RootCertStore")?;

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("WebPkiClientVerifier::build")?;

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![CertificateDer::from(self.server_cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key_der.clone())),
            )
            .context("mTLS ServerConfig::with_single_cert")?;

        Ok(config)
    }

    /// Build a `rustls::ServerConfig` for the browser HTTPS dashboard:
    ///   - server presents the localhost cert (SAN = "localhost" + 127.0.0.1)
    ///   - NO client cert required — browsers don't have one
    pub fn browser_rustls_config(&self) -> Result<ServerConfig> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(self.browser_cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.browser_key_der.clone())),
            )
            .context("browser ServerConfig::with_single_cert")?;

        Ok(config)
    }
}
