//! Ephemeral PKI for mTLS back-channel authentication (Issue #189).
//!
//! The seed generates a fresh CA on every startup. Before propagating to each
//! target, `issue_agent_cert` produces a unique client cert signed by that CA.
//! The cert + key + CA PEM travel in the lineage (AES-GCM encrypted) so the
//! propagated agent can authenticate to the seed's HTTPS server.
//!
//! `STORE` is set once in main.rs when `--server` is active; `llm_loop.rs`
//! reads it to embed certs before each propagation.

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
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
    /// DER of the server cert chain — presented to clients during TLS handshake.
    server_cert_der: Vec<u8>,
    /// DER of the server private key (PKCS8).
    server_key_der: Vec<u8>,
}

impl TlsStore {
    /// Generate an ephemeral CA and a server cert signed by it.
    pub fn new() -> Result<Self> {
        // reqwest's rustls-tls feature brings in ring but does not install it as
        // process-level default until the first Client is built.  We install it here
        // so ServerConfig::builder() can find a CryptoProvider at server startup.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok(); // silently ignored if already installed

        // Ephemeral CA
        let ca_key = KeyPair::generate().context("CA KeyPair::generate")?;
        let mut ca_params = CertificateParams::new(vec![]).context("CA CertificateParams::new")?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).context("CA self_signed")?;
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = ca_cert.der().to_vec();

        // Server cert — presented to propagated agents during TLS handshake
        let server_key = KeyPair::generate().context("server KeyPair::generate")?;
        let server_params = CertificateParams::new(vec!["physarum-seed".to_string()])
            .context("server CertificateParams::new")?;
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .context("server cert signed_by")?;
        let server_cert_der = server_cert.der().to_vec();
        let server_key_der = server_key.serialize_der();

        tracing::info!("ephemeral PKI ready — CA + server cert generated");

        Ok(Self {
            ca_key,
            ca_cert,
            ca_cert_pem,
            ca_cert_der,
            server_cert_der,
            server_key_der,
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

    /// Build a `rustls::ServerConfig` with mTLS:
    ///   - server presents its cert (signed by the ephemeral CA)
    ///   - client must present a cert also signed by the ephemeral CA
    pub fn server_rustls_config(&self) -> Result<ServerConfig> {
        // Trust only certs signed by our ephemeral CA
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
            .context("ServerConfig::with_single_cert")?;

        Ok(config)
    }
}
