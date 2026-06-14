/// AES-256-GCM lineage payload encryption — Issue #187.
///
/// Lifecycle:
///   Seed startup    → `init_seed()`  generates a 32-byte OsRng key
///   SSH command     → hex key injected as `env PHYSARUM_LINEAGE_KEY=<hex> ...`
///   Propagated start→ `init_from_env()` reads the env var, erases it immediately
///
/// All `to_b64()` / `from_b64()` calls in `lineage.rs` route through here when
/// a key is available; fallback to plaintext base64 when no key is set.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};
use rand::RngCore;
use std::sync::OnceLock;

static KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Generate a fresh 32-byte key. Called once on seed startup.
pub fn init_seed() {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let _ = KEY.set(key);
}

/// Read key from `PHYSARUM_LINEAGE_KEY` env var, then erase it.
/// Called once on propagated-agent startup.
pub fn init_from_env() {
    let key = std::env::var("PHYSARUM_LINEAGE_KEY")
        .ok()
        .and_then(|h| decode_hex(&h).ok())
        .and_then(|v| v.try_into().ok());
    if let Some(k) = key {
        let _ = KEY.set(k);
    }
    // Remove from env regardless — prevents child processes from inheriting it.
    std::env::remove_var("PHYSARUM_LINEAGE_KEY");
}

/// Returns hex-encoded key for injection into SSH commands, or None if not initialised.
pub fn hex_key() -> Option<String> {
    KEY.get().map(|k| encode_hex(k))
}

/// True when a key is available and `to_b64` will encrypt.
pub fn is_active() -> bool {
    KEY.get().is_some()
}

/// Encrypt `plaintext` with AES-256-GCM.
/// Output layout: nonce (12 B) || ciphertext+tag (len+16 B).
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let raw = KEY.get().context("lineage key not initialised")?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(raw));
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob produced by `encrypt`.  Expects nonce (12 B) || ciphertext+tag.
pub fn decrypt(data: &[u8]) -> Result<Vec<u8>> {
    let raw = KEY.get().context("lineage key not initialised")?;
    if data.len() < 12 + 16 {
        bail!("payload too short to be encrypted ({} B)", data.len());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(raw));
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| anyhow::anyhow!("AES-GCM decrypt: {e}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        bail!("hex string has odd length");
    }
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).context("invalid hex char"))
        .collect()
}
