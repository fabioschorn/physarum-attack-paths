use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use physarum_llm::LlmAttemptEvidence;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const LINEAGE_PATH: &str = "/tmp/physarum-lineage.json";

/// Lineage carried by every propagated instance.
///
/// Represents the path from the seed to the current host and the D_ij
/// edge weights accumulated along the way.  Passed between hosts as
/// a base64-encoded JSON blob on the CLI so no extra file transfer is needed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Lineage {
    /// IP of the seed host (Host A)
    pub origin: String,
    /// Ordered list of IPs traversed from origin to current host
    pub path: Vec<String>,
    /// Set of all IPs in `path` (O(1) cycle detection)
    pub visited: HashSet<String>,
    /// IPs where propagation was rejected (sshd or SCP failure)
    pub dead_ends: HashSet<String>,
    /// IPs found to already run physarum-maze (secondary conduit endpoints)
    pub colonized: HashSet<String>,
    /// Secondary conduits: ["from_ip", "to_ip"] pairs discovered after primary path
    pub secondary_conduits: Vec<[String; 2]>,
    /// D_ij edge weights keyed as "src_ip->dst_ip"
    pub scores: HashMap<String, f64>,
    /// UTC timestamp of each successful hop, keyed as "src_ip->dst_ip"
    pub transitions: HashMap<String, String>,
    /// Total hops from origin
    pub hops: usize,
    pub started_at: String,
    pub updated_at: String,
    /// HTTP port of the seed's organism graph server (`--server <PORT>`).
    /// Carried through the lineage chain so propagated agents can POST
    /// `ColonizationReport` to `http://<origin>:<server_port>/report-colonization`.
    /// `None` when the seed was started without `--server`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    /// Structured evidence from every LLM reasoning attempt.
    /// Each entry records the query, policy decision, execution result, and next action.
    /// Secret material (PEM, API keys) never appears here — only SecretRef.key_id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub llm_attempts: Vec<LlmAttemptEvidence>,
}

impl Lineage {
    /// Create a fresh seed lineage starting at `my_ip`.
    pub fn seed(my_ip: &str) -> Self {
        let now = Utc::now().to_rfc3339();
        let mut visited = HashSet::new();
        visited.insert(my_ip.to_string());
        Self {
            origin: my_ip.to_string(),
            path: vec![my_ip.to_string()],
            visited,
            dead_ends: HashSet::new(),
            colonized: HashSet::new(),
            secondary_conduits: Vec::new(),
            scores: HashMap::new(),
            transitions: HashMap::new(),
            hops: 0,
            started_at: now.clone(),
            updated_at: now,
            server_port: None,
            llm_attempts: Vec::new(),
        }
    }

    /// Append one LlmAttemptEvidence record.
    /// Called by llm_loop after each policy evaluation + execution attempt.
    pub fn record_llm_attempt(&mut self, evidence: LlmAttemptEvidence) {
        self.llm_attempts.push(evidence);
        self.updated_at = Utc::now().to_rfc3339();
    }

    /// Return a new lineage extended by one successful hop to `next_ip`.
    pub fn extend(&self, next_ip: &str) -> Self {
        let mut next = self.clone();
        let edge = self.edge_key(next_ip);
        let now = Utc::now().to_rfc3339();
        // Reinforce the successful edge (D_ij adaptation: multiply by 1.5)
        *next.scores.entry(edge.clone()).or_insert(1.0) *= 1.5;
        next.transitions.insert(edge, now.clone());
        next.path.push(next_ip.to_string());
        next.visited.insert(next_ip.to_string());
        next.hops += 1;
        next.updated_at = now;
        next
    }

    /// Penalise a failed SSH attempt without marking as a dead end.
    pub fn penalize(&mut self, target_ip: &str) {
        let edge = self.edge_key(target_ip);
        *self.scores.entry(edge).or_insert(1.0) *= 0.5;
        self.updated_at = Utc::now().to_rfc3339();
    }

    /// Mark a target as a dead end and heavily penalise its edge.
    pub fn mark_dead_end(&mut self, target_ip: &str) {
        self.dead_ends.insert(target_ip.to_string());
        let edge = self.edge_key(target_ip);
        *self.scores.entry(edge).or_insert(1.0) *= 0.05;
        self.updated_at = Utc::now().to_rfc3339();
    }

    /// Remove a dead end mark and reset the edge score to neutral (1.0).
    /// Called when the host sends an active stimulus — the environment changed.
    pub fn unmark_dead_end(&mut self, target_ip: &str) {
        self.dead_ends.remove(target_ip);
        let edge = self.edge_key(target_ip);
        self.scores.entry(edge).and_modify(|s| *s = 1.0);
        self.updated_at = Utc::now().to_rfc3339();
    }

    /// Record a host already running physarum-maze; mild score reduction since
    /// the corridor is valid but the endpoint is occupied.
    pub fn mark_colonized(&mut self, target_ip: &str) {
        self.colonized.insert(target_ip.to_string());
        let edge = self.edge_key(target_ip);
        *self.scores.entry(edge).or_insert(1.0) *= 0.8;
        self.updated_at = Utc::now().to_rfc3339();
    }

    /// Record a secondary conduit (from_ip → to_ip) discovered after the
    /// primary lineage path was already established.  Mildly reinforces the
    /// edge to preserve it as an alternative route.
    pub fn add_secondary_conduit(&mut self, from_ip: &str, to_ip: &str) {
        self.secondary_conduits
            .push([from_ip.to_string(), to_ip.to_string()]);
        let edge = format!("{}->{}", from_ip, to_ip);
        *self.scores.entry(edge).or_insert(1.0) *= 1.2;
        self.updated_at = Utc::now().to_rfc3339();
    }

    pub fn is_visited(&self, ip: &str) -> bool {
        self.visited.contains(ip)
    }

    pub fn is_dead_end(&self, ip: &str) -> bool {
        self.dead_ends.contains(ip)
    }

    pub fn is_colonized(&self, ip: &str) -> bool {
        self.colonized.contains(ip)
    }

    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(LINEAGE_PATH, json).with_context(|| format!("write {LINEAGE_PATH}"))?;
        Ok(())
    }

    pub fn from_b64(encoded: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(encoded)
            .context("base64 decode of lineage failed")?;
        // When a key is active and payload is long enough, try AES-GCM decrypt first.
        // Falls back to plaintext on decryption failure (e.g. legacy unencrypted lineage).
        if crate::lineage_crypto::is_active() && bytes.len() >= 28 {
            if let Ok(plain) = crate::lineage_crypto::decrypt(&bytes) {
                return serde_json::from_slice(&plain)
                    .context("lineage JSON parse after decrypt failed");
            }
        }
        serde_json::from_slice(&bytes).context("lineage JSON parse failed")
    }

    pub fn to_b64(&self) -> Result<String> {
        let json = serde_json::to_string(self).context("lineage serialise failed")?;
        if crate::lineage_crypto::is_active() {
            let encrypted = crate::lineage_crypto::encrypt(json.as_bytes())
                .context("lineage encrypt failed")?;
            return Ok(STANDARD.encode(&encrypted));
        }
        Ok(STANDARD.encode(json.as_bytes()))
    }

    fn edge_key(&self, dst_ip: &str) -> String {
        format!("{}->{}", self.path.last().unwrap_or(&self.origin), dst_ip)
    }
}
