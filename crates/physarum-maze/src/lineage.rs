use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
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
    /// D_ij edge weights keyed as "src_ip->dst_ip"
    pub scores: HashMap<String, f64>,
    /// Total hops from origin
    pub hops: usize,
    pub started_at: String,
    pub updated_at: String,
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
            scores: HashMap::new(),
            hops: 0,
            started_at: now.clone(),
            updated_at: now,
        }
    }

    /// Return a new lineage extended by one successful hop to `next_ip`.
    pub fn extend(&self, next_ip: &str) -> Self {
        let mut next = self.clone();
        let edge = self.edge_key(next_ip);
        // Reinforce the successful edge (D_ij adaptation: multiply by 1.5)
        *next.scores.entry(edge).or_insert(1.0) *= 1.5;
        next.path.push(next_ip.to_string());
        next.visited.insert(next_ip.to_string());
        next.hops += 1;
        next.updated_at = Utc::now().to_rfc3339();
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

    pub fn is_visited(&self, ip: &str) -> bool {
        self.visited.contains(ip)
    }

    pub fn is_dead_end(&self, ip: &str) -> bool {
        self.dead_ends.contains(ip)
    }

    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(LINEAGE_PATH, json)
            .with_context(|| format!("write {LINEAGE_PATH}"))?;
        Ok(())
    }

    pub fn from_b64(encoded: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(encoded)
            .context("base64 decode of lineage failed")?;
        serde_json::from_slice(&bytes).context("lineage JSON parse failed")
    }

    pub fn to_b64(&self) -> Result<String> {
        let json = serde_json::to_string(self).context("lineage serialise failed")?;
        Ok(STANDARD.encode(json.as_bytes()))
    }

    fn edge_key(&self, dst_ip: &str) -> String {
        format!("{}->{}", self.path.last().unwrap_or(&self.origin), dst_ip)
    }
}
