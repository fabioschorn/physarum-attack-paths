//! Payload generators — ported from Nuclei `pkg/protocols/common/generators`.
//!
//! Implements three Nuclei attack types:
//! - **BatteringRam** — one payload set iterated sequentially
//! - **Pitchfork** — multiple payload sets zipped by index
//! - **ClusterBomb** — multiple payload sets as cartesian product
//!
//! Payloads can be specified inline (list of values) or loaded from a file
//! (one value per line).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

// ── Attack type ───────────────────────────────────────────────────────────────

/// Which attack strategy to use when multiple payload sets are defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackType {
    /// Iterate a single payload list sequentially (N requests).
    #[default]
    BatteringRam,
    /// Zip multiple lists by index — stops at shortest list (N requests).
    Pitchfork,
    /// Cartesian product of all lists (N₁ × N₂ × … requests).
    ClusterBomb,
}

// ── Payload source ────────────────────────────────────────────────────────────

/// Where to source payload values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PayloadSource {
    /// Inline list of values.
    Inline(Vec<String>),
    /// Path to a file containing one value per line.
    File(String),
}

impl PayloadSource {
    /// Resolve to a `Vec<String>`.
    pub fn resolve(&self) -> anyhow::Result<Vec<String>> {
        match self {
            PayloadSource::Inline(values) => Ok(values.clone()),
            PayloadSource::File(path) => load_wordlist(path),
        }
    }
}

// ── PayloadGenerator ──────────────────────────────────────────────────────────

/// Generates payload combination maps for template variable substitution.
///
/// Each call to `next()` returns a `HashMap<name, value>` that can be merged
/// into the template variable context.
pub struct PayloadGenerator {
    attack_type: AttackType,
    /// Resolved payload sets: name → Vec<value>
    sets: Vec<(String, Vec<String>)>,
    /// Current iteration index / state
    state: GeneratorState,
}

enum GeneratorState {
    BatteringRam { index: usize },
    Pitchfork { index: usize },
    ClusterBomb { indices: Vec<usize>, done: bool },
}

impl PayloadGenerator {
    /// Construct a generator from a payload map and attack type.
    ///
    /// `payloads` maps variable name → `PayloadSource`. Sources are resolved
    /// (file paths loaded, inline lists kept) at construction time.
    pub fn new(
        attack_type: AttackType,
        payloads: &HashMap<String, PayloadSource>,
    ) -> anyhow::Result<Self> {
        let sets: Vec<(String, Vec<String>)> = payloads
            .iter()
            .map(|(name, source)| Ok((name.clone(), source.resolve()?)))
            .collect::<anyhow::Result<_>>()?;

        // Sort by name for deterministic ordering
        let mut sets = sets;
        sets.sort_by(|a, b| a.0.cmp(&b.0));

        let state = match attack_type {
            AttackType::BatteringRam => GeneratorState::BatteringRam { index: 0 },
            AttackType::Pitchfork => GeneratorState::Pitchfork { index: 0 },
            AttackType::ClusterBomb => {
                let done = sets.iter().any(|(_, v)| v.is_empty());
                GeneratorState::ClusterBomb {
                    indices: vec![0; sets.len()],
                    done,
                }
            }
        };

        Ok(Self {
            attack_type,
            sets,
            state,
        })
    }

    /// Total number of iterations this generator will produce.
    pub fn total(&self) -> usize {
        if self.sets.is_empty() {
            return 0;
        }
        match self.attack_type {
            AttackType::BatteringRam => self.sets.first().map(|(_, v)| v.len()).unwrap_or(0),
            AttackType::Pitchfork => self.sets.iter().map(|(_, v)| v.len()).min().unwrap_or(0),
            AttackType::ClusterBomb => self.sets.iter().map(|(_, v)| v.len()).product(),
        }
    }

    /// Return the next payload combination, or `None` when exhausted.
    pub fn next_payload(&mut self) -> Option<HashMap<String, String>> {
        if self.sets.is_empty() {
            return None;
        }

        match &mut self.state {
            GeneratorState::BatteringRam { index } => {
                let (name, values) = &self.sets[0];
                if *index >= values.len() {
                    return None;
                }
                let val = values[*index].clone();
                *index += 1;
                Some(std::iter::once((name.clone(), val)).collect())
            }

            GeneratorState::Pitchfork { index } => {
                let min_len = self.sets.iter().map(|(_, v)| v.len()).min().unwrap_or(0);
                if *index >= min_len {
                    return None;
                }
                let payload: HashMap<String, String> = self
                    .sets
                    .iter()
                    .map(|(name, values)| (name.clone(), values[*index].clone()))
                    .collect();
                *index += 1;
                Some(payload)
            }

            GeneratorState::ClusterBomb { indices, done } => {
                if *done {
                    return None;
                }

                let payload: HashMap<String, String> = self
                    .sets
                    .iter()
                    .enumerate()
                    .map(|(i, (name, values))| (name.clone(), values[indices[i]].clone()))
                    .collect();

                // Increment indices (rightmost first — last set cycles fastest)
                let mut carry = true;
                for i in (0..indices.len()).rev() {
                    if carry {
                        indices[i] += 1;
                        if indices[i] >= self.sets[i].1.len() {
                            indices[i] = 0;
                        } else {
                            carry = false;
                        }
                    }
                }
                if carry {
                    *done = true;
                }

                Some(payload)
            }
        }
    }
}

impl Iterator for PayloadGenerator {
    type Item = HashMap<String, String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_payload()
    }
}

// ── File loading ──────────────────────────────────────────────────────────────

/// Load a wordlist file — one entry per line, empty lines and `#` comments skipped.
pub fn load_wordlist(path: impl AsRef<Path>) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| anyhow::anyhow!("load wordlist {:?}: {}", path.as_ref(), e))?;
    let values: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    Ok(values)
}

// ── Template variable substitution ───────────────────────────────────────────

/// Apply a payload map to a template string, replacing `{{name}}` placeholders.
pub fn apply_payload(template: &str, payload: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (k, v) in payload {
        result = result.replace(&format!("{{{{{k}}}}}"), v);
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn inline(values: &[&str]) -> PayloadSource {
        PayloadSource::Inline(values.iter().map(|s| s.to_string()).collect())
    }

    fn gen(attack: AttackType, sets: &[(&str, &[&str])]) -> anyhow::Result<PayloadGenerator> {
        let map: HashMap<String, PayloadSource> = sets
            .iter()
            .map(|(name, vals)| (name.to_string(), inline(vals)))
            .collect();
        PayloadGenerator::new(attack, &map)
    }

    #[test]
    fn battering_ram_iterates_single_set() {
        let mut g = gen(AttackType::BatteringRam, &[("word", &["a", "b", "c"])]).unwrap();
        assert_eq!(g.total(), 3);
        assert_eq!(g.next_payload().unwrap()["word"], "a");
        assert_eq!(g.next_payload().unwrap()["word"], "b");
        assert_eq!(g.next_payload().unwrap()["word"], "c");
        assert!(g.next_payload().is_none());
    }

    #[test]
    fn pitchfork_zips_by_index() {
        let mut g = gen(
            AttackType::Pitchfork,
            &[("user", &["admin", "root"]), ("pass", &["x", "y", "z"])],
        )
        .unwrap();
        assert_eq!(g.total(), 2); // limited by shortest list
        let p0 = g.next_payload().unwrap();
        assert_eq!(p0["user"], "admin");
        assert_eq!(p0["pass"], "x");
        let p1 = g.next_payload().unwrap();
        assert_eq!(p1["user"], "root");
        assert_eq!(p1["pass"], "y");
        assert!(g.next_payload().is_none());
    }

    #[test]
    fn clusterbomb_cartesian_product() {
        let g = gen(
            AttackType::ClusterBomb,
            &[("a", &["1", "2"]), ("b", &["x", "y"])],
        )
        .unwrap();
        assert_eq!(g.total(), 4);
        let combos: Vec<(String, String)> = g.map(|p| (p["a"].clone(), p["b"].clone())).collect();
        assert!(combos.contains(&("1".into(), "x".into())));
        assert!(combos.contains(&("1".into(), "y".into())));
        assert!(combos.contains(&("2".into(), "x".into())));
        assert!(combos.contains(&("2".into(), "y".into())));
    }

    #[test]
    fn apply_payload_substitutes_variables() {
        let mut payload = HashMap::new();
        payload.insert("user".into(), "admin".into());
        payload.insert("pass".into(), "secret".into());
        let result = apply_payload("user={{user}}&pass={{pass}}", &payload);
        assert_eq!(result, "user=admin&pass=secret");
    }

    #[test]
    fn empty_payload_set_returns_none() {
        let map: HashMap<String, PayloadSource> =
            [("word".to_string(), inline(&[]))].into_iter().collect();
        let mut g = PayloadGenerator::new(AttackType::BatteringRam, &map).unwrap();
        assert_eq!(g.total(), 0);
        assert!(g.next_payload().is_none());
    }
}
