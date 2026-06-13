use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Live snapshot of the organism's propagation graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganismGraph {
    pub nodes: Vec<OrganismNode>,
    pub edges: Vec<OrganismEdge>,
}

impl OrganismGraph {
    /// Apply an event to this graph, mutating state in place.
    pub fn apply(&mut self, event: &ColonizationEvent) {
        match &event.kind {
            EventKind::NodeDiscovered { ip, depth } => {
                if !self.nodes.iter().any(|n| &n.id == ip) {
                    self.nodes.push(OrganismNode {
                        id: ip.clone(),
                        depth: *depth,
                        colonized: false,
                        confidence: 0.0,
                        cve: None,
                    });
                }
            }
            EventKind::NodeColonized {
                ip,
                depth,
                confidence,
                cve,
            } => {
                if let Some(n) = self.nodes.iter_mut().find(|n| &n.id == ip) {
                    n.colonized = true;
                    n.confidence = *confidence;
                    n.cve = cve.clone();
                } else {
                    self.nodes.push(OrganismNode {
                        id: ip.clone(),
                        depth: *depth,
                        colonized: true,
                        confidence: *confidence,
                        cve: cve.clone(),
                    });
                }
            }
            EventKind::EdgeAdded { from, to } => {
                if !self.edges.iter().any(|e| &e.from == from && &e.to == to) {
                    self.edges.push(OrganismEdge {
                        from: from.clone(),
                        to: to.clone(),
                        conductivity: 0.5,
                        timestamp: event.timestamp,
                    });
                }
            }
            EventKind::DijUpdated {
                from,
                to,
                conductivity,
            } => {
                if let Some(e) = self.edges.iter_mut().find(|e| &e.from == from && &e.to == to) {
                    e.conductivity = *conductivity;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganismNode {
    pub id: String,
    pub depth: u32,
    pub colonized: bool,
    pub confidence: f64,
    pub cve: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganismEdge {
    pub from: String,
    pub to: String,
    /// Physarum conductivity D_ij in [0.0, 1.0].
    pub conductivity: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColonizationEvent {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl ColonizationEvent {
    pub fn new(kind: EventKind) -> Self {
        Self {
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now(),
            kind,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    NodeDiscovered {
        ip: String,
        depth: u32,
    },
    NodeColonized {
        ip: String,
        depth: u32,
        confidence: f64,
        cve: Option<String>,
    },
    EdgeAdded {
        from: String,
        to: String,
    },
    DijUpdated {
        from: String,
        to: String,
        conductivity: f64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_node_discovered() {
        let mut g = OrganismGraph::default();
        g.apply(&ColonizationEvent::new(EventKind::NodeDiscovered {
            ip: "10.0.0.1".into(),
            depth: 0,
        }));
        assert_eq!(g.nodes.len(), 1);
        assert!(!g.nodes[0].colonized);
    }

    #[test]
    fn apply_node_colonized_upserts() {
        let mut g = OrganismGraph::default();
        let ev = ColonizationEvent::new(EventKind::NodeColonized {
            ip: "10.0.0.2".into(),
            depth: 1,
            confidence: 0.9,
            cve: Some("CVE-2021-31805".into()),
        });
        g.apply(&ev);
        assert_eq!(g.nodes.len(), 1);
        assert!(g.nodes[0].colonized);
        assert!((g.nodes[0].confidence - 0.9).abs() < 1e-9);
        assert_eq!(g.nodes[0].cve.as_deref(), Some("CVE-2021-31805"));
    }

    #[test]
    fn apply_edge_added_no_duplicate() {
        let mut g = OrganismGraph::default();
        let ev = ColonizationEvent::new(EventKind::EdgeAdded {
            from: "10.0.0.1".into(),
            to: "10.0.0.2".into(),
        });
        g.apply(&ev);
        g.apply(&ev);
        assert_eq!(g.edges.len(), 1);
    }

    #[test]
    fn event_round_trips_json() {
        let ev = ColonizationEvent::new(EventKind::NodeColonized {
            ip: "10.0.0.3".into(),
            depth: 2,
            confidence: 0.75,
            cve: None,
        });
        let json = serde_json::to_string(&ev).unwrap();
        let back: ColonizationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seq, ev.seq);
        if let EventKind::NodeColonized { ip, .. } = back.kind {
            assert_eq!(ip, "10.0.0.3");
        } else {
            panic!("wrong kind");
        }
    }
}
