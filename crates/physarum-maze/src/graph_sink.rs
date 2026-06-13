use physarum_protocol::{ColonizationEvent, EventKind, OrganismGraph};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

const CHANNEL_CAPACITY: usize = 512;

/// Shared state between the organism agent loop and the axum server.
///
/// The agent loop calls `emit()` on every colonization event.
/// The server reads `graph` for the /graph snapshot, `log` for SSE replay on
/// reconnect (Last-Event-ID), and subscribes to `tx` for the live SSE stream.
pub struct GraphSink {
    pub graph: Arc<RwLock<OrganismGraph>>,
    pub tx: broadcast::Sender<ColonizationEvent>,
    /// Append-only event log — enables Last-Event-ID replay on browser reconnect.
    pub log: Arc<RwLock<Vec<ColonizationEvent>>>,
}

impl GraphSink {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            graph: Arc::new(RwLock::new(OrganismGraph::default())),
            tx,
            log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Apply a colonization event: update the in-memory graph, append to the
    /// replay log, and broadcast to live SSE subscribers.
    pub async fn emit(&self, kind: EventKind) {
        let event = ColonizationEvent::new(kind);
        {
            let mut g = self.graph.write().await;
            g.apply(&event);
        }
        {
            let mut log = self.log.write().await;
            log.push(event.clone());
        }
        // Ignore send errors — no subscribers yet is normal during startup.
        let _ = self.tx.send(event);
    }
}
