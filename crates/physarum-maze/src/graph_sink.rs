use physarum_protocol::{ColonizationEvent, EventKind, OrganismGraph};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

const CHANNEL_CAPACITY: usize = 512;

/// Shared state between the organism agent loop and the axum server.
///
/// The agent loop calls `emit()` on every colonization event.
/// The server reads `graph` for the /graph snapshot and subscribes to `tx` for SSE.
pub struct GraphSink {
    pub graph: Arc<RwLock<OrganismGraph>>,
    pub tx: broadcast::Sender<ColonizationEvent>,
}

impl GraphSink {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            graph: Arc::new(RwLock::new(OrganismGraph::default())),
            tx,
        }
    }

    /// Apply a colonization event: update the in-memory graph and broadcast to SSE subscribers.
    pub async fn emit(&self, kind: EventKind) {
        let event = ColonizationEvent::new(kind);
        {
            let mut g = self.graph.write().await;
            g.apply(&event);
        }
        // Ignore send errors — no subscribers yet is normal during startup.
        let _ = self.tx.send(event);
    }
}
