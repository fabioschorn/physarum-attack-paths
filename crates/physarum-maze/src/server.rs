use crate::graph_sink::GraphSink;
use crate::tls_store::TlsStore;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::STANDARD, Engine};
use physarum_protocol::{ColonizationReport, EventKind, OrganismGraph};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

const VERSION: &str = env!("CARGO_PKG_VERSION");
static INDEX_HTML_TPL: &str = include_str!("server/index.html");

const AUTH_USER: &str = "admin";
const AUTH_PASS: &str = "Physarum-M@z&";

#[derive(Clone)]
struct AppState {
    sink: Arc<GraphSink>,
}

/// HTTP Basic Auth middleware — protects browser-facing routes only.
/// /report-colonization is excluded so propagated agents can call back freely.
async fn require_basic_auth(req: Request, next: Next) -> Response {
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|creds| creds == format!("{}:{}", AUTH_USER, AUTH_PASS));

    if authorized {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(
                "WWW-Authenticate",
                "Basic realm=\"physarum-maze\", charset=\"UTF-8\"",
            )],
            "Unauthorized",
        )
            .into_response()
    }
}

/// Browser-facing server — /, /graph, /events (Basic Auth) + /report-colonization.
/// When `tls` is Some: HTTPS on 127.0.0.1 (Issue #190 — self-signed ephemeral cert).
/// When `tls` is None: plain HTTP on 0.0.0.0 (lab default, no browser warning).
pub async fn start(
    port: u16,
    sink: Arc<GraphSink>,
    tls: Option<Arc<TlsStore>>,
) -> anyhow::Result<()> {
    let state = AppState { sink };

    let protected = Router::new()
        .route("/", get(index_handler))
        .route("/graph", get(graph_handler))
        .route("/events", get(events_handler))
        .layer(middleware::from_fn(require_basic_auth));

    let internal = Router::new().route("/report-colonization", post(report_colonization_handler));

    let app = Router::new()
        .merge(protected)
        .merge(internal)
        .with_state(state);

    if let Some(store) = tls {
        // HTTPS — bind all interfaces so Docker port-forwarding can reach the container.
        // 127.0.0.1 would work for native deploys but breaks Docker's port mapping.
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        let server_config = store.browser_rustls_config()?;
        let rustls_config = RustlsConfig::from_config(Arc::new(server_config));
        tracing::info!(
            "organism server → https://localhost:{port}/  \
             (self-signed cert — click Advanced → Proceed on first visit)"
        );
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        // Plain HTTP — bind all interfaces so the Docker bridge can reach it.
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        tracing::info!("organism server → http://localhost:{port}/");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

/// mTLS back-channel — /report-colonization only; client must present cert signed by seed CA.
/// Runs on a separate port (server_port + 1) so the browser HTTP server is unaffected.
pub async fn start_mtls_backchannel(
    port: u16,
    sink: Arc<GraphSink>,
    store: Arc<TlsStore>,
) -> anyhow::Result<()> {
    let state = AppState { sink };

    let app = Router::new()
        .route("/report-colonization", post(report_colonization_handler))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let server_config = store.server_rustls_config()?;
    let rustls_config = RustlsConfig::from_config(Arc::new(server_config));
    tracing::info!("mTLS back-channel → https://0.0.0.0:{port}/report-colonization");
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

async fn index_handler() -> impl IntoResponse {
    let html = INDEX_HTML_TPL.replace("{{PHYSARUM_VERSION}}", &format!("v{VERSION}"));
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

/// Receive a colonization report from a propagated agent and update the organism graph.
///
/// The `from_ip` is inferred from the TCP source address — the reporting agent's
/// real IP — so the graph edge is accurate regardless of what the agent knows
/// about its own address. The seed emits `NodeDiscovered`, `EdgeAdded`,
/// `NodeColonized`, and `DijUpdated` for the downstream hop.
async fn report_colonization_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(report): Json<ColonizationReport>,
) -> StatusCode {
    let from_ip = addr.ip().to_string();
    tracing::info!(
        from = %from_ip,
        hop = %report.hop_ip,
        depth = report.depth,
        confidence = report.confidence,
        scoring_mode = ?report.scoring_mode,
        q_ema = ?report.q_ema,
        scoring_observations = ?report.scoring_observations,
        cve_ids = ?report.cve_ids,
        "back-channel: colonization report received"
    );

    let events = {
        let graph = state.sink.graph.read().await;
        colonization_report_events(&graph, &from_ip, &report)
    };
    for event in events {
        state.sink.emit(event).await;
    }

    StatusCode::OK
}

fn colonization_report_events(
    graph: &OrganismGraph,
    from_ip: &str,
    report: &ColonizationReport,
) -> Vec<EventKind> {
    let mut events = Vec::new();
    let existing_node = graph.nodes.iter().find(|node| node.id == report.hop_ip);
    let report_cve = report.cve_ids.first().cloned();

    if existing_node.is_none() {
        events.push(EventKind::NodeDiscovered {
            ip: report.hop_ip.clone(),
            depth: report.depth,
        });
    }

    let improves_node = existing_node.is_none_or(|node| {
        !node.colonized
            || report.confidence > node.confidence
            || (node.cve.is_none() && report_cve.is_some())
    });
    if improves_node {
        events.push(EventKind::NodeColonized {
            ip: report.hop_ip.clone(),
            depth: report.depth,
            confidence: report.confidence,
            cve: report_cve,
        });
    }

    // A propagated agent reports itself on startup. That confirms the node but
    // does not describe a network edge, so never create hop_ip -> hop_ip.
    if from_ip == report.hop_ip {
        return events;
    }

    let edge_exists = graph
        .edges
        .iter()
        .any(|edge| edge.from == from_ip && edge.to == report.hop_ip);
    if !edge_exists {
        events.push(EventKind::EdgeAdded {
            from: from_ip.to_string(),
            to: report.hop_ip.clone(),
        });
    }

    // New agents send the runtime-selected conductivity. Older agents omit it;
    // use the Phase 1 fallback only when creating a previously unknown edge.
    let conductivity = report
        .conductivity
        .filter(|value| value.is_finite())
        .map(|value| value.clamp(0.0, 1.0))
        .or_else(|| (!edge_exists).then_some(report.confidence.clamp(0.1, 0.95)));
    if let Some(conductivity) = conductivity {
        events.push(EventKind::DijUpdated {
            from: from_ip.to_string(),
            to: report.hop_ip.clone(),
            conductivity,
        });
    }

    events
}

async fn graph_handler(State(state): State<AppState>) -> Json<OrganismGraph> {
    let graph = state.sink.graph.read().await;
    Json(graph.clone())
}

async fn events_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    // Parse Last-Event-ID sent by the browser on reconnect.
    let last_seq: Option<u64> = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Subscribe to live broadcast BEFORE reading the log — ensures no event
    // emitted between the log snapshot and subscribe is lost.
    let rx = state.sink.tx.subscribe();

    // Build replay slice and track the highest seq we will send via replay.
    // cutoff is used to deduplicate live stream events that overlap the log.
    let (replay, cutoff): (Vec<Event>, Option<u64>) = {
        let log = state.sink.log.read().await;
        let mut max_seq: Option<u64> = last_seq;
        let events: Vec<Event> = log
            .iter()
            .filter(|e| last_seq.is_some_and(|seq| e.seq > seq))
            .filter_map(|e| {
                max_seq = Some(max_seq.map_or(e.seq, |m| m.max(e.seq)));
                let data = serde_json::to_string(e).ok()?;
                Some(Event::default().data(data).id(e.seq.to_string()))
            })
            .collect();
        (events, if last_seq.is_some() { max_seq } else { None })
    };

    let replay_stream = futures::stream::iter(replay.into_iter().map(Ok::<_, Infallible>));

    let live_stream = BroadcastStream::new(rx).filter_map(move |result| {
        let event = result.ok()?;
        // Drop events already covered by the replay window.
        if cutoff.is_some_and(|c| event.seq <= c) {
            return None;
        }
        let data = serde_json::to_string(&event).ok()?;
        // Set id on every event so the browser tracks Last-Event-ID continuously.
        Some(Ok(Event::default().data(data).id(event.seq.to_string())))
    });

    Sse::new(replay_stream.chain(live_stream)).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use physarum_protocol::{OrganismEdge, OrganismNode};

    fn report(hop_ip: &str, confidence: f64, cve_ids: Vec<&str>) -> ColonizationReport {
        ColonizationReport {
            hop_ip: hop_ip.into(),
            depth: 1,
            confidence,
            cve_ids: cve_ids.into_iter().map(str::to_string).collect(),
            conductivity: None,
            q_ema: None,
            scoring_observations: None,
            scoring_mode: None,
        }
    }

    #[test]
    fn startup_report_for_known_node_is_a_noop() {
        let graph = OrganismGraph {
            nodes: vec![OrganismNode {
                id: "10.0.0.2".into(),
                depth: 1,
                colonized: true,
                confidence: 0.95,
                cve: Some("CVE-2020-17530".into()),
            }],
            edges: vec![],
        };

        let events =
            colonization_report_events(&graph, "10.0.0.2", &report("10.0.0.2", 0.9, vec![]));

        assert!(events.is_empty());
    }

    #[test]
    fn legacy_report_does_not_overwrite_existing_edge_conductivity() {
        let graph = OrganismGraph {
            nodes: vec![],
            edges: vec![OrganismEdge {
                from: "10.0.0.1".into(),
                to: "10.0.0.2".into(),
                conductivity: 0.064,
                timestamp: Utc::now(),
            }],
        };

        let events =
            colonization_report_events(&graph, "10.0.0.1", &report("10.0.0.2", 0.9, vec![]));

        assert!(events
            .iter()
            .all(|event| !matches!(event, EventKind::DijUpdated { .. })));
    }

    #[test]
    fn downstream_report_creates_edge_and_uses_supplied_dij() {
        let graph = OrganismGraph::default();
        let mut report = report("10.0.0.3", 0.95, vec!["CVE-2021-31805"]);
        report.conductivity = Some(0.061);

        let events = colonization_report_events(&graph, "10.0.0.2", &report);

        assert!(events.iter().any(|event| matches!(
            event,
            EventKind::EdgeAdded { from, to }
                if from == "10.0.0.2" && to == "10.0.0.3"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            EventKind::DijUpdated { conductivity, .. }
                if (*conductivity - 0.061).abs() < 1e-12
        )));
    }
}
