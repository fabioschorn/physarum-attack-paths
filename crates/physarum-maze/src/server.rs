use crate::graph_sink::GraphSink;
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
use base64::{engine::general_purpose::STANDARD, Engine};
use physarum_protocol::{ColonizationReport, EventKind, OrganismGraph};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

static INDEX_HTML: &str = include_str!("server/index.html");

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

pub async fn start(port: u16, sink: Arc<GraphSink>) -> anyhow::Result<()> {
    let state = AppState { sink };

    // Browser-facing routes — protected by Basic Auth.
    let protected = Router::new()
        .route("/", get(index_handler))
        .route("/graph", get(graph_handler))
        .route("/events", get(events_handler))
        .layer(middleware::from_fn(require_basic_auth));

    // Agent back-channel — no auth, internal Docker network only.
    let internal = Router::new().route("/report-colonization", post(report_colonization_handler));

    let app = Router::new()
        .merge(protected)
        .merge(internal)
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("organism server → http://localhost:{port}/");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn index_handler() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
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
        cve_ids = ?report.cve_ids,
        "back-channel: colonization report received"
    );

    let sink = &state.sink;

    // Ensure the colonized hop exists as a node.
    sink.emit(EventKind::NodeDiscovered {
        ip: report.hop_ip.clone(),
        depth: report.depth,
    })
    .await;

    // Edge from the reporting hop to the newly colonized host.
    sink.emit(EventKind::EdgeAdded {
        from: from_ip.clone(),
        to: report.hop_ip.clone(),
    })
    .await;

    // Mark the hop as colonized with LLM evidence.
    sink.emit(EventKind::NodeColonized {
        ip: report.hop_ip.clone(),
        depth: report.depth,
        confidence: report.confidence,
        cve: report.cve_ids.first().cloned(),
    })
    .await;

    // D_ij update: use LLM confidence as conductivity (Phase 1 approximation).
    sink.emit(EventKind::DijUpdated {
        from: from_ip,
        to: report.hop_ip.clone(),
        conductivity: report.confidence.clamp(0.1, 0.95),
    })
    .await;

    StatusCode::OK
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
