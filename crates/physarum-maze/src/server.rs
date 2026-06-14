use crate::graph_sink::GraphSink;
use axum::{
    extract::State,
    http::{header, HeaderMap},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::get,
    Json, Router,
};
use physarum_protocol::OrganismGraph;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

static INDEX_HTML: &str = include_str!("server/index.html");

#[derive(Clone)]
struct AppState {
    sink: Arc<GraphSink>,
}

pub async fn start(port: u16, sink: Arc<GraphSink>) -> anyhow::Result<()> {
    let state = AppState { sink };
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/graph", get(graph_handler))
        .route("/events", get(events_handler))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("organism server → http://localhost:{port}/");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index_handler() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
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
