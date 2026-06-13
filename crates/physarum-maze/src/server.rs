use crate::graph_sink::GraphSink;
use axum::{
    Json, Router,
    extract::State,
    http::header,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use physarum_protocol::OrganismGraph;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

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
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX_HTML)
}

async fn graph_handler(State(state): State<AppState>) -> Json<OrganismGraph> {
    let graph = state.sink.graph.read().await;
    Json(graph.clone())
}

async fn events_handler(
    State(state): State<AppState>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.sink.tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        let event = result.ok()?;
        let data = serde_json::to_string(&event).ok()?;
        Some(Ok(Event::default().data(data)))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
