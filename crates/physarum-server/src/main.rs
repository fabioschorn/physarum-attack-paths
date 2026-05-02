use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod routes;
mod state;

use state::AppState;

#[derive(Parser)]
#[command(name = "physarum-server", about = "Physarum attack-path coordinator")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080", env = "PHYSARUM_LISTEN")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let state = Arc::new(AppState::new());

    let app = Router::new()
        .route("/health", get(routes::health::health))
        .route("/register", post(routes::agents::register))
        .route("/agents", get(routes::agents::list_agents))
        .with_state(state);

    tracing::info!("physarum-server listening on {}", cli.listen);

    let listener = tokio::net::TcpListener::bind(cli.listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
