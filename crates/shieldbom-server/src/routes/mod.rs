mod scans;

use axum::routing::get;
use axum::Router;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api_routes())
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/scans", axum::routing::post(scans::create))
        .route("/scans", get(scans::list))
        .route("/scans/{id}", get(scans::get_by_id))
}

async fn health() -> &'static str {
    "ok"
}
