use std::sync::Arc;

use axum::Router;

use crate::state::app_state::AppState;

mod auth;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().nest("/auth", auth::router())
}
