use std::sync::Arc;

use axum::{routing::post, Router};

use crate::{
    handlers::auth::{login_handler, pre_register_handler, register_handler},
    state::app_state::AppState,
};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login", post(login_handler))
        .route("/pre_register", post(pre_register_handler))
        .route("/register", post(register_handler))
}
