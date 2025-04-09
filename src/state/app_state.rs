use axum::extract::FromRef;
use sqlx::PgPool;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub config: Config,
}

impl AppState {
    pub async fn new(db_pool: PgPool, config: Config) -> Self {
        Self { db_pool, config }
    }
}
