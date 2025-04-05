use sqlx::PgPool;

use crate::config::Config;

pub struct AppState {
    pub db_pool: PgPool,
    pub config: Config,
}
