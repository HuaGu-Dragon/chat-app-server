use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use error::AppError;
use middleware::auth::Claims;
use state::app_state::AppState;
use tokio::net::TcpListener;
use tower_http::cors;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod middleware;
mod models;
mod service;
mod state {
    pub mod app_state;
}

type Result<T> = std::result::Result<T, AppError>;

#[tokio::main]
async fn main() {
    let config = match config::load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    tracing::info!("Logging initialized with level: {:?}", Level::INFO);

    tracing::info!(
        "Starting server on {}:{}",
        config.server.host,
        config.server.port
    );
    tracing::info!("Database URL: {}", config.database.url);
    tracing::info!("JWT Secret: {}", config.jwt.secret);
    tracing::info!("CORS Allowed Origins: {:?}", config.cors.allowed_origins);
    tracing::info!("CORS Allowed Methods: {:?}", config.cors.allowed_methods);
    tracing::info!("CORS Allowed Headers: {:?}", config.cors.allowed_headers);
    tracing::info!("CORS Max Age: {}", config.cors.max_age);
    tracing::info!("CORS Allow Credentials: {}", config.cors.allow_credentials);
    tracing::info!("JWT Expiration: {}", config.jwt.expiration);
    tracing::info!(
        "Database Max Connections: {}",
        config.database.max_connections
    );
    tracing::info!(
        "Database Min Connections: {}",
        config.database.min_connections
    );
    tracing::info!(
        "Database Connection Timeout: {}",
        config.database.connection_timeout
    );
    tracing::info!("Server Host: {}", config.server.host);
    tracing::info!("Server Port: {}", config.server.port);

    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .min_connections(config.database.min_connections)
        .connect(&config.database.url)
        .await
        .expect("Failed to connect to database");

    let app_state = state::app_state::AppState::new(db_pool, config).await;

    let app_state = Arc::new(app_state);

    let addr = format!(
        "{}:{}",
        app_state.config.server.host, app_state.config.server.port
    );

    let app = Router::new()
        .route("/config", get(handler))
        .route("/summon_jwt/{user_id}", get(summer_jwt))
        .nest(
            "/protect",
            Router::new().route("/login", post(test_login)).layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    middleware::auth::jwt_middleware,
                ),
            ),
        )
        .layer(cors::CorsLayer::permissive())
        .with_state(app_state);

    tracing::info!("Listening on {}", addr);
    let listener = TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");
    tracing::info!("Server started successfully");
    tracing::info!("Server is running...");
    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
    tracing::info!("Server stopped");
    tracing::info!("Exiting application");
    tracing::info!("Goodbye!");

    println!("Hello, world!");
}

async fn handler(State(app_state): State<Arc<AppState>>) -> &'static str {
    tracing::info!("Handler called");
    tracing::info!("Config: {:?}", app_state.config);
    tracing::info!("Database pool: {:?}", app_state.db_pool);
    tracing::info!("CORS config: {:?}", app_state.config.cors);
    tracing::info!("JWT config: {:?}", app_state.config.jwt);
    tracing::info!("Server config: {:?}", app_state.config.server);
    tracing::info!("Database config: {:?}", app_state.config.database);
    "Hello, World!"
}

async fn test_login(claims: Claims) -> impl IntoResponse {
    tracing::info!("Claims: {:?}", claims);
    tracing::info!("User: {:?}", claims.sub);
    (StatusCode::OK, format!("Hello, {}", claims.sub))
}

async fn summer_jwt(
    State(app_state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    tracing::info!("Generating JWT");
    let jwt = service::jwt::JwtService::generate_token(&app_state.config.jwt.secret, &user_id, 60)
        .unwrap()
        .access_token;
    tracing::info!("Generated JWT: {}", jwt);
    (StatusCode::OK, jwt)
}
