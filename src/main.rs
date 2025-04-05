use error::AppError;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod models;
mod state {
    mod app_state;
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

    println!("Hello, world!");
}
