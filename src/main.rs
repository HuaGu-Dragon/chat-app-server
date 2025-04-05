use config::Config;

use error::AppError;

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
    println!("Hello, world!");
}
