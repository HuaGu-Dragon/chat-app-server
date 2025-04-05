use serde::Deserialize;

use crate::Result;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub cors: CorsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_age: u64,
    pub allow_credentials: bool,
}

pub fn load_config() -> Result<Config> {
    let base_path = std::env::current_dir().expect("Failed to get current directory");
    let config_path = base_path.join("config");
    let config_file = config_path.join("default.toml");
    let settings = config::Config::builder()
        .add_source(config::File::from(config_path.join(config_file)))
        .add_source(config::File::from(config_path.join(
            std::env::var("APP_ENV").unwrap_or_else(|_| "development.toml".into()),
        )))
        .add_source(config::Environment::with_prefix("APP"))
        .build()?;

    let config: Config = settings.try_deserialize()?;
    Ok(config)
}
