use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("config error: {0}")]
    ConfigError(#[from] config::ConfigError),
    #[error("request error: {0}")]
    ValidationError(String),
    #[error("database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("password hashing error: {0}")]
    PasswordHashError(String),
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("uuid error: {0}")]
    UuidError(#[from] uuid::Error),
    #[error("Unauthorized")]
    Unauthorized,
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AppError::PasswordHashError(err.to_string())
    }
}
