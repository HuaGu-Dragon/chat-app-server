use axum::response::IntoResponse;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum AppError {
    #[error("config error: {0}")]
    ConfigError(String),
    #[error("request error: {0}")]
    ValidationError(String),
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("password hashing error: {0}")]
    PasswordHashError(String),
    #[error("json error: {0}")]
    JsonError(String),
    #[error("uuid error: {0}")]
    UuidError(#[from] uuid::Error),
    #[error("jwt error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Invalid pin")]
    InvalidPin,
    #[error("Email not found")]
    EmailNotFound,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid password")]
    InvalidPassword,
}

impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        AppError::ConfigError(err.to_string())
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DatabaseError(err.to_string())
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AppError::PasswordHashError(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::JsonError(err.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AppError::ValidationError(_) => axum::http::StatusCode::BAD_REQUEST,
            AppError::Unauthorized => axum::http::StatusCode::UNAUTHORIZED,
            AppError::InvalidToken => axum::http::StatusCode::UNAUTHORIZED,
            AppError::InvalidPin => axum::http::StatusCode::BAD_REQUEST,
            AppError::EmailNotFound => axum::http::StatusCode::NOT_FOUND,
            AppError::InvalidInput => axum::http::StatusCode::BAD_REQUEST,
            AppError::InvalidPassword => axum::http::StatusCode::UNAUTHORIZED,
            _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
