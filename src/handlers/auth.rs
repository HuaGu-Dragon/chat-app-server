use std::sync::Arc;

use axum::{extract::State, Json};

use crate::{
    error::AppError,
    models::{
        user::{LoginUser, UserResponse},
        RegisterUser, User,
    },
    service::jwt::JwtService,
    state::app_state::AppState,
    Result,
};

pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterUser>,
) -> Result<Json<UserResponse>> {
    payload.validate().await?;
    if User::email_exist(&state.db_pool, &payload.email).await? {
        return Err(AppError::ValidationError(
            "Email already exists".to_string(),
        ));
    }
    let user = User::create(&state.db_pool, payload).await?;
    let token = JwtService::generate_token(&state.config.jwt.secret, &user.email, 60)?;
    let user = UserResponse::from(user);
    Ok(Json(UserResponse {
        token: Some(token),
        ..user
    }))
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginUser>,
) -> Result<Json<UserResponse>> {
    let user = User::find_by_email(&state.db_pool, &payload.email)
        .await?
        .ok_or(AppError::EmailNotFound)?;
    if !user.verify_password(&payload.password)? {
        return Err(AppError::InvalidPassword);
    }
    let token = JwtService::generate_token(&state.config.jwt.secret, &user.email, 60)?;
    let user = UserResponse::from(user);
    Ok(Json(UserResponse {
        token: Some(token),
        ..user
    }))
}
