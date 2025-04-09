use std::sync::Arc;

use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{request::Parts, Request},
    middleware::Next,
    response::Response,
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::{Deserialize, Serialize};

use crate::{error::AppError, service::jwt::JwtService, state::app_state::AppState};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync + AsRef<AppState>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<crate::Result<Claims>>()
            .ok_or(AppError::Unauthorized)?
            .clone()
    }
}

pub async fn jwt_middleware(
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> crate::Result<Response> {
    let (mut parts, body) = request.into_parts();

    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await
        .map_err(|_| AppError::Unauthorized)?;
    let claims = JwtService::validate_token(bearer.token(), &app_state.config.jwt.secret)
        .map_err(|_| AppError::Unauthorized);
    tracing::info!("Token: {:?}", bearer.token());
    tracing::info!("Claims: {:?}", claims);
    parts.extensions.insert(claims);
    let request = Request::from_parts(parts, body);
    Ok(next.run(request).await)
}
