use chrono::Utc;
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::{middleware::auth::Claims, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub struct JwtService;

impl JwtService {
    pub fn generate_token(secret: &str, user_id: &str, expires_in: i64) -> Result<TokenPayload> {
        let now = Utc::now();
        let exp = now + chrono::Duration::hours(expires_in);
        let claims = Claims {
            sub: user_id.to_string(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )?;
        Ok(TokenPayload {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: expires_in * 3600,
        })
    }

    pub fn validate_token(token: &str, secret: &str) -> Result<Claims> {
        let token_data = jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_ref()),
            &jsonwebtoken::Validation::default(),
        )?;
        Ok(token_data.claims)
    }
}
