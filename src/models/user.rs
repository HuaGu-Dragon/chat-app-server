use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    PasswordVerifier,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, PgPool};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::{service::jwt::TokenPayload, Result};

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub token: Option<TokenPayload>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterUser {
    pub email: String,
    pub pin: String,
    pub password: String,
}

static EMAIL_REGEX: OnceCell<Regex> = OnceCell::const_new();

async fn get_email_regex() -> &'static Regex {
    EMAIL_REGEX
        .get_or_init(|| async {
            Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
        })
        .await
}

impl RegisterUser {
    pub async fn validate(&self) -> Result<()> {
        if self.email.is_empty()
            || self.password.is_empty()
            || self.pin.is_empty()
            || self.pin.len() != 6
        {
            return Err(crate::error::AppError::InvalidInput);
        }
        if self.password.len() < 8 {
            return Err(crate::error::AppError::InvalidInput);
        }
        if self.password.chars().any(|c| c.is_whitespace()) {
            return Err(crate::error::AppError::InvalidInput);
        }
        if self.pin.chars().any(|c| c.is_whitespace()) {
            return Err(crate::error::AppError::InvalidInput);
        }
        if self.email.chars().any(|c| c.is_whitespace()) {
            return Err(crate::error::AppError::InvalidInput);
        }
        // validate email format
        let email_regex = get_email_regex().await;
        if !email_regex.is_match(&self.email) {
            return Err(crate::error::AppError::InvalidInput);
        }

        Ok(())
    }
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            avatar_url: user.avatar_url,
            bio: user.bio,
            created_at: user.created_at,
            updated_at: user.updated_at,
            token: None,
        }
    }
}

impl User {
    pub async fn create(pool: &PgPool, user: RegisterUser) -> Result<Self> {
        let password_hash = Self::password_hash(&user.password)?;
        // let new_user = sqlx::query_as!(
        //     User,
        //     r#"
        //     INSERT INTO users (username, email, password_hash)
        //     VALUES ($1, $2, $3)
        //     RETURNING *
        //     "#,
        //     user.email,
        //     user.email,
        //     password_hash
        // )
        // .fetch_one(pool)
        // .await?;
        if user.pin != "111111" {
            return Err(crate::error::AppError::InvalidPin);
        }
        let new_user = sqlx::query_as(
            r#"
            INSERT INTO users (username, email, password_hash)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(&user.email)
        .bind(&user.email)
        .bind(password_hash)
        .fetch_one(pool)
        .await?;
        Ok(new_user)
    }

    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>> {
        // let user = sqlx::query_as!(User, r#"SELECT * FROM users WHERE email = $1"#, email)
        //     .fetch_optional(pool)
        //     .await?;
        let user = sqlx::query_as(
            r#"
            SELECT * FROM users WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;
        Ok(user)
    }

    pub async fn email_exist(pool: &PgPool, email: &str) -> Result<bool> {
        // let exists = sqlx::query_scalar!(
        //     r#"SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)"#,
        //     email
        // )
        // .fetch_one(pool)
        // .await?;
        let exists: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)
            "#,
        )
        .bind(email)
        .fetch_one(pool)
        .await?;
        Ok(exists.unwrap_or(false))
    }

    pub fn password_hash(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = argon2::Argon2::default();
        Ok(argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string())
    }

    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let argon2 = argon2::Argon2::default();
        let parsed_hash = argon2::PasswordHash::new(&self.password_hash)?;
        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}
