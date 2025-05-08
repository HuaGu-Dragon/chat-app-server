use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    PasswordVerifier,
};
use chrono::{DateTime, Utc};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, PgPool};
use tokio::sync::OnceCell;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{handlers::auth::generate_code, service::jwt::TokenPayload, Result};

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
pub struct CreateUser {
    pub email: String,
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

impl CreateUser {
    pub async fn validate(&self) -> Result<()> {
        if self.email.is_empty() {
            return Err(crate::error::AppError::InvalidInput);
        }
        if self.email.chars().any(|c| c.is_whitespace()) {
            return Err(crate::error::AppError::InvalidInput);
        }
        let email_regex = get_email_regex().await;
        if !email_regex.is_match(&self.email) {
            return Err(crate::error::AppError::InvalidInput);
        }
        Ok(())
    }
}

impl RegisterUser {
    async fn validate_email(&self) -> Result<()> {
        if self.email.is_empty() {
            return Err(crate::error::AppError::InvalidInput);
        }
        if self.email.chars().any(|c| c.is_whitespace()) {
            return Err(crate::error::AppError::InvalidInput);
        }
        let email_regex = get_email_regex().await;
        if !email_regex.is_match(&self.email) {
            return Err(crate::error::AppError::InvalidInput);
        }
        Ok(())
    }

    pub async fn validate(&self) -> Result<()> {
        self.validate_email().await?;
        if self.password.is_empty() || self.pin.is_empty() || self.pin.len() != 6 {
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
    pub async fn send_pin(
        pool: &PgPool,
        smtp_username: &str,
        smtp_password: &str,
        smtp_server: &str,
        to: String,
    ) -> Result<()> {
        let pin = Self::create_user(pool, &to).await?;

        let email = Message::builder()
            .from(smtp_username.parse().unwrap())
            .to(to.parse().unwrap())
            .subject("Your Pin Code")
            .header(ContentType::TEXT_PLAIN)
            .body(String::from(pin))
            .unwrap();

        let cred = Credentials::new(smtp_username.to_owned(), smtp_password.to_owned());

        let mailer: AsyncSmtpTransport<Tokio1Executor> =
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_server)
                .unwrap()
                .credentials(cred)
                .build();

        match mailer.send(email).await {
            Ok(_) => info!("send email success"),
            Err(e) => warn!("send email error: {:?}", e),
        };

        Ok(())
    }

    pub async fn create_user(pool: &PgPool, email: &str) -> Result<String> {
        let pin = generate_code(6);
        sqlx::query(
            r#"
            INSERT INTO create_users_table (email, pin)
            VALUES ($1, $2)
            ON CONFLICT (email) DO UPDATE
                SET pin = EXCLUDED.pin,
                    created_at = now()
            "#,
        )
        .bind(email)
        .bind(&pin)
        .execute(pool)
        .await?;
        Ok(pin)
    }

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
        let pin: Option<String> = sqlx::query_scalar(
            r#"
            SELECT pin
            FROM create_users_table
            WHERE email = $1
            "#,
        )
        .bind(&user.email)
        .fetch_optional(pool)
        .await?;
        if let Some(pin) = pin {
            if pin != user.pin {
                return Err(crate::error::AppError::InvalidPin);
            }
        } else {
            return Err(crate::error::AppError::ValidationError(
                "pin code not found. Please register again".to_owned(),
            ));
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
