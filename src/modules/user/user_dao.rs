// 查询用户

use std::sync::Arc;
use uuid::Uuid;
use crate::common::app_state::AppState;
use crate::common::errors::AppError;
use crate::modules::user::user_model::User;

pub async fn exists_user_by_email(data: &Arc<AppState>, email: &String) -> Result<Option<bool>, AppError> {
    let exists = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(email.to_ascii_lowercase())
        .fetch_one(&data.db)
        .await?;
    Ok(exists)
}

pub async fn find_user_by_email(data: &Arc<AppState>, email: &String) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as!(User,"SELECT * FROM users WHERE email = $1",email.to_ascii_lowercase())
        .fetch_optional(&data.db)
        .await?;
    Ok(user)
}

pub async fn find_user_by_id(data: &Arc<AppState>, user_id: Uuid) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_optional(&data.db)
        .await?;
    Ok(user)
}

pub async fn save_user(data: &Arc<AppState>, name: &String, email: &String, password: &String) -> Result<User, AppError> {
    let user = sqlx::query_as!(User,"INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",name,email.to_ascii_lowercase(),password)
        .fetch_one(&data.db)
        .await?;
    Ok(user)
}