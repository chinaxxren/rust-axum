use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use tokio::task::JoinError;
use sqlx::Error as SqlxError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DataBaseError(#[from] SqlxError),

    #[error("auth error: {0}")]
    Authenticate(#[from] AuthenticateError),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("bad request: {0}")]
    BadRequest(#[from] BadRequest),

    #[error("not found: {0}")]
    NotFound(#[from] NotFound),

    #[error("run sync task: {0}")]
    RunSyncTask(#[from] JoinError),

    #[error("Custom error: {0}")]
    CustomError(String),
}

impl AppError {
    fn get_codes(&self) -> (StatusCode, u16) {
        match *self {
            // 4XX Errors
            AppError::CustomError(_) => (StatusCode::BAD_REQUEST, 40001),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, 40002),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, 40003),
            AppError::Authenticate(AuthenticateError::WrongCredentials) => {
                (StatusCode::UNAUTHORIZED, 40004)
            }
            AppError::Authenticate(AuthenticateError::InvalidToken) => {
                (StatusCode::UNAUTHORIZED, 40005)
            }
            AppError::Authenticate(AuthenticateError::Locked) => (StatusCode::LOCKED, 40006),

            // 5XX Errors
            AppError::IoError(_) => (StatusCode::INTERNAL_SERVER_ERROR, 5000),
            AppError::Authenticate(AuthenticateError::TokenCreation) => {
                (StatusCode::INTERNAL_SERVER_ERROR, 5001)
            }
            AppError::DataBaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, 5003),
            AppError::RunSyncTask(_) => (StatusCode::INTERNAL_SERVER_ERROR, 5005),
        }
    }

    pub fn bad_request() -> Self {
        AppError::BadRequest(BadRequest {})
    }

    pub fn not_found() -> Self {
        AppError::NotFound(NotFound {})
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status_code, code) = self.get_codes();
        let message = self.to_string();
        let body = Json(json!({ "code": code, "message": message }));

        (status_code, body).into_response()
    }
}

#[derive(thiserror::Error, Debug)]
#[error("...")]
pub enum AuthenticateError {
    #[error("Wrong authentication credentials")]
    WrongCredentials,
    #[error("Failed to create authentication token")]
    TokenCreation,
    #[error("Invalid authentication credentials")]
    InvalidToken,
    #[error("User is locked")]
    Locked,
}

#[derive(thiserror::Error, Debug)]
#[error("Bad Request")]
pub struct BadRequest {}

#[derive(thiserror::Error, Debug)]
#[error("Not found")]
pub struct NotFound {}
