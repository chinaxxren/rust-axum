use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use axum::body::Body;

use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Serialize;
use sqlx::query_as;
use uuid::Uuid;

use crate::{
    model::{TokenClaims, User},
    AppState,
};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: &'static str,
    pub message: String,
}

/// 执行用户身份验证，通过验证用户的令牌并获取用户信息。
///
/// 该函数首先尝试从请求的 cookies 或请求头中获取用户的令牌。
/// 然后解码和验证令牌，提取用户的 ID，并查询数据库以获取用户信息。
/// 如果任何步骤失败，将返回相应的错误响应。
/// 否则，将用户信息添加到请求中，并传递控制权给下一个处理程序。
///
/// - `cookie_jar`: 包含请求中的所有 cookies，用于获取令牌。
/// - `State(data)`: 在请求之间共享的应用状态，包含数据库和环境信息。
/// - `mut req`: 进来的请求，可能在头部包含令牌。
/// - `next`: 处理完此中间件后传递控制权的下一个中间件或处理程序。
///
/// 返回:
/// - 成功时: 下一个处理程序执行的结果。
/// - 失败时: 表示身份验证失败原因的 HTTP 状态码和错误消息。
pub async fn auth(
    cookie_jar: CookieJar,
    State(data): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // 尝试从 cookies 中获取令牌
    let token = cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            // 尝试从请求头中获取令牌
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned())
                    } else {
                        None
                    }
                })
        });

    // 处理缺少令牌的错误
    let token = token.ok_or_else(|| {
        let json_error = ErrorResponse {
            status: "fail",
            message: "您未登录，请提供令牌".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    // 解码和验证令牌
    let claims = decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(data.env.jwt_secret.as_ref()),
        &Validation::default(),
    )
        .map_err(|_| {
            let json_error = ErrorResponse {
                status: "fail",
                message: "无效的令牌".to_string(),
            };
            (StatusCode::UNAUTHORIZED, Json(json_error))
        })?
        .claims;

    // 从令牌声明中解析用户 ID
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        let json_error = ErrorResponse {
            status: "fail",
            message: "无效的令牌".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    // 查询数据库以获取用户
    let user = query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let json_error = ErrorResponse {
                status: "fail",
                message: format!("从数据库获取用户时出错: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
        })?;

    // 处理用户不存在的错误
    let user = user.ok_or_else(|| {
        let json_error = ErrorResponse {
            status: "fail",
            message: "属于此令牌的用户已不存在".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    // 将用户信息添加到请求中，并传递控制权给下一个处理程序
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}