use axum::http::{HeaderValue, Method};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use tower_http::cors::CorsLayer;

pub fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
}
