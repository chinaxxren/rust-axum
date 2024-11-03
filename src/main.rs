use std::sync::Arc;

use axum::middleware::from_fn;
use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use dotenv::dotenv;
use tower_http::cors::CorsLayer;

use sqlx::{postgres::PgPoolOptions};
use tokio::net::TcpListener;
use tracing::log::info;
use tower::ServiceBuilder;

mod common;
mod modules;
mod middlewares;

use crate::{
    middlewares::{
        request_id::{set_request_id, propagate_request_id},
        request_response_logger::print_request_response,
        trace::trace,
        cors::cors,
        request_id,
        trace,
    },
    modules::user::user_route,
    common::config::Config,
    common::errors::AppError,
    common::app_state::AppState,
};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            info!("✅Connection to the database is successful!");
            pool
        }
        Err(err) => {
            info!("🔥 Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    let app = user_route::create_router(Arc::new(AppState {
        db: pool.clone(),
        env: config.clone(),
    })).layer(from_fn(
        print_request_response,
    ))
        //建议使用 tower::ServiceBuilder 一次应用多个中间件，而不是重复调用layer（或route_layer）。
        //ServiceBuilder 的工作原理是将所有层组合成一个层，以便它们从上到下运行。
        //自上而下执行中间件通常更容易理解和遵循，这也是推荐使用 ServiceBuilder 的原因之一。
        .layer(
            ServiceBuilder::new()
                .layer(set_request_id())
                .layer(propagate_request_id())
                .layer(trace())
                .layer(cors()),
        );

    let listener = TcpListener::bind("0.0.0.0:8000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

