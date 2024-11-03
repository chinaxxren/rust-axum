use sqlx::{Pool, Postgres};
use crate::common::config::Config;

pub struct AppState {
    pub db: Pool<Postgres>,
    pub env: Config,
}

impl AppState {

    pub fn db(&self) -> &Pool<Postgres> {
        &self.db
    }

    pub fn env(&self) -> &Config {
        &self.env
    }
}