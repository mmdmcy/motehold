use std::{env, io, path::PathBuf};

use crate::security::auth::AuthConfig;

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) bind: String,
    pub(crate) db_path: PathBuf,
    pub(crate) auth: AuthConfig,
}

impl Config {
    pub(crate) fn from_env() -> io::Result<Self> {
        let bind = env::var("MOTEHOLD_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
        let db_path = env::var("MOTEHOLD_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/motehold.sqlite"));

        Ok(Self {
            bind,
            db_path,
            auth: AuthConfig::from_env()?,
        })
    }
}
