use rusqlite::Connection;
use std::sync::Mutex;

use super::Config;
use crate::security::auth::LoginLimiter;

pub(crate) struct AppState {
    pub(crate) db: Mutex<Connection>,
    pub(crate) config: Config,
    pub(crate) login_limiter: LoginLimiter,
}
