use rusqlite::Connection;
use std::sync::Mutex;

use super::Config;

pub(crate) struct AppState {
    pub(crate) db: Mutex<Connection>,
    pub(crate) config: Config,
}
