use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use super::{AppState, Config, database};
use crate::interfaces::http::build_router;

pub(crate) async fn serve() -> io::Result<()> {
    let config = Config::from_env()?;
    let conn = database::open(&config.db_path)?;
    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        config,
    });
    let app = build_router(state.clone());
    let bind = state
        .config
        .bind
        .parse::<SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("Motehold listening on http://{bind}");
    axum::serve(listener, app).await
}
