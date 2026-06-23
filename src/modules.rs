use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use std::sync::Arc;

use crate::{AppState, MAX_IMAGE_BYTES, MAX_NOTE_CHARS};

pub(crate) fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(crate::notes_page))
        .route("/login", get(crate::login_page).post(crate::login_post))
        .route("/logout", post(crate::logout_post))
        .route("/notes", get(crate::notes_page).post(crate::note_create))
        .route("/notes/channels", post(crate::channel_create))
        .route("/notes/channels/{id}/delete", post(crate::channel_delete))
        .route("/notes/{id}/delete", post(crate::note_delete))
        .route("/notes/images/{id}", get(crate::note_image))
        .layer(DefaultBodyLimit::max(
            MAX_IMAGE_BYTES + MAX_NOTE_CHARS + 1024 * 1024,
        ))
        .with_state(state)
}
