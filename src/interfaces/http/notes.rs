use axum::{
    extract::{Form, Multipart, Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;

use super::presentation;
use crate::{
    app::AppState,
    features::notes::{
        DEFAULT_CHANNEL, MAX_ATTACHMENT_BYTES, MAX_CHANNEL_CHARS, MAX_IMAGE_BYTES, MAX_NOTE_CHARS,
        allowed_image_type, is_markdown_attachment, safe_attachment_filename,
    },
    persistence::notes::{self, NewNote},
    security::auth::{page_guard, raw_guard},
};

#[derive(Deserialize)]
pub(crate) struct NotesQuery {
    channel: Option<i64>,
}

pub(crate) async fn notes_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotesQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let channels = {
        let db = state.db.lock().unwrap();
        notes::list_channels(&db).unwrap_or_default()
    };
    let active_channel = channels
        .iter()
        .find(|channel| Some(channel.id) == query.channel)
        .or_else(|| channels.first());
    let active_channel_id = active_channel.map(|channel| channel.id).unwrap_or(1);
    let active_channel_name = active_channel
        .map(|channel| channel.name.as_str())
        .unwrap_or(DEFAULT_CHANNEL);
    let note_rows = {
        let db = state.db.lock().unwrap();
        notes::list_notes(&db, Some(active_channel_id)).unwrap_or_default()
    };
    presentation::notes_page(
        &channels,
        active_channel_id,
        active_channel_name,
        &note_rows,
    )
}

#[derive(Deserialize)]
pub(crate) struct ChannelForm {
    name: String,
}

pub(crate) async fn channel_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ChannelForm>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let name = form.name.trim();
    let mut channel_id = None;
    if !name.is_empty() && name.chars().count() <= MAX_CHANNEL_CHARS {
        let db = state.db.lock().unwrap();
        channel_id = notes::ensure_channel(&db, name).ok();
    }
    Redirect::to(&notes_location(channel_id)).into_response()
}

pub(crate) async fn channel_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let db = state.db.lock().unwrap();
    let channel_count = notes::channel_count(&db).unwrap_or(0);
    if channel_count > 1 {
        let _ = notes::delete_channel(&db, id);
    }
    Redirect::to(&notes_location(None)).into_response()
}

pub(crate) async fn note_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let mut channel_id = None;
    let mut body = String::new();
    let mut image_type: Option<String> = None;
    let mut image_data: Option<Vec<u8>> = None;
    let mut attachment_name: Option<String> = None;
    let mut attachment_type: Option<String> = None;
    let mut attachment_data: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "channel_id" => {
                if let Ok(text) = field.text().await {
                    channel_id = text.trim().parse::<i64>().ok();
                }
            }
            "body" => {
                if let Ok(text) = field.text().await {
                    body = text;
                }
            }
            "image" | "attachment" => {
                let file_name = field.file_name().map(str::to_string);
                let content_type = field.content_type().map(str::to_string);
                let Ok(bytes) = field.bytes().await else {
                    continue;
                };
                if content_type.as_deref().is_some_and(allowed_image_type)
                    && !bytes.is_empty()
                    && bytes.len() <= MAX_IMAGE_BYTES
                {
                    image_type = content_type;
                    image_data = Some(bytes.to_vec());
                } else if is_markdown_attachment(file_name.as_deref(), content_type.as_deref())
                    && !bytes.is_empty()
                    && bytes.len() <= MAX_ATTACHMENT_BYTES
                    && String::from_utf8(bytes.to_vec()).is_ok()
                {
                    attachment_name = Some(
                        file_name
                            .filter(|name| !name.trim().is_empty())
                            .unwrap_or_else(|| "attachment.md".into()),
                    );
                    attachment_type = Some("text/markdown; charset=utf-8".into());
                    attachment_data = Some(bytes.to_vec());
                }
            }
            _ => {}
        }
    }

    let body = body.trim().to_string();
    let channel_id = channel_id.unwrap_or(1);
    if (!body.is_empty() || image_data.is_some() || attachment_data.is_some())
        && body.len() <= MAX_NOTE_CHARS
    {
        let db = state.db.lock().unwrap();
        if notes::channel_exists(&db, channel_id).unwrap_or(false) {
            let _ = notes::insert_note(
                &db,
                NewNote {
                    channel_id,
                    body,
                    image_type,
                    image_data,
                    attachment_name,
                    attachment_type,
                    attachment_data,
                    created_at: Utc::now().to_rfc3339(),
                },
            );
        }
    }
    Redirect::to(&notes_location(Some(channel_id))).into_response()
}

pub(crate) async fn note_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let db = state.db.lock().unwrap();
    let channel_id = notes::note_channel_id(&db, id).unwrap_or(None);
    let _ = notes::delete_note(&db, id);
    Redirect::to(&notes_location(channel_id)).into_response()
}

pub(crate) async fn note_image(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let row = {
        let db = state.db.lock().unwrap();
        notes::note_image(&db, id).unwrap_or(None)
    };
    let Some((image_type, bytes)) = row else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if bytes.len() > MAX_IMAGE_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "image too large").into_response();
    }
    let content_type = image_type.unwrap_or_else(|| "application/octet-stream".into());
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type).unwrap(),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        bytes,
    )
        .into_response()
}

pub(crate) async fn note_attachment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let row = {
        let db = state.db.lock().unwrap();
        notes::note_attachment(&db, id).unwrap_or(None)
    };
    let Some((name, bytes)) = row else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if bytes.len() > MAX_ATTACHMENT_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "attachment too large").into_response();
    }
    let filename = safe_attachment_filename(name.as_deref().unwrap_or("attachment.md"));
    let disposition = format!("attachment; filename=\"{filename}\"");
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/markdown; charset=utf-8"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition).unwrap(),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        bytes,
    )
        .into_response()
}

fn notes_location(channel_id: Option<i64>) -> String {
    channel_id
        .filter(|id| *id > 0)
        .map(|id| format!("/notes?channel={id}"))
        .unwrap_or_else(|| "/notes".into())
}
