use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    extract::{Form, Multipart, Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Read},
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;

mod db_migrations;
mod modules;

const DEFAULT_CHANNEL: &str = "general";
const MAX_NOTE_CHARS: usize = 256 * 1024;
const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
const MAX_CHANNEL_CHARS: usize = 40;
const SESSION_COOKIE: &str = "motehold_session";
const SESSION_DAYS: i64 = 30;
const PAGE_CSS: &str = include_str!("page.css");

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str).unwrap_or("serve") {
        "serve" => serve().await,
        "hash-password" => {
            hash_password_cmd(&args[1..])?;
            Ok(())
        }
        "audit-public" => {
            if audit_public_cmd(&args[1..])? != 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        _ => {
            eprintln!("usage: motehold [serve|hash-password --stdin|audit-public]");
            Ok(())
        }
    }
}

async fn serve() -> io::Result<()> {
    let config = Config::from_env()?;
    let conn = open_db(&config.db_path)?;
    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        config,
    });
    let app = modules::build_router(state.clone());
    let bind = state
        .config
        .bind
        .parse::<SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("Motehold listening on http://{bind}");
    axum::serve(listener, app).await
}

#[derive(Clone)]
struct Config {
    bind: String,
    db_path: PathBuf,
    user: String,
    password_hash: Option<String>,
    cookie_secret: Vec<u8>,
    auth_disabled: bool,
}

impl Config {
    fn from_env() -> io::Result<Self> {
        let bind = env::var("MOTEHOLD_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
        let db_path = env::var("MOTEHOLD_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/motehold.sqlite"));
        let user = env::var("MOTEHOLD_USER").unwrap_or_else(|_| "motehold".into());
        let password_hash = env::var("MOTEHOLD_PASSWORD_HASH")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let auth_disabled = env_flag("MOTEHOLD_AUTH_DISABLED", true);
        if password_hash.is_none() && !auth_disabled {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MOTEHOLD_PASSWORD_HASH is required unless MOTEHOLD_AUTH_DISABLED=1",
            ));
        }
        let cookie_secret = env::var("MOTEHOLD_COOKIE_SECRET")
            .ok()
            .and_then(|value| hex::decode(value.trim()).ok())
            .filter(|bytes| bytes.len() >= 32)
            .unwrap_or_else(random_secret);

        Ok(Self {
            bind,
            db_path,
            user,
            password_hash,
            cookie_secret,
            auth_disabled,
        })
    }
}

struct AppState {
    db: Mutex<Connection>,
    config: Config,
}

#[derive(Debug)]
struct AuditFinding {
    path: String,
    line: Option<usize>,
    message: String,
}

fn open_db(path: &Path) -> io::Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).map_err(io_other)?;
    db_migrations::migrate(&conn).map_err(io_other)?;
    ensure_channel(&conn, DEFAULT_CHANNEL).map_err(io_other)?;
    Ok(conn)
}

fn ensure_channel(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    let existing = conn
        .query_row(
            "SELECT id FROM channels WHERE name = ?1",
            params![name],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO channels (name, created_at) VALUES (?1, ?2)",
        params![name, Utc::now().to_rfc3339()],
    )?;
    Ok(conn.last_insert_rowid())
}

async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if authorized(&state.config, &headers) {
        return Redirect::to("/").into_response();
    }
    page(
        "Motehold Login",
        r#"
<main class="login">
  <h1>Motehold</h1>
  <form action="/login" method="post">
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">Log in</button>
  </form>
</main>
"#,
    )
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login_post(State(state): State<Arc<AppState>>, Form(form): Form<LoginForm>) -> Response {
    if !verify_password(&state.config, &form.password) {
        return page(
            "Motehold Login",
            r#"
<main class="login">
  <h1>Motehold</h1>
  <p class="error">Wrong password.</p>
  <form action="/login" method="post">
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">Log in</button>
  </form>
</main>
"#,
        );
    }
    let cookie = make_session_cookie(&state.config);
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_static("/")),
            (header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap()),
        ],
    )
        .into_response()
}

async fn logout_post() -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_static("/login")),
            (
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "motehold_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
                ),
            ),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
struct NotesQuery {
    channel: Option<i64>,
}

async fn notes_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotesQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let channels = {
        let db = state.db.lock().unwrap();
        list_channels(&db).unwrap_or_default()
    };
    let active_channel = channels
        .iter()
        .find(|channel| Some(channel.id) == query.channel)
        .or_else(|| channels.first());
    let active_channel_id = active_channel.map(|channel| channel.id).unwrap_or(1);
    let active_channel_name = active_channel
        .map(|channel| channel.name.as_str())
        .unwrap_or(DEFAULT_CHANNEL);
    let notes = {
        let db = state.db.lock().unwrap();
        list_notes(&db, Some(active_channel_id)).unwrap_or_default()
    };
    let channels_html = channels
        .iter()
        .map(|channel| {
            let active_class = if channel.id == active_channel_id {
                " active"
            } else {
                ""
            };
            let channel_name = html_escape(&channel.name);
            let delete = if channels.len() > 1 {
                format!(
                    r#"<form action="/notes/channels/{}/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete channel {}">x</button></form>"#,
                    channel.id, channel_name
                )
            } else {
                String::new()
            };
            format!(
                r##"<div class="channel-row{active_class}"><a class="channel-link" href="/notes?channel={}"><span>#</span>{}</a>{}</div>"##,
                channel.id, channel_name, delete
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let active_channel_label = html_escape(active_channel_name);
    let notes_html = if notes.is_empty() {
        format!(
            r##"<p class="empty">No messages in #{} yet.</p>"##,
            active_channel_label
        )
    } else {
        notes
            .iter()
            .rev()
            .map(|note| {
                let body = if note.body.trim().is_empty() {
                    String::new()
                } else {
                    format!(r#"<p>{}</p>"#, html_escape(&note.body).replace('\n', "<br>"))
                };
                let image = if note.has_image {
                    format!(
                        r#"<img class="message-image" src="/notes/images/{}" alt="">"#,
                        note.id
                    )
                } else {
                    String::new()
                };
                format!(
                    r##"<article class="message">
  <div class="message-avatar">#</div>
  <div class="message-body">
    <div class="message-meta"><strong>{}</strong><form action="/notes/{}/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete message">x</button></form></div>
    {}{}
  </div>
</article>"##,
                    html_escape(&note.channel),
                    note.id,
                    body,
                    image
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let message_count = notes.len();
    page(
        "Notes",
        &format!(
            r#"
<nav><a href="/">Motehold</a><strong>Notes</strong><form action="/logout" method="post"><button class="ghost" type="submit">Log out</button></form></nav>
<main class="chat-shell">
  <aside class="channel-rail" aria-label="Channels">
    <div class="rail-title">Channels</div>
    <div class="channel-list">{channels_html}</div>
    <details class="channel-add">
      <summary>Add channel</summary>
      <form action="/notes/channels" method="post" class="channel-form">
        <input name="name" maxlength="{MAX_CHANNEL_CHARS}" placeholder="Channel name" required>
        <button type="submit">Add</button>
      </form>
    </details>
  </aside>
  <section class="chat-pane">
    <header class="chat-head"><strong># {active_channel_label}</strong><span>{message_count} messages</span></header>
    <div class="message-list">{notes_html}</div>
    <form action="/notes" method="post" enctype="multipart/form-data" class="composer">
      <input name="channel_id" type="hidden" value="{active_channel_id}">
      <textarea name="body" maxlength="{MAX_NOTE_CHARS}" placeholder="Message #{active_channel_label}"></textarea>
      <label class="file-pill"><input name="image" type="file" accept="image/png,image/jpeg,image/gif,image/webp"><span>Image</span></label>
      <button type="submit">Send</button>
    </form>
  </section>
</main>
<script>
const messages = document.querySelector(".message-list");
if (messages) messages.scrollTop = messages.scrollHeight;
</script>
"#
        ),
    )
}

#[derive(Deserialize)]
struct ChannelForm {
    name: String,
}

async fn channel_create(
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
        channel_id = ensure_channel(&db, name).ok();
    }
    Redirect::to(&notes_location(channel_id)).into_response()
}

async fn channel_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let db = state.db.lock().unwrap();
    let channel_count: i64 = db
        .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
        .unwrap_or(0);
    if channel_count > 1 {
        let _ = db.execute("DELETE FROM channels WHERE id = ?1", params![id]);
    }
    Redirect::to(&notes_location(None)).into_response()
}

async fn note_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let mut channel_id = None;
    let mut body = String::new();
    let mut image_type = None;
    let mut image_data = None;

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
            "image" => {
                let content_type = field.content_type().map(str::to_string);
                if content_type.as_deref().is_some_and(allowed_image_type)
                    && let Ok(bytes) = field.bytes().await
                    && !bytes.is_empty()
                    && bytes.len() <= MAX_IMAGE_BYTES
                {
                    image_type = content_type;
                    image_data = Some(bytes.to_vec());
                }
            }
            _ => {}
        }
    }

    let body = body.trim();
    let channel_id = channel_id.unwrap_or(1);
    if (!body.is_empty() || image_data.is_some()) && body.len() <= MAX_NOTE_CHARS {
        let db = state.db.lock().unwrap();
        let exists = db
            .query_row(
                "SELECT 1 FROM channels WHERE id = ?1",
                params![channel_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap_or(None)
            .is_some();
        if exists {
            let _ = db.execute(
                "INSERT INTO notes (channel_id, body, image_type, image_data, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![channel_id, body, image_type, image_data, Utc::now().to_rfc3339()],
            );
        }
    }
    Redirect::to(&notes_location(Some(channel_id))).into_response()
}

async fn note_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let db = state.db.lock().unwrap();
    let channel_id = db
        .query_row(
            "SELECT channel_id FROM notes WHERE id = ?1",
            params![id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .unwrap_or(None);
    let _ = db.execute("DELETE FROM notes WHERE id = ?1", params![id]);
    Redirect::to(&notes_location(channel_id)).into_response()
}

async fn note_image(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let row = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT image_type, image_data FROM notes WHERE id = ?1 AND image_data IS NOT NULL",
            params![id],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .unwrap_or(None)
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

#[derive(Debug)]
struct ChannelRow {
    id: i64,
    name: String,
}

#[derive(Debug)]
struct NoteRow {
    id: i64,
    channel: String,
    body: String,
    has_image: bool,
}

fn list_channels(db: &Connection) -> rusqlite::Result<Vec<ChannelRow>> {
    let mut stmt = db.prepare("SELECT id, name FROM channels ORDER BY id ASC")?;
    stmt.query_map([], |row| {
        Ok(ChannelRow {
            id: row.get(0)?,
            name: row.get(1)?,
        })
    })?
    .collect()
}

fn list_notes(db: &Connection, channel: Option<i64>) -> rusqlite::Result<Vec<NoteRow>> {
    let sql = if channel.is_some() {
        "SELECT n.id, c.name, n.body, n.image_data IS NOT NULL FROM notes n JOIN channels c ON c.id = n.channel_id WHERE n.channel_id = ?1 ORDER BY n.id DESC LIMIT 200"
    } else {
        "SELECT n.id, c.name, n.body, n.image_data IS NOT NULL FROM notes n JOIN channels c ON c.id = n.channel_id ORDER BY n.id DESC LIMIT 200"
    };
    let mut stmt = db.prepare(sql)?;
    let rows = if let Some(channel) = channel {
        stmt.query_map(params![channel], note_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        stmt.query_map([], note_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(rows)
}

fn note_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NoteRow> {
    Ok(NoteRow {
        id: row.get(0)?,
        channel: row.get(1)?,
        body: row.get(2)?,
        has_image: row.get::<_, i64>(3)? != 0,
    })
}

fn notes_location(channel_id: Option<i64>) -> String {
    channel_id
        .filter(|id| *id > 0)
        .map(|id| format!("/notes?channel={id}"))
        .unwrap_or_else(|| "/notes".into())
}

fn allowed_image_type(value: &str) -> bool {
    matches!(
        value,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

fn page(title: &str, body: &str) -> Response {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<title>{}</title>
<style>
{PAGE_CSS}
</style>
</head>
<body>{}</body>
</html>"#,
        html_escape(title),
        body
    ))
    .into_response()
}

fn page_guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if authorized(&state.config, headers) {
        None
    } else {
        Some(Redirect::to("/login").into_response())
    }
}

fn raw_guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if authorized(&state.config, headers) {
        None
    } else {
        Some((StatusCode::UNAUTHORIZED, "authentication required").into_response())
    }
}

fn authorized(config: &Config, headers: &HeaderMap) -> bool {
    if config.auth_disabled {
        return true;
    }
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some(raw) = value.strip_prefix("Basic ")
        && let Ok(decoded) = BASE64.decode(raw.trim())
        && let Ok(pair) = String::from_utf8(decoded)
        && let Some((user, password)) = pair.split_once(':')
    {
        return user == config.user && verify_password(config, password);
    }
    let Some(cookie) = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    cookie
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .is_some_and(|(_, value)| verify_session_cookie(config, value))
}

fn verify_password(config: &Config, password: &str) -> bool {
    if config.auth_disabled {
        return true;
    }
    let Some(hash) = &config.password_hash else {
        return false;
    };
    if hash.starts_with("$argon2") {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }
    let Some((prefix, rest)) = hash.split_once(':') else {
        return false;
    };
    if prefix != "sha256" {
        return false;
    }
    let Some((salt_hex, expected_hex)) = rest.split_once(':') else {
        return false;
    };
    let Ok(salt) = hex::decode(salt_hex) else {
        return false;
    };
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let actual = password_digest(&salt, password);
    actual.as_slice().ct_eq(expected.as_slice()).into()
}

fn password_digest(salt: &[u8], password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}

fn make_session_cookie(config: &Config) -> String {
    let expires = (Utc::now() + Duration::days(SESSION_DAYS)).timestamp();
    let signature = session_signature(config, expires);
    format!(
        "{SESSION_COOKIE}={expires}:{signature}; Max-Age={}; Path=/; HttpOnly; SameSite=Lax",
        SESSION_DAYS * 24 * 60 * 60
    )
}

fn verify_session_cookie(config: &Config, value: &str) -> bool {
    let Some((raw_expires, signature)) = value.split_once(':') else {
        return false;
    };
    let Ok(expires) = raw_expires.parse::<i64>() else {
        return false;
    };
    if expires < Utc::now().timestamp() {
        return false;
    }
    let expected = session_signature(config, expires);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

fn session_signature(config: &Config, expires: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&config.cookie_secret);
    hasher.update(expires.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

fn audit_public_cmd(args: &[String]) -> io::Result<u8> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!(
            r#"Usage:
  motehold audit-public
  motehold audit-public --install-hook

Checks tracked files for local/private paths, common secret markers,
private-network IP leaks, and host-specific denylist terms.
"#
        );
        return Ok(0);
    }

    let root = git_root()?;
    if args.iter().any(|arg| arg == "--install-hook") {
        install_audit_hooks(&root)?;
        println!("installed .git/hooks/pre-commit and .git/hooks/pre-push");
    }

    let findings = audit_public(&root)?;
    if findings.is_empty() {
        println!("audit-public: ok");
        return Ok(0);
    }

    eprintln!("audit-public: found {} issue(s)", findings.len());
    for finding in &findings {
        match finding.line {
            Some(line) => eprintln!("{}:{}: {}", finding.path, line, finding.message),
            None => eprintln!("{}: {}", finding.path, finding.message),
        }
    }
    Ok(1)
}

fn git_root() -> io::Result<PathBuf> {
    let output = StdCommand::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("not inside a Git repository"));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn install_audit_hooks(root: &Path) -> io::Result<()> {
    let hooks = root.join(".git/hooks");
    fs::create_dir_all(&hooks)?;
    for name in ["pre-commit", "pre-push"] {
        let hook = hooks.join(name);
        fs::write(
            &hook,
            r#"#!/bin/sh
set -eu
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
cargo run --quiet -- audit-public
"#,
        )?;
        let mut permissions = fs::metadata(&hook)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook, permissions)?;
    }
    Ok(())
}

fn audit_public(root: &Path) -> io::Result<Vec<AuditFinding>> {
    let files = git_tracked_files(root)?;
    let private_terms = load_audit_denylist(root);
    let mut findings = Vec::new();

    for path in files {
        if let Some(message) = audit_path(&path) {
            findings.push(AuditFinding {
                path,
                line: None,
                message,
            });
            continue;
        }

        let full_path = root.join(&path);
        if fs::metadata(&full_path)
            .map(|metadata| metadata.len() > 1_000_000)
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(&full_path) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            for message in audit_line(line, &private_terms) {
                findings.push(AuditFinding {
                    path: path.clone(),
                    line: Some(index + 1),
                    message,
                });
            }
        }
    }

    Ok(findings)
}

fn git_tracked_files(root: &Path) -> io::Result<Vec<String>> {
    let output = StdCommand::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect())
}

fn audit_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    let denied_exact = [
        "AGENTS.md",
        "motehold.local.toml",
        ".env",
        ".env.local",
        "id_rsa",
        "id_ed25519",
    ];
    if denied_exact.contains(&normalized.as_str()) || denied_exact.contains(&name) {
        return Some("private file path is tracked".into());
    }
    if name.starts_with(".env.") && name != ".env.example" {
        return Some("private env file is tracked".into());
    }
    if normalized.starts_with("docs/private/")
        || normalized.starts_with(".motehold/")
        || normalized.starts_with("backups/")
        || normalized.starts_with("data/")
        || normalized.starts_with("downloads/")
    {
        return Some("ignored private/runtime path is tracked".into());
    }
    if normalized.contains("/data/")
        || normalized.contains("/cache/")
        || normalized.contains("/config/")
        || normalized.contains("/downloads/")
        || normalized.contains("/secrets/")
    {
        return Some("runtime or secret data path is tracked".into());
    }
    if matches!(
        Path::new(name).extension().and_then(|ext| ext.to_str()),
        Some("db" | "sqlite" | "sqlite3" | "log" | "pid" | "pem" | "key" | "p12" | "pfx")
    ) {
        return Some("private state or key-like file is tracked".into());
    }
    None
}

fn load_audit_denylist(root: &Path) -> Vec<String> {
    let mut paths = vec![
        root.join("docs/private/audit-denylist.txt"),
        root.join(".motehold/audit-denylist.txt"),
    ];
    if let Ok(path) = env::var("MOTEHOLD_AUDIT_DENYLIST") {
        paths.push(PathBuf::from(path));
    }

    let mut terms = Vec::new();
    for path in paths {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let term = line.trim();
            if term.is_empty() || term.starts_with('#') {
                continue;
            }
            terms.push(term.to_ascii_lowercase());
        }
    }
    terms
}

fn audit_line(line: &str, private_terms: &[String]) -> Vec<String> {
    let mut findings = Vec::new();
    let lower = line.to_ascii_lowercase();
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return findings;
    }

    if line.contains("-----BEGIN ") && line.contains(&["PRIVATE", " KEY"].concat()) {
        findings.push("private key material".into());
    }
    for marker in token_markers() {
        if line.contains(&marker) {
            findings.push(format!("token marker `{marker}`"));
        }
    }
    if contains_tailscale_ipv4(line) {
        findings.push("Tailscale/CGNAT private IP address".into());
    }
    if suspicious_secret_assignment(line) {
        findings.push("non-placeholder secret-looking assignment".into());
    }
    for term in private_terms {
        if !term.is_empty() && lower.contains(term) {
            findings.push("local denylist term".into());
        }
    }

    findings
}

fn token_markers() -> Vec<String> {
    vec![
        ["github", "_pat_"].concat(),
        ["gh", "p_"].concat(),
        ["gh", "o_"].concat(),
        ["gh", "s_"].concat(),
        ["gh", "u_"].concat(),
        ["s", "k-"].concat(),
        ["xo", "xb-"].concat(),
        ["xo", "xp-"].concat(),
    ]
}

fn suspicious_secret_assignment(line: &str) -> bool {
    if line.contains("::") {
        return false;
    }
    let Some((key, value)) = line.split_once('=').or_else(|| line.split_once(':')) else {
        return false;
    };
    let key = key.trim().to_ascii_lowercase();
    if key.is_empty()
        || key.len() > 80
        || !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return false;
    }
    let secret_keys = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "client_secret",
        "private_key",
    ];
    if !secret_keys.iter().any(|needle| key.contains(needle)) {
        return false;
    }

    let value = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches(',')
        .trim();
    let allowed = [
        "",
        "example",
        "placeholder",
        "changeme",
        "change-me",
        "redacted",
        "dummy",
        "none",
        "null",
        "false",
        "true",
    ];
    if allowed.contains(&value.to_ascii_lowercase().as_str()) {
        return false;
    }
    if value == "String" || value.starts_with("Option<") || value.starts_with("Vec<") {
        return false;
    }
    if value.starts_with("${")
        || value.starts_with('<')
        || value.starts_with("your-")
        || value.contains("...")
        || value.starts_with("Some(")
        || value.starts_with("vec!")
    {
        return false;
    }
    true
}

fn contains_tailscale_ipv4(line: &str) -> bool {
    line.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .filter(|token| token.matches('.').count() == 3)
        .any(|token| {
            let octets: Vec<u16> = token
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            octets.len() == 4
                && octets[0] == 100
                && (64..=127).contains(&octets[1])
                && octets.iter().all(|octet| *octet <= 255)
        })
}

fn hash_password_cmd(args: &[String]) -> io::Result<()> {
    if !args.iter().any(|arg| arg == "--stdin") {
        eprintln!("usage: motehold hash-password --stdin");
        return Ok(());
    }
    let mut password = String::new();
    io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']);
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).map_err(io_other)?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(io_other)?;
    println!("{hash}");
    Ok(())
}

fn random_secret() -> Vec<u8> {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret.to_vec()
}

fn env_flag(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn io_other(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trips() {
        let salt = b"0123456789abcdef";
        let digest = password_digest(salt, "secret");
        let hash = format!("sha256:{}:{}", hex::encode(salt), hex::encode(digest));
        let config = Config {
            bind: "127.0.0.1:0".into(),
            db_path: PathBuf::new(),
            user: "motehold".into(),
            password_hash: Some(hash),
            cookie_secret: vec![1; 32],
            auth_disabled: false,
        };
        assert!(verify_password(&config, "secret"));
        assert!(!verify_password(&config, "wrong"));
    }

    #[test]
    fn audit_secret_assignment_allows_placeholders() {
        assert!(!suspicious_secret_assignment(&format!("{}=", "TOKEN")));
        assert!(!suspicious_secret_assignment(&format!(
            "{}=<value>",
            "TOKEN"
        )));
        assert!(!suspicious_secret_assignment(&format!(
            "{}=${{VALUE}}",
            "TOKEN"
        )));
        assert!(suspicious_secret_assignment(&format!(
            "{}={}",
            "TOKEN", "abc123"
        )));
    }

    #[test]
    fn audit_detects_cgnat_private_address() {
        let line = format!("bind = 100.{}.0.1", 64);
        assert!(contains_tailscale_ipv4(&line));
        assert!(!contains_tailscale_ipv4("bind = 127.0.0.1"));
    }

    #[test]
    fn audit_rejects_private_paths() {
        assert!(audit_path(".env").is_some());
        assert!(audit_path("data/motehold.sqlite").is_some());
        assert!(audit_path("src/main.rs").is_none());
    }
}
