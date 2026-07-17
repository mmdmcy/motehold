use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    extract::{Form, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{env, io, sync::Arc};
use subtle::ConstantTimeEq;

use crate::{
    app::AppState,
    interfaces::http::presentation::{auth_error_body, login_body, page},
};

use super::oidc::OidcConfig;

const SESSION_COOKIE: &str = "motehold_session";
const LOCAL_SESSION_DAYS: i64 = 30;
const OIDC_SESSION_HOURS: i64 = 12;
#[derive(Clone)]
pub(crate) struct AuthConfig {
    user: String,
    password_hash: Option<String>,
    cookie_secret: Vec<u8>,
    pub(crate) auth_disabled: bool,
    pub(crate) oidc: Option<OidcConfig>,
    cookie_secure: bool,
}

impl AuthConfig {
    pub(crate) fn from_env() -> io::Result<Self> {
        let password_hash = env::var("MOTEHOLD_PASSWORD_HASH")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let auth_disabled = env_flag("MOTEHOLD_AUTH_DISABLED", true);
        let oidc = OidcConfig::from_env()?;
        validate_auth_policy(password_hash.as_deref(), auth_disabled, oidc.as_ref())?;

        let cookie_secure = oidc.as_ref().is_some_and(OidcConfig::uses_secure_cookie)
            || env_flag("MOTEHOLD_COOKIE_SECURE", false);
        let cookie_secret = env::var("MOTEHOLD_COOKIE_SECRET")
            .ok()
            .and_then(|value| hex::decode(value.trim()).ok())
            .filter(|bytes| bytes.len() >= 32)
            .unwrap_or_else(random_secret);

        Ok(Self {
            user: env::var("MOTEHOLD_USER").unwrap_or_else(|_| "motehold".into()),
            password_hash,
            cookie_secret,
            auth_disabled,
            oidc,
            cookie_secure,
        })
    }

    pub(crate) fn identity_mode(&self) -> &'static str {
        if self.auth_disabled {
            "disabled"
        } else if self.oidc.is_some() {
            "oidc+local"
        } else {
            "local"
        }
    }

    pub(crate) fn secure_cookie_suffix(&self) -> &'static str {
        if self.cookie_secure { "; Secure" } else { "" }
    }
}

fn validate_auth_policy(
    password_hash: Option<&str>,
    auth_disabled: bool,
    oidc: Option<&OidcConfig>,
) -> io::Result<()> {
    if oidc.is_some() && (auth_disabled || password_hash.is_none()) {
        return Err(invalid_input(
            "managed OIDC requires MOTEHOLD_AUTH_DISABLED=0 and MOTEHOLD_PASSWORD_HASH for local break-glass login",
        ));
    }
    if password_hash.is_none() && !auth_disabled {
        return Err(invalid_input(
            "MOTEHOLD_PASSWORD_HASH is required unless MOTEHOLD_AUTH_DISABLED=1",
        ));
    }
    Ok(())
}

pub(crate) async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if authorized(&state, &headers) {
        return Redirect::to("/").into_response();
    }
    page(
        "Motehold Login",
        &login_body(state.config.auth.oidc.is_some(), None),
    )
}

#[derive(Deserialize)]
pub(crate) struct LoginForm {
    password: String,
}

pub(crate) async fn login_post(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    if !verify_password(&state.config.auth, &form.password) {
        return page(
            "Motehold Login",
            &login_body(state.config.auth.oidc.is_some(), Some("Wrong password.")),
        );
    }
    let cookie = {
        let db = state.db.lock().unwrap();
        create_session_cookie(&db, &state.config.auth, "local", Utc::now().timestamp())
    };
    match cookie {
        Ok(cookie) => redirect_with_cookie("/", &cookie),
        Err(_) => auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create a session.",
        ),
    }
}

pub(crate) async fn logout_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = session_cookie_value(&headers) {
        let hash = session_token_hash(&state.config.auth, token);
        let db = state.db.lock().unwrap();
        let _ = db.execute("DELETE FROM auth_sessions WHERE token_hash = ?1", [hash]);
    }
    redirect_with_cookie("/login", &expired_cookie(&state.config.auth))
}

pub(crate) fn page_guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if authorized(state, headers) {
        None
    } else {
        Some(Redirect::to("/login").into_response())
    }
}

pub(crate) fn raw_guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if authorized(state, headers) {
        None
    } else {
        Some((StatusCode::UNAUTHORIZED, "authentication required").into_response())
    }
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let config = &state.config.auth;
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
    let Some(token) = session_cookie_value(headers) else {
        return false;
    };
    let db = state.db.lock().unwrap();
    verify_session(&db, config, token, Utc::now().timestamp()).unwrap_or(false)
}

fn verify_password(config: &AuthConfig, password: &str) -> bool {
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
    let (Ok(salt), Ok(expected)) = (hex::decode(salt_hex), hex::decode(expected_hex)) else {
        return false;
    };
    let actual = password_digest(&salt, password);
    actual.as_slice().ct_eq(expected.as_slice()).into()
}

pub(crate) fn create_session_cookie(
    db: &Connection,
    config: &AuthConfig,
    method: &str,
    now: i64,
) -> rusqlite::Result<String> {
    let token = random_token();
    let hours = if method == "oidc" {
        OIDC_SESSION_HOURS
    } else {
        LOCAL_SESSION_DAYS * 24
    };
    let expires_at = now + Duration::hours(hours).num_seconds();
    db.execute("DELETE FROM auth_sessions WHERE expires_at <= ?1", [now])?;
    db.execute(
        "INSERT INTO auth_sessions (token_hash, auth_method, expires_at) VALUES (?1, ?2, ?3)",
        params![session_token_hash(config, &token), method, expires_at],
    )?;
    Ok(format!(
        "{SESSION_COOKIE}={token}; Max-Age={}; Path=/; HttpOnly; SameSite=Lax{}",
        hours * 60 * 60,
        secure_suffix(config)
    ))
}

fn verify_session(
    db: &Connection,
    config: &AuthConfig,
    token: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    db.execute("DELETE FROM auth_sessions WHERE expires_at <= ?1", [now])?;
    let expires_at = db
        .query_row(
            "SELECT expires_at FROM auth_sessions WHERE token_hash = ?1",
            [session_token_hash(config, token)],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    Ok(expires_at.is_some_and(|expires_at| expires_at > now))
}

fn session_cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value)
}

fn session_token_hash(config: &AuthConfig, token: &str) -> String {
    keyed_hash(&config.cookie_secret, b"session", token)
}

pub(crate) fn pending_state_hash(config: &AuthConfig, state: &str) -> String {
    keyed_hash(&config.cookie_secret, b"oidc-state", state)
}

pub(crate) fn flow_token_hash(config: &AuthConfig, token: &str) -> String {
    keyed_hash(&config.cookie_secret, b"oidc-flow", token)
}

fn keyed_hash(secret: &[u8], purpose: &[u8], value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(purpose);
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn redirect_with_cookie(location: &str, cookie: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_str(location).unwrap()),
            (header::SET_COOKIE, HeaderValue::from_str(cookie).unwrap()),
        ],
    )
        .into_response()
}

fn expired_cookie(config: &AuthConfig) -> String {
    format!(
        "{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax{}",
        secure_suffix(config)
    )
}

fn secure_suffix(config: &AuthConfig) -> &'static str {
    config.secure_cookie_suffix()
}

pub(crate) fn auth_error(status: StatusCode, message: &str) -> Response {
    let mut response = page("Motehold Login", &auth_error_body(message));
    *response.status_mut() = status;
    response
}

pub(crate) fn hash_password_cmd(args: &[String]) -> io::Result<()> {
    use std::io::Read;

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

fn password_digest(salt: &[u8], password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}

fn random_secret() -> Vec<u8> {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret.to_vec()
}

pub(crate) fn random_token() -> String {
    let mut token = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
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

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
pub(crate) fn test_auth_config(oidc_enabled: bool) -> AuthConfig {
    AuthConfig {
        user: "motehold".into(),
        password_hash: Some(format!(
            "sha256:{}:{}",
            hex::encode(b"0123456789abcdef"),
            hex::encode(password_digest(b"0123456789abcdef", "secret"))
        )),
        cookie_secret: vec![7; 32],
        auth_disabled: false,
        oidc: oidc_enabled.then(OidcConfig::test_config),
        cookie_secure: oidc_enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::migrations;

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        migrations::migrate(&db).unwrap();
        db
    }

    #[test]
    fn managed_oidc_requires_local_break_glass() {
        let oidc = test_auth_config(true).oidc.unwrap();
        assert!(validate_auth_policy(None, false, Some(&oidc)).is_err());
        assert!(validate_auth_policy(Some("hash"), true, Some(&oidc)).is_err());
        assert!(validate_auth_policy(Some("hash"), false, Some(&oidc)).is_ok());
        assert!(verify_password(&test_auth_config(true), "secret"));
    }

    #[test]
    fn opaque_sessions_are_hashed_and_expire() {
        let db = database();
        let config = test_auth_config(false);
        let cookie = create_session_cookie(&db, &config, "local", 100).unwrap();
        let token = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
        assert!(verify_session(&db, &config, token, 101).unwrap());
        let stored: String = db
            .query_row("SELECT token_hash FROM auth_sessions", [], |row| row.get(0))
            .unwrap();
        assert_ne!(stored, token);
        assert!(
            !verify_session(
                &db,
                &config,
                token,
                100 + Duration::days(LOCAL_SESSION_DAYS + 1).num_seconds()
            )
            .unwrap()
        );
    }

    #[test]
    fn password_hash_round_trips() {
        let config = test_auth_config(false);
        assert!(verify_password(&config, "secret"));
        assert!(!verify_password(&config, "wrong"));
    }

    #[test]
    fn identity_mode_matches_effective_auth_configuration() {
        assert_eq!(test_auth_config(false).identity_mode(), "local");
        assert_eq!(test_auth_config(true).identity_mode(), "oidc+local");
        let mut disabled = test_auth_config(false);
        disabled.auth_disabled = true;
        assert_eq!(disabled.identity_mode(), "disabled");
    }
}
