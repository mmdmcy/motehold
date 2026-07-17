use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use openidconnect::{
    AsyncHttpClient, AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreClientAuthMethod, CoreProviderMetadata},
    reqwest,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use std::{env, io, net::IpAddr, sync::Arc, time::Duration as StdDuration};
use url::Url;

use crate::{
    app::AppState,
    security::auth::{
        AuthConfig, auth_error, create_session_cookie, flow_token_hash, pending_state_hash,
        random_token,
    },
};

const PENDING_FLOW_MINUTES: i64 = 10;
const FLOW_COOKIE: &str = "motehold_oidc_flow";

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone)]
pub(crate) struct OidcConfig {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
}

impl OidcConfig {
    pub(crate) fn from_env() -> io::Result<Option<Self>> {
        Self::from_values(
            env_value("MOTEHOLD_OIDC_ISSUER"),
            env_value("MOTEHOLD_OIDC_CLIENT_ID"),
            env_value("MOTEHOLD_OIDC_CLIENT_SECRET"),
            env_value("MOTEHOLD_OIDC_REDIRECT_URL"),
        )
    }

    fn from_values(
        issuer: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        redirect_url: Option<String>,
    ) -> io::Result<Option<Self>> {
        let configured = [
            issuer.is_some(),
            client_id.is_some(),
            client_secret.is_some(),
            redirect_url.is_some(),
        ];
        if configured.iter().all(|value| !value) {
            return Ok(None);
        }
        if !configured.iter().all(|value| *value) {
            return Err(invalid_input(
                "MOTEHOLD_OIDC_ISSUER, MOTEHOLD_OIDC_CLIENT_ID, MOTEHOLD_OIDC_CLIENT_SECRET, and MOTEHOLD_OIDC_REDIRECT_URL must be set together",
            ));
        }

        let issuer = issuer.unwrap();
        let redirect_url = redirect_url.unwrap();
        validate_oidc_url("MOTEHOLD_OIDC_ISSUER", &issuer, false)?;
        validate_oidc_url("MOTEHOLD_OIDC_REDIRECT_URL", &redirect_url, true)?;
        Ok(Some(Self {
            issuer,
            client_id: client_id.unwrap(),
            client_secret: client_secret.unwrap(),
            redirect_url,
        }))
    }

    pub(crate) fn uses_secure_cookie(&self) -> bool {
        Url::parse(&self.redirect_url).is_ok_and(|url| url.scheme() == "https")
    }

    #[cfg(test)]
    pub(crate) fn test_config() -> Self {
        Self {
            issuer: "https://identity.example.test".into(),
            client_id: "motehold".into(),
            client_secret: String::from("placeholder"),
            redirect_url: "https://motehold.example.test/auth/oidc/callback".into(),
        }
    }
}

fn validate_oidc_url(name: &str, raw: &str, callback: bool) -> io::Result<()> {
    let url =
        Url::parse(raw).map_err(|_| invalid_input(format!("{name} must be an absolute URL")))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid_input(format!(
            "{name} contains forbidden URL parts"
        )));
    }
    if !secure_or_loopback(&url) {
        return Err(invalid_input(format!(
            "{name} must use HTTPS; HTTP is allowed only for loopback dogfood URLs"
        )));
    }
    if url.query().is_some() {
        return Err(invalid_input(format!("{name} must not contain a query")));
    }
    if callback && url.path() != "/auth/oidc/callback" {
        return Err(invalid_input(format!(
            "{name} must use the exact /auth/oidc/callback path"
        )));
    }
    Ok(())
}

fn secure_or_loopback(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    if url.scheme() != "http" {
        return false;
    }
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .map(|address| address.is_loopback())
                .unwrap_or(false)
    })
}

pub(crate) async fn oidc_start(State(state): State<Arc<AppState>>) -> Response {
    let Some(config) = state.config.auth.oidc.as_ref() else {
        return Redirect::to("/login").into_response();
    };
    let Ok((client, _http_client)) = discover_client(config).await else {
        return auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Organization login is temporarily unavailable. Local break-glass login remains available.",
        );
    };

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, state_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(challenge)
        .url();
    let flow_token = random_token();
    let stored = {
        let db = state.db.lock().unwrap();
        store_pending_flow(
            &db,
            &state.config.auth,
            state_token.secret(),
            &flow_token,
            nonce.secret(),
            verifier.secret(),
            Utc::now().timestamp(),
        )
    };
    if stored.is_err() {
        return auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Organization login could not be started.",
        );
    }
    redirect_with_flow_cookie(authorize_url.as_str(), &flow_token, &state.config.auth)
}

#[derive(Deserialize)]
pub(crate) struct OidcCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub(crate) async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OidcCallback>,
    headers: HeaderMap,
) -> Response {
    let failed = |status, message| finish_callback(&state.config.auth, auth_error(status, message));
    if query.error.is_some() {
        return failed(
            StatusCode::UNAUTHORIZED,
            "Organization login was not completed.",
        );
    }
    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return failed(
            StatusCode::BAD_REQUEST,
            "Invalid organization login response.",
        );
    };
    let Some(flow_token) = flow_cookie_value(&headers) else {
        return failed(
            StatusCode::BAD_REQUEST,
            "Organization login failed browser-flow verification.",
        );
    };
    let pending = {
        let db = state.db.lock().unwrap();
        take_pending_flow(
            &db,
            &state.config.auth,
            &returned_state,
            flow_token,
            Utc::now().timestamp(),
        )
    };
    let Ok(Some(pending)) = pending else {
        return failed(
            StatusCode::BAD_REQUEST,
            "Organization login expired or failed state verification.",
        );
    };
    let Some(config) = state.config.auth.oidc.as_ref() else {
        return failed(
            StatusCode::BAD_REQUEST,
            "Organization login is not configured.",
        );
    };
    let Ok((client, http_client)) = discover_client(config).await else {
        return failed(
            StatusCode::SERVICE_UNAVAILABLE,
            "Organization login is temporarily unavailable. Local break-glass login remains available.",
        );
    };
    let request = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(request) => request.set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier)),
        Err(_) => return failed(StatusCode::BAD_GATEWAY, "Organization login failed."),
    };
    let Ok(tokens) = request.request_async(&http_client).await else {
        return failed(StatusCode::BAD_GATEWAY, "Organization login failed.");
    };
    let Some(id_token) = tokens.id_token() else {
        return failed(
            StatusCode::BAD_GATEWAY,
            "Organization login returned no identity.",
        );
    };
    if id_token
        .claims(&client.id_token_verifier(), &Nonce::new(pending.nonce))
        .is_err()
    {
        return failed(
            StatusCode::UNAUTHORIZED,
            "Organization identity verification failed.",
        );
    }

    // Provider tokens are dropped here. Only an opaque app-owned session is persisted.
    let cookie = {
        let db = state.db.lock().unwrap();
        create_session_cookie(&db, &state.config.auth, "oidc", Utc::now().timestamp())
    };
    let response = match cookie {
        Ok(cookie) => crate::security::auth::redirect_with_cookie("/", &cookie),
        Err(_) => auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create a session.",
        ),
    };
    finish_callback(&state.config.auth, response)
}

async fn discover_client(config: &OidcConfig) -> Result<(OidcClient, reqwest::Client), String> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(StdDuration::from_secs(5))
        .timeout(StdDuration::from_secs(10))
        .build()
        .map_err(|error| error.to_string())?;
    let safe_discovery_client = |request: HttpRequest| {
        let http_client = http_client.clone();
        async move {
            let raw_url = request.uri().to_string();
            let url = Url::parse(&raw_url)
                .map_err(|_| io::Error::other("OIDC request URL is invalid"))?;
            validate_service_endpoint("OIDC discovery request", &url).map_err(io::Error::other)?;
            http_client
                .call(request)
                .await
                .map_err(|error| io::Error::other(error.to_string()))
        }
    };
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.issuer.clone()).map_err(|error| error.to_string())?,
        &safe_discovery_client,
    )
    .await
    .map_err(|error| error.to_string())?;
    validate_discovered_endpoints(&metadata)?;
    let auth_type = select_token_auth_method(
        metadata
            .token_endpoint_auth_methods_supported()
            .map(Vec::as_slice),
    )?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_auth_type(auth_type)
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_url.clone()).map_err(|error| error.to_string())?,
    );
    Ok((client, http_client))
}

fn select_token_auth_method(
    advertised: Option<&[CoreClientAuthMethod]>,
) -> Result<AuthType, String> {
    let Some(advertised) = advertised else {
        return Ok(AuthType::BasicAuth);
    };
    if advertised.contains(&CoreClientAuthMethod::ClientSecretPost) {
        return Ok(AuthType::RequestBody);
    }
    if advertised.contains(&CoreClientAuthMethod::ClientSecretBasic) {
        return Ok(AuthType::BasicAuth);
    }
    Err("OIDC provider supports neither client_secret_post nor client_secret_basic".into())
}

fn validate_discovered_endpoints(metadata: &CoreProviderMetadata) -> Result<(), String> {
    validate_service_endpoint(
        "OIDC authorization endpoint",
        metadata.authorization_endpoint().url(),
    )?;
    let token_endpoint = metadata
        .token_endpoint()
        .ok_or_else(|| "OIDC provider has no token endpoint".to_string())?;
    validate_service_endpoint("OIDC token endpoint", token_endpoint.url())?;
    if let Some(userinfo_endpoint) = metadata.userinfo_endpoint() {
        validate_service_endpoint("OIDC userinfo endpoint", userinfo_endpoint.url())?;
    }
    validate_service_endpoint("OIDC JWKS endpoint", metadata.jwks_uri().url())
}

fn validate_service_endpoint(name: &str, url: &Url) -> Result<(), String> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(format!("{name} contains forbidden URL parts"));
    }
    if !secure_or_loopback(url) {
        return Err(format!(
            "{name} must use HTTPS; HTTP is allowed only for loopback dogfood URLs"
        ));
    }
    Ok(())
}

fn store_pending_flow(
    db: &Connection,
    config: &AuthConfig,
    state: &str,
    flow_token: &str,
    nonce: &str,
    pkce_verifier: &str,
    now: i64,
) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM oidc_pending_flows WHERE expires_at <= ?1",
        [now],
    )?;
    db.execute(
        "INSERT INTO oidc_pending_flows (state_hash, flow_hash, nonce, pkce_verifier, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            pending_state_hash(config, state),
            flow_token_hash(config, flow_token),
            nonce,
            pkce_verifier,
            now + Duration::minutes(PENDING_FLOW_MINUTES).num_seconds()
        ],
    )?;
    Ok(())
}

struct PendingFlow {
    nonce: String,
    pkce_verifier: String,
}

fn take_pending_flow(
    db: &Connection,
    config: &AuthConfig,
    state: &str,
    flow_token: &str,
    now: i64,
) -> rusqlite::Result<Option<PendingFlow>> {
    let hash = pending_state_hash(config, state);
    let pending = db
        .query_row(
            "SELECT nonce, pkce_verifier, expires_at FROM oidc_pending_flows WHERE state_hash = ?1 AND flow_hash = ?2",
            params![&hash, flow_token_hash(config, flow_token)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    db.execute(
        "DELETE FROM oidc_pending_flows WHERE state_hash = ?1",
        [&hash],
    )?;
    Ok(pending.and_then(|(nonce, pkce_verifier, expires_at)| {
        (expires_at > now).then_some(PendingFlow {
            nonce,
            pkce_verifier,
        })
    }))
}

fn redirect_with_flow_cookie(location: &str, token: &str, config: &AuthConfig) -> Response {
    let Ok(location) = HeaderValue::from_str(location) else {
        return auth_error(StatusCode::BAD_GATEWAY, "Organization login failed.");
    };
    let cookie = format!(
        "{FLOW_COOKIE}={token}; Max-Age={}; Path=/auth/oidc/callback; HttpOnly; SameSite=Lax{}",
        Duration::minutes(PENDING_FLOW_MINUTES).num_seconds(),
        config.secure_cookie_suffix()
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location),
            (header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap()),
        ],
    )
        .into_response()
}

fn finish_callback(config: &AuthConfig, mut response: Response) -> Response {
    let expired = format!(
        "{FLOW_COOKIE}=; Max-Age=0; Path=/auth/oidc/callback; HttpOnly; SameSite=Lax{}",
        config.secure_cookie_suffix()
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&expired).expect("static cookie attributes are valid"),
    );
    response
}

fn flow_cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == FLOW_COOKIE)
        .map(|(_, value)| value)
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{persistence::migrations, security::auth::test_auth_config};
    use openidconnect::{TokenUrl, core::CoreJsonWebKeySet};
    use std::collections::HashMap;

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        migrations::migrate(&db).unwrap();
        db
    }

    #[test]
    fn configuration_is_all_or_none() {
        assert!(
            OidcConfig::from_values(None, None, None, None)
                .unwrap()
                .is_none()
        );
        assert!(
            OidcConfig::from_values(
                Some("https://identity.example.test".into()),
                Some("client".into()),
                None,
                Some("https://app.example.test/auth/oidc/callback".into())
            )
            .is_err()
        );
    }

    #[test]
    fn urls_require_https_or_loopback_http() {
        assert!(validate_oidc_url("issuer", "https://identity.example.test", false).is_ok());
        assert!(validate_oidc_url("issuer", "http://127.0.0.1:8080", false).is_ok());
        assert!(validate_oidc_url("issuer", "http://identity.example.test", false).is_err());
        assert!(
            validate_oidc_url("redirect", "http://localhost:8787/auth/oidc/callback", true).is_ok()
        );
        assert!(validate_oidc_url("redirect", "javascript:alert(1)", true).is_err());
    }

    #[test]
    fn uppercase_https_redirect_still_uses_a_secure_cookie() {
        let config = OidcConfig::from_values(
            Some("https://identity.example.test".into()),
            Some("client".into()),
            Some("secret".into()),
            Some("HTTPS://app.example.test/auth/oidc/callback".into()),
        )
        .unwrap()
        .unwrap();

        assert!(config.uses_secure_cookie());
    }

    #[test]
    fn token_auth_method_follows_provider_metadata() {
        assert!(matches!(
            select_token_auth_method(Some(&[
                CoreClientAuthMethod::ClientSecretBasic,
                CoreClientAuthMethod::ClientSecretPost,
            ])),
            Ok(AuthType::RequestBody)
        ));
        assert!(matches!(
            select_token_auth_method(Some(&[CoreClientAuthMethod::ClientSecretBasic])),
            Ok(AuthType::BasicAuth)
        ));
        assert!(matches!(
            select_token_auth_method(None),
            Ok(AuthType::BasicAuth)
        ));
        assert!(select_token_auth_method(Some(&[CoreClientAuthMethod::PrivateKeyJwt])).is_err());
    }

    #[test]
    fn discovered_endpoints_require_https_or_loopback_http() {
        assert!(
            validate_service_endpoint(
                "authorization endpoint",
                &Url::parse("https://identity.example.test/authorize").unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_service_endpoint(
                "token endpoint",
                &Url::parse("http://127.0.0.1:8080/token").unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_service_endpoint(
                "JWKS endpoint",
                &Url::parse("http://identity.example.test/jwks.json").unwrap()
            )
            .is_err()
        );
        assert!(
            validate_service_endpoint(
                "userinfo endpoint",
                &Url::parse("https://user:password@identity.example.test/userinfo").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn pending_state_nonce_and_browser_binding_are_one_time_and_expire() {
        let db = database();
        let config = test_auth_config(true);
        store_pending_flow(&db, &config, "state", "browser-a", "nonce", "verifier", 100).unwrap();
        assert!(
            take_pending_flow(&db, &config, "state", "browser-b", 101)
                .unwrap()
                .is_none()
        );

        store_pending_flow(
            &db,
            &config,
            "state-2",
            "browser-a",
            "nonce",
            "verifier",
            100,
        )
        .unwrap();
        let pending = take_pending_flow(&db, &config, "state-2", "browser-a", 101)
            .unwrap()
            .unwrap();
        assert_eq!(pending.nonce, "nonce");
        assert_eq!(pending.pkce_verifier, "verifier");
        assert!(
            take_pending_flow(&db, &config, "state-2", "browser-a", 102)
                .unwrap()
                .is_none()
        );

        store_pending_flow(&db, &config, "old", "browser", "nonce", "verifier", 100).unwrap();
        assert!(
            take_pending_flow(
                &db,
                &config,
                "old",
                "browser",
                100 + Duration::minutes(PENDING_FLOW_MINUTES + 1).num_seconds()
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn client_secret_post_puts_credentials_in_the_token_request_body() {
        let client = CoreClient::new(
            ClientId::new("pilot-client".into()),
            IssuerUrl::new("https://identity.example.test".into()).unwrap(),
            CoreJsonWebKeySet::new(Vec::new()),
        )
        .set_client_secret(ClientSecret::new("pilot-secret".into()))
        .set_auth_type(AuthType::RequestBody)
        .set_token_uri(TokenUrl::new("https://identity.example.test/token".into()).unwrap())
        .set_redirect_uri(
            RedirectUrl::new("https://motehold.example.test/auth/oidc/callback".into()).unwrap(),
        );

        assert!(matches!(client.auth_type(), AuthType::RequestBody));
        let _tokens = client
            .exchange_code(AuthorizationCode::new("authorization-code".into()))
            .request(&|request: openidconnect::HttpRequest| {
                assert!(
                    request
                        .headers()
                        .get(openidconnect::http::header::AUTHORIZATION)
                        .is_none()
                );
                let fields = url::form_urlencoded::parse(request.body())
                    .into_owned()
                    .collect::<HashMap<_, _>>();
                assert_eq!(
                    fields.get("client_id").map(String::as_str),
                    Some("pilot-client")
                );
                assert_eq!(
                    fields.get("client_secret").map(String::as_str),
                    Some("pilot-secret")
                );
                Ok::<_, io::Error>(
                    openidconnect::http::Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            openidconnect::http::header::CONTENT_TYPE,
                            "application/json",
                        )
                        .body(br#"{"access_token":"access-token","token_type":"Bearer"}"#.to_vec())
                        .unwrap(),
                )
            })
            .unwrap();
    }
}
