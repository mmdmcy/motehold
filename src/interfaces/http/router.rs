use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use std::sync::Arc;

use super::{component_status, notes};
use crate::{
    app::AppState,
    features::notes::{MAX_ATTACHMENT_BYTES, MAX_IMAGE_BYTES, MAX_NOTE_CHARS},
    security::{auth, oidc},
};

pub(crate) fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(notes::notes_page))
        .route("/login", get(auth::login_page).post(auth::login_post))
        .route("/logout", post(auth::logout_post))
        .route("/auth/oidc/start", get(oidc::oidc_start))
        .route("/auth/oidc/callback", get(oidc::oidc_callback))
        .route(
            "/.well-known/linuxmice/component",
            get(component_status::component_status),
        )
        .route("/notes", get(notes::notes_page).post(notes::note_create))
        .route("/notes/channels", post(notes::channel_create))
        .route("/notes/channels/{id}/delete", post(notes::channel_delete))
        .route("/notes/{id}/delete", post(notes::note_delete))
        .route("/notes/images/{id}", get(notes::note_image))
        .route("/notes/attachments/{id}", get(notes::note_attachment))
        .layer(DefaultBodyLimit::max(
            MAX_IMAGE_BYTES + MAX_NOTE_CHARS + MAX_ATTACHMENT_BYTES + 1024 * 1024,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use rusqlite::Connection;
    use std::{path::PathBuf, sync::Mutex};
    use tower::ServiceExt;

    fn oidc_state() -> Arc<AppState> {
        let db = Connection::open_in_memory().unwrap();
        crate::persistence::migrations::migrate(&db).unwrap();
        Arc::new(AppState {
            db: Mutex::new(db),
            config: crate::app::Config {
                bind: "127.0.0.1:0".into(),
                db_path: PathBuf::new(),
                auth: crate::security::auth::test_auth_config(true),
            },
        })
    }

    #[tokio::test]
    async fn login_route_offers_organization_and_local_break_glass() {
        let response = build_router(oidc_state())
            .oneshot(Request::get("/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Organization login"));
        assert!(body.contains("Local login"));
    }

    #[tokio::test]
    async fn local_break_glass_login_never_contacts_oidc() {
        let response = build_router(oidc_state())
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=secret"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| value.starts_with("motehold_session="))
        );
    }

    #[tokio::test]
    async fn logout_invalidates_the_opaque_session() {
        let app = build_router(oidc_state());
        let login = app
            .clone()
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("password=secret"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = login
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("motehold_session="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let logout = app
            .clone()
            .oneshot(
                Request::post("/logout")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::SEE_OTHER);
        let protected = app
            .oneshot(
                Request::get("/")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(protected.status(), StatusCode::SEE_OTHER);
        assert_eq!(protected.headers()[header::LOCATION], "/login");
    }

    #[tokio::test]
    async fn callback_route_rejects_missing_flow_and_clears_flow_cookie() {
        let response = build_router(oidc_state())
            .oneshot(
                Request::get("/auth/oidc/callback")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("motehold_oidc_flow="))
            .unwrap();
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("Secure"));
    }
}
