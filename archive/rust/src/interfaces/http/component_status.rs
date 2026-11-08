use crate::{app::AppState, security::auth::random_token};
use axum::{Json, extract::State, http::HeaderMap};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub(crate) struct ComponentStatusEnvelope {
    schema_version: &'static str,
    component: &'static str,
    operation: &'static str,
    outcome: &'static str,
    data: ComponentStatusData,
    warnings: Vec<String>,
    error: Option<String>,
    correlation_id: String,
}

#[derive(Debug, Serialize)]
struct ComponentStatusData {
    status: &'static str,
    version: &'static str,
    standalone: bool,
    identity_mode: &'static str,
    capabilities: [&'static str; 3],
}

pub(crate) async fn component_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<ComponentStatusEnvelope> {
    Json(ComponentStatusEnvelope {
        schema_version: "linuxmice.response.v1",
        component: "katteke.motehold",
        operation: "status",
        outcome: "success",
        data: ComponentStatusData {
            status: "ready",
            version: env!("CARGO_PKG_VERSION"),
            standalone: true,
            identity_mode: state.config.auth.identity_mode(),
            capabilities: ["notes.channels", "notes.attachments", "notes.images"],
        },
        warnings: Vec::new(),
        error: None,
        correlation_id: request_correlation_id(&headers),
    })
}

fn request_correlation_id(headers: &HeaderMap) -> String {
    if let Some(value) = headers
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
        })
    {
        return value.to_string();
    }
    random_token()
}

#[cfg(test)]
mod tests {
    use super::request_correlation_id;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn echoes_only_safe_correlation_ids() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-correlation-id",
            HeaderValue::from_static("pilot:request-42"),
        );
        assert_eq!(request_correlation_id(&headers), "pilot:request-42");

        headers.insert("x-correlation-id", HeaderValue::from_static("unsafe/value"));
        let generated = request_correlation_id(&headers);
        assert_eq!(generated.len(), 43);
        assert!(
            generated
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        );
    }

    #[test]
    fn fallback_correlation_ids_are_random_and_opaque() {
        let headers = HeaderMap::new();
        let first = request_correlation_id(&headers);
        let second = request_correlation_id(&headers);

        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        );
    }
}
