use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug)]
pub enum ProxyError {
    Unauthorized(String),
    Forbidden { message: String, decision_id: String, body: serde_json::Value },
    BadRequest(String),
    Upstream(String),
    Internal(String),
    NotReady(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        match self {
            ProxyError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": { "message": msg, "type": "authentication_error", "code": "unauthorized" }
                })),
            )
                .into_response(),
            ProxyError::Forbidden { message, decision_id, body } => {
                let mut err = serde_json::json!({
                    "error": {
                        "message": message,
                        "type": "authorization_error",
                        "code": "paac_deny",
                        "decision_id": decision_id
                    }
                });
                if let Some(obj) = err.as_object_mut() {
                    obj.insert("paac".into(), body);
                }
                (StatusCode::FORBIDDEN, Json(err)).into_response()
            }
            ProxyError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": msg, "type": "invalid_request_error" }
                })),
            )
                .into_response(),
            ProxyError::Upstream(msg) => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": { "message": msg, "type": "upstream_error" }
                })),
            )
                .into_response(),
            ProxyError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "message": msg, "type": "server_error" }
                })),
            )
                .into_response(),
            ProxyError::NotReady(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "message": msg, "type": "not_ready" }
                })),
            )
                .into_response(),
        }
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
