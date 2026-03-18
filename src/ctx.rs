use crate::oauth2::VerifiedClaims;

/// Per-request context threaded through every Pingora hook.
#[derive(Default, Debug)]
pub struct RequestCtx {
    /// Distributed trace ID injected into upstream as traceparent
    pub trace_id: String,
    /// Validated identity from OAuth2/OIDC
    pub claims: Option<VerifiedClaims>,
    /// Which upstream instance was selected (for logging)
    pub upstream_addr: Option<String>,
    /// Timestamp the request entered Pingora (nanoseconds)
    pub start_ns: u64,
    /// Whether this request was rate-limited and short-circuited
    pub rate_limited: bool,
    /// OAuth2 error code if auth failed (for structured logging)
    pub auth_error: Option<String>,
}

impl RequestCtx {
    pub fn new() -> Self {
        Self {
            trace_id: uuid::Uuid::new_v4().to_string(),
            start_ns: current_ns(),
            ..Default::default()
        }
    }

    pub fn elapsed_ms(&self) -> f64 {
        let elapsed = current_ns().saturating_sub(self.start_ns);
        elapsed as f64 / 1_000_000.0
    }

    pub fn user_id(&self) -> Option<&str> {
        self.claims.as_ref().map(|c| c.sub.as_str())
    }
}

fn current_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
