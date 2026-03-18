use crate::{
    auth::{has_role, has_scopes, required_roles_for_path, required_scopes_for_path},
    ctx::RequestCtx,
    loadbalancer::canary_peer,
    oauth2::{extract_token, OAuth2Service},
    observability::{inject_trace_headers, log_request},
    rate_limit::RateLimiter,
};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::Error as PingoraError;
use pingora_http::ResponseHeader;
use pingora_load_balancing::{selection::RoundRobin, LoadBalancer};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use tracing::{info, warn};

const CANARY_ADDR: &str = "intranet-canary:8080";
const CANARY_FRACTION: f64 = 0.10;

fn internal_token() -> String {
    std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_else(|_| "dev-token".to_string())
}

type PResult<T> = Result<T, Box<PingoraError>>;

fn to_perr(e: impl std::fmt::Display) -> Box<PingoraError> {
    PingoraError::new_str(Box::leak(e.to_string().into_boxed_str()))
}

pub struct ProxyMiddleware {
    upstream: Arc<LoadBalancer<RoundRobin>>,
    rate_limiter: Arc<RateLimiter>,
    oauth2: Arc<OAuth2Service>,
}

impl ProxyMiddleware {
    pub fn new(
        upstream: Arc<LoadBalancer<RoundRobin>>,
        oauth2: Arc<OAuth2Service>,
    ) -> Self {
        Self {
            upstream,
            rate_limiter: Arc::new(RateLimiter::from_env()),
            oauth2,
        }
    }
}

#[async_trait]
impl ProxyHttp for ProxyMiddleware {
    type CTX = RequestCtx;
    fn new_ctx(&self) -> Self::CTX { RequestCtx::new() }

    // ── 1. Request filter ────────────────────────────────────────────────────
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> PResult<bool> {
        let path   = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str().to_string();

        // ── A. Extract token (Bearer header or access_token cookie) ──────────
        let token = match extract_token(session.req_header()) {
            Some(t) => t,
            None => {
                // Browser request with no token → redirect to IdP (BFF pattern)
                let accepts_html = session
                    .req_header()
                    .headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .map(|a| a.contains("text/html"))
                    .unwrap_or(false);

                if accepts_html {
                    return redirect_to_idp(session).await;
                }
                warn!(trace_id = %ctx.trace_id, path = %path, "no token present");
                ctx.auth_error = Some("missing_token".into());
                return respond_with(session, 401, "missing_token", "No bearer token provided").await;
            }
        };

        // ── B. Verify token via configured strategy (JWKS / introspect) ─────
        let auth_start = std::time::Instant::now();
        let claims = match self.oauth2.verify(&token).await {
            Ok(c) => c,
            Err(e) => {
                let code = oauth2_error_code(&e.to_string());
                warn!(
                    trace_id   = %ctx.trace_id,
                    path       = %path,
                    error_code = %code,
                    "token verification failed: {e}"
                );
                ctx.auth_error = Some(code.clone());
                return respond_with(session, 401, &code, &e.to_string()).await;
            }
        };
        let auth_ms = auth_start.elapsed().as_millis();
        info!(trace_id = %ctx.trace_id, auth_latency_ms = %auth_ms, sub = %claims.sub, "token verified");

        // ── C. Role ACL ──────────────────────────────────────────────────────
        if let Some(required) = required_roles_for_path(&path) {
            if !has_role(&claims, required) {
                warn!(trace_id = %ctx.trace_id, sub = %claims.sub, path = %path, "insufficient roles");
                ctx.auth_error = Some("insufficient_role".into());
                return respond_with(session, 403, "insufficient_role", "Role not granted for this path").await;
            }
        }

        // ── D. Scope enforcement ─────────────────────────────────────────────
        if let Some(required) = required_scopes_for_path(&path, &method) {
            if !has_scopes(&claims, required) {
                warn!(trace_id = %ctx.trace_id, sub = %claims.sub, path = %path, method = %method, "insufficient scope");
                ctx.auth_error = Some("insufficient_scope".into());
                return respond_with(session, 403, "insufficient_scope", "Required OAuth2 scope not present").await;
            }
        }

        // ── E. Per-user rate limiting ────────────────────────────────────────
        match self.rate_limiter.is_allowed(&claims.sub).await {
            Ok(false) => {
                ctx.rate_limited = true;
                warn!(trace_id = %ctx.trace_id, sub = %claims.sub, "rate limit exceeded");
                return respond_with(session, 429, "rate_limited", "Too many requests").await;
            }
            Err(e) => warn!("Rate limiter unavailable, failing open: {e}"),
            Ok(true) => {}
        }

        // ── F. Audit log for write operations ────────────────────────────────
        if matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
            info!(
                audit   = true,
                sub     = %claims.sub,
                email   = ?claims.email,
                method  = %method,
                path    = %path,
                "write request authorised"
            );
        }

        ctx.claims = Some(claims);
        Ok(false)
    }

    // ── 2. Upstream peer selection ────────────────────────────────────────────
    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> PResult<Box<HttpPeer>> {
        if let Some(uid) = ctx.user_id() {
            if let Some(canary) = canary_peer(uid, CANARY_ADDR, CANARY_FRACTION) {
                ctx.upstream_addr = Some(canary.clone());
                return Ok(Box::new(HttpPeer::new(canary, false, String::new())));
            }
        }

        let upstream = self
            .upstream
            .select(b"", 256)
            .ok_or_else(|| PingoraError::new_str("no healthy upstream"))?;

        let addr = upstream.addr.to_string();
        ctx.upstream_addr = Some(addr.clone());
        Ok(Box::new(HttpPeer::new(addr, false, String::new())))
    }

    // ── 3. Upstream request filter ────────────────────────────────────────────
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()> {
        // Internal auth token — proves this request passed Pingora
        upstream_request
            .insert_header("x-internal-service-auth", internal_token().as_str())
            .map_err(to_perr)?;

        // Forward verified identity as structured headers (not the raw JWT)
        if let Some(claims) = &ctx.claims {
            upstream_request.insert_header("x-user-id",     claims.sub.as_str()).map_err(to_perr)?;
            upstream_request.insert_header("x-user-scopes", claims.scopes.join(" ").as_str()).map_err(to_perr)?;
            upstream_request.insert_header("x-user-roles",  claims.roles.join(",").as_str()).map_err(to_perr)?;
            if let Some(email) = &claims.email {
                upstream_request.insert_header("x-user-email", email.as_str()).map_err(to_perr)?;
            }
        }

        // W3C trace propagation
        inject_trace_headers(upstream_request, &ctx.trace_id).map_err(to_perr)?;

        // Strip raw JWT and cookies — intranet only sees structured headers
        upstream_request.remove_header("authorization");
        upstream_request.remove_header("cookie");
        Ok(())
    }

    // ── 4. Response filter ────────────────────────────────────────────────────
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()> {
        upstream_response.insert_header("x-trace-id", ctx.trace_id.as_str()).map_err(to_perr)?;
        upstream_response.remove_header("x-internal-service-auth");
        Ok(())
    }

    // ── 5. Logging ────────────────────────────────────────────────────────────
    async fn logging(&self, session: &mut Session, _error: Option<&PingoraError>, ctx: &mut Self::CTX) {
        let status = session.response_written().map(|r| r.status.as_u16()).unwrap_or(0);
        let path   = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str().to_string();
        log_request(ctx, status, &path, &method);
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<PingoraError>,
    ) -> Box<PingoraError> {
        warn!(trace_id = %ctx.trace_id, upstream = ?ctx.upstream_addr, "upstream connection failed");
        e
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn respond_with(
    session: &mut Session,
    status: u16,
    error_code: &str,
    message: &str,
) -> PResult<bool> {
    let body = Bytes::from(format!(
        r#"{{"error":"{}","message":"{}","status":{}}}"#,
        error_code, message, status
    ));
    let mut resp = ResponseHeader::build(status, None).map_err(to_perr)?;
    resp.insert_header("content-type", "application/json").map_err(to_perr)?;
    resp.insert_header("content-length", body.len().to_string().as_str()).map_err(to_perr)?;
    // RFC 6750 WWW-Authenticate header for 401s
    if status == 401 {
        resp.insert_header(
            "www-authenticate",
            format!(r#"Bearer error="{error_code}""#).as_str(),
        ).map_err(to_perr)?;
    }
    session.write_response_header(Box::new(resp), false).await.map_err(to_perr)?;
    session.write_response_body(Some(body), true).await.map_err(to_perr)?;
    Ok(true)
}

/// BFF pattern: browser with no token gets a 302 to the IdP authorization endpoint.
async fn redirect_to_idp(session: &mut Session) -> PResult<bool> {
    let issuer      = std::env::var("OIDC_ISSUER").unwrap_or_else(|_| "https://idp.example.com".into());
    let client_id   = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "api".into());
    let redirect_uri = std::env::var("OIDC_REDIRECT_URI")
        .unwrap_or_else(|_| "https://api.example.com/callback".into());
    let state = uuid::Uuid::new_v4().to_string();

    let location = crate::oauth2::authorization_redirect_url(
        &issuer, &client_id, &redirect_uri, &state, &["openid", "profile", "email", "api:read"],
    );

    let mut resp = ResponseHeader::build(302, None).map_err(to_perr)?;
    resp.insert_header("location", location.as_str()).map_err(to_perr)?;
    // Store state in a short-lived cookie for CSRF protection
    resp.insert_header(
        "set-cookie",
        format!("oauth_state={state}; HttpOnly; Secure; SameSite=Lax; Max-Age=300").as_str(),
    ).map_err(to_perr)?;
    session.write_response_header(Box::new(resp), true).await.map_err(to_perr)?;
    Ok(true)
}

/// Classify an error string into an RFC 6750 error code for structured logging.
fn oauth2_error_code(msg: &str) -> String {
    if msg.contains("expired") || msg.contains("exp") {
        "token_expired".into()
    } else if msg.contains("inactive") {
        "token_inactive".into()
    } else if msg.contains("insufficient_scope") {
        "insufficient_scope".into()
    } else if msg.contains("signature") || msg.contains("kid") {
        "invalid_token".into()
    } else {
        "invalid_token".into()
    }
}
