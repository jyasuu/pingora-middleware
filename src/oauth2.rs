/// OAuth2/OIDC support for Pingora middleware.
///
/// Implements three validation strategies, selectable via the
/// OAUTH2_STRATEGY environment variable:
///
///   jwks         — Validate JWT signature locally using cached JWKS (default, fastest)
///   introspect   — Call IdP /introspect on every request (slowest, instant revocation)
///   discovery    — Bootstrap from .well-known/openid-configuration (multi-tenant)
///
/// Configuration env vars:
///   OAUTH2_STRATEGY          jwks | introspect | discovery   (default: jwks)
///   OIDC_ISSUER              https://your-idp.example.com
///   OIDC_AUDIENCE            your-api-client-id
///   OIDC_REQUIRED_SCOPES     api:read,api:write  (comma-separated, all must be present)
///   JWKS_REFRESH_SECS        how often to refresh JWKS in background (default: 3600)
///   OAUTH2_CLOCK_SKEW_SECS   leeway for exp/nbf validation (default: 60)
///   INTROSPECT_CLIENT_ID     client_id for introspection endpoint
///   INTROSPECT_CLIENT_SECRET client_secret for introspection endpoint

use anyhow::{anyhow, bail, Result};
use arc_swap::ArcSwap;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

// ── Validated claims returned to the filter pipeline ─────────────────────────

#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    /// Subject — unique user/service identifier
    pub sub: String,
    /// OAuth2 scopes granted to this token
    pub scopes: Vec<String>,
    /// Application roles (from custom `roles` claim)
    pub roles: Vec<String>,
    /// Raw email if present
    pub email: Option<String>,
}

// ── Internal JWT claims shape ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawClaims {
    sub: String,
    exp: usize,
    #[serde(default)]
    nbf: usize,
    aud: Option<serde_json::Value>,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    roles: Vec<String>,
    email: Option<String>,
}

// ── OIDC Discovery document (subset we need) ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
    introspection_endpoint: Option<String>,
}

// ── Token introspection response ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IntrospectResponse {
    active: bool,
    sub: Option<String>,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    roles: Vec<String>,
    email: Option<String>,
}

// ── JWKS cache entry ─────────────────────────────────────────────────────────

#[allow(dead_code)]
struct JwksCache {
    keyset: JwkSet,
    fetched_at: Instant,
}

// ── OAuth2 service (the main entry point) ────────────────────────────────────

pub struct OAuth2Service {
    strategy: Strategy,
    issuer: String,
    audience: String,
    required_scopes: Vec<String>,
    clock_skew: u64,
    http: reqwest::Client,

    /// Hot-swappable JWKS — background task writes, request handler reads
    jwks: Arc<ArcSwap<Option<JwksCache>>>,
    jwks_uri: Arc<tokio::sync::RwLock<Option<String>>>,
    introspect_uri: Arc<tokio::sync::RwLock<Option<String>>>,

    introspect_client_id: String,
    introspect_client_secret: String,
}

#[derive(Debug, Clone, PartialEq)]
enum Strategy {
    Jwks,
    Introspect,
    Discovery,
}

impl OAuth2Service {
    /// Construct from environment variables and immediately bootstrap
    /// (fetches discovery doc / JWKS synchronously so the server is ready
    /// to validate on the first request).
    pub async fn from_env() -> Result<Self> {
        let strategy = match std::env::var("OAUTH2_STRATEGY")
            .unwrap_or_else(|_| "jwks".into())
            .as_str()
        {
            "introspect" => Strategy::Introspect,
            "discovery" => Strategy::Discovery,
            _ => Strategy::Jwks,
        };

        let issuer = std::env::var("OIDC_ISSUER")
            .unwrap_or_else(|_| "https://idp.example.com".into());
        let audience = std::env::var("OIDC_AUDIENCE")
            .unwrap_or_else(|_| "api".into());
        let required_scopes: Vec<String> = std::env::var("OIDC_REQUIRED_SCOPES")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let clock_skew: u64 = std::env::var("OAUTH2_CLOCK_SKEW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let svc = Self {
            strategy,
            issuer,
            audience,
            required_scopes,
            clock_skew,
            http,
            jwks: Arc::new(ArcSwap::new(Arc::new(None))),
            jwks_uri: Arc::new(tokio::sync::RwLock::new(None)),
            introspect_uri: Arc::new(tokio::sync::RwLock::new(None)),
            introspect_client_id: std::env::var("INTROSPECT_CLIENT_ID")
                .unwrap_or_default(),
            introspect_client_secret: std::env::var("INTROSPECT_CLIENT_SECRET")
                .unwrap_or_default(),
        };

        // Bootstrap: fetch discovery doc or JWKS immediately
        svc.bootstrap().await?;
        Ok(svc)
    }

    async fn bootstrap(&self) -> Result<()> {
        match self.strategy {
            Strategy::Discovery | Strategy::Introspect => {
                let doc = self.fetch_discovery().await?;
                *self.jwks_uri.write().await = Some(doc.jwks_uri.clone());
                if let Some(uri) = doc.introspection_endpoint {
                    *self.introspect_uri.write().await = Some(uri);
                }
                self.refresh_jwks(&doc.jwks_uri).await?;
                info!("OIDC discovery bootstrap complete for {}", self.issuer);
            }
            Strategy::Jwks => {
                // Derive JWKS URI from issuer using the standard path
                let uri = format!("{}/protocol/openid-connect/certs", self.issuer.trim_end_matches('/'));
                *self.jwks_uri.write().await = Some(uri.clone());
                self.refresh_jwks(&uri).await?;
                info!("JWKS bootstrap complete from {uri}");
            }
        }
        Ok(())
    }

    // ── Public: verify a Bearer token ────────────────────────────────────────

    pub async fn verify(&self, token: &str) -> Result<VerifiedClaims> {
        let claims = match self.strategy {
            Strategy::Introspect => self.introspect_token(token).await?,
            _ => self.validate_jwt_locally(token).await?,
        };

        // Scope enforcement — all required scopes must be present
        if !self.required_scopes.is_empty() {
            let granted: HashSet<&str> = claims.scopes.iter().map(String::as_str).collect();
            for required in &self.required_scopes {
                if !granted.contains(required.as_str()) {
                    bail!("insufficient_scope: required `{required}` not in token");
                }
            }
        }

        Ok(claims)
    }

    // ── JWKS-backed local JWT validation ─────────────────────────────────────

    async fn validate_jwt_locally(&self, token: &str) -> Result<VerifiedClaims> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or_else(|| anyhow!("JWT missing `kid` header"))?;

        let keyset_guard = self.jwks.load();
        let cache = keyset_guard
            .as_ref()
            .as_ref()
            .ok_or_else(|| anyhow!("JWKS not yet loaded"))?;

        // Find the matching key by kid
        let jwk = cache
            .keyset
            .find(&kid)
            .ok_or_else(|| anyhow!("no JWK found for kid={kid}"))?;

        let decoding_key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?,
            AlgorithmParameters::EllipticCurve(ec) => {
                DecodingKey::from_ec_components(&ec.x, &ec.y)?
            }
            AlgorithmParameters::OctetKeyPair(okp) => DecodingKey::from_ed_components(&okp.x)?,
            _ => bail!("unsupported JWK algorithm"),
        };

        let algorithm = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            jsonwebtoken::Algorithm::EdDSA => Algorithm::EdDSA,
            other => bail!("unsupported algorithm: {other:?}"),
        };

        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = self.clock_skew;

        let data = decode::<RawClaims>(token, &decoding_key, &validation)?;
        Ok(claims_from_raw(data.claims))
    }

    // ── Token introspection (calls IdP on every request) ─────────────────────

    async fn introspect_token(&self, token: &str) -> Result<VerifiedClaims> {
        let uri = self
            .introspect_uri
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("introspection endpoint not configured"))?;

        let resp: IntrospectResponse = self
            .http
            .post(&uri)
            .basic_auth(&self.introspect_client_id, Some(&self.introspect_client_secret))
            .form(&[("token", token)])
            .send()
            .await?
            .json()
            .await?;

        if !resp.active {
            bail!("token_inactive: IdP reported token as inactive");
        }

        let sub = resp.sub.ok_or_else(|| anyhow!("introspect response missing `sub`"))?;
        let scopes = resp.scope.split_whitespace().map(String::from).collect();

        Ok(VerifiedClaims {
            sub,
            scopes,
            roles: resp.roles,
            email: resp.email,
        })
    }

    // ── JWKS refresh ─────────────────────────────────────────────────────────

    async fn refresh_jwks(&self, uri: &str) -> Result<()> {
        debug!("Refreshing JWKS from {uri}");
        let keyset: JwkSet = self.http.get(uri).send().await?.json().await?;
        self.jwks.store(Arc::new(Some(JwksCache {
            keyset,
            fetched_at: Instant::now(),
        })));
        debug!("JWKS refreshed successfully");
        Ok(())
    }

    async fn fetch_discovery(&self) -> Result<OidcDiscovery> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let doc: OidcDiscovery = self.http.get(&url).send().await?.json().await?;
        Ok(doc)
    }

    // ── Background JWKS refresh task ─────────────────────────────────────────
    //
    // Call this once at startup; it loops forever, refreshing on the configured
    // interval. Pass the returned future to tokio::spawn or a Pingora background
    // service.

    pub async fn run_jwks_refresh_loop(self: Arc<Self>) {
        let interval_secs: u64 = std::env::var("JWKS_REFRESH_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // first tick fires immediately — skip it

        loop {
            interval.tick().await;
            let uri = self.jwks_uri.read().await.clone();
            if let Some(uri) = uri {
                match self.refresh_jwks(&uri).await {
                    Ok(()) => info!("JWKS refreshed in background"),
                    Err(e) => warn!("JWKS refresh failed (keeping stale keys): {e}"),
                }
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn claims_from_raw(raw: RawClaims) -> VerifiedClaims {
    let scopes = raw.scope.split_whitespace().map(String::from).collect();
    VerifiedClaims {
        sub: raw.sub,
        scopes,
        roles: raw.roles,
        email: raw.email,
    }
}

/// Extract Bearer token from Authorization header or `access_token` cookie.
pub fn extract_token(headers: &pingora_http::RequestHeader) -> Option<String> {
    // 1. Authorization: Bearer <token>
    if let Some(auth) = headers.headers.get("authorization") {
        if let Ok(s) = auth.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                return Some(t.to_string());
            }
        }
    }
    // 2. Cookie: access_token=<token>  (BFF / session-cookie pattern)
    if let Some(cookie) = headers.headers.get("cookie") {
        if let Ok(s) = cookie.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("access_token=") {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Build the IdP authorization redirect URL for the Authorization Code flow.
/// Pingora returns this as a 302 when no valid token is present and the
/// request came from a browser (Accept: text/html).
pub fn authorization_redirect_url(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    scopes: &[&str],
) -> String {
    let scope = scopes.join("%20");
    format!(
        "{issuer}/protocol/openid-connect/auth\
         ?response_type=code\
         &client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &scope={scope}\
         &state={state}"
    )
}
