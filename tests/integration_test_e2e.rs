/// End-to-end integration tests: OAuth2 Authorization-Code + Client-Credentials
/// flowing through Pingora → traefik/whoami, asserting HTTP headers.
///
/// # Stack (docker-compose.integration.yml)
///
///   [tests] ──► Pingora :6191 ──► whoami (traefik/whoami)
///                    │
///                    └── validates JWT / introspects via
///               mock-jwks :8888
///
/// traefik/whoami echoes every received request header back in its plain-text
/// body, so we can assert exactly which headers Pingora forwards upstream.
///
/// # Running
///
///   make integration-test
///
///   # or manually:
///   docker compose -f deploy/docker/docker-compose.integration.yml up -d
///   PINGORA_URL=http://localhost:6191 \
///   MOCK_JWKS_URL=http://localhost:8888 \
///   cargo test --test integration_test_e2e -- --nocapture
///
/// # Env vars
///   PINGORA_URL      proxy base URL   (default: http://localhost:6191)
///   MOCK_JWKS_URL    mock IdP URL     (default: http://localhost:8888)

use std::collections::HashMap;
use std::time::Duration;

// ── shared helpers ────────────────────────────────────────────────────────────

fn pingora_url() -> String {
    std::env::var("PINGORA_URL").unwrap_or_else(|_| "http://localhost:6191".into())
}

fn mock_jwks_url() -> String {
    std::env::var("MOCK_JWKS_URL").unwrap_or_else(|_| "http://localhost:8888".into())
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
}

/// No-redirect client — used when we need to inspect a 302 response.
fn no_redirect_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
}

// ── token helpers ─────────────────────────────────────────────────────────────

/// Obtain a user JWT (Authorization Code stand-in) from the mock IdP.
///
/// Form fields mirror mock_jwks.py `grant_type=password` shortcut.
fn obtain_user_token(sub: &str, roles: &[&str], scopes: &str, email: Option<&str>) -> String {
    let url = format!("{}/token", mock_jwks_url());
    let mut form: Vec<(&str, String)> = vec![
        ("sub",    sub.to_string()),
        ("roles",  roles.join(",")),
        ("scopes", scopes.to_string()),
    ];
    if let Some(e) = email {
        form.push(("email", e.to_string()));
    }

    let resp = client().post(&url).form(&form).send()
        .expect("mock-jwks /token (user) failed");

    assert!(resp.status().is_success(),
        "token endpoint {}: {}", resp.status(), resp.text().unwrap_or_default());

    let body: serde_json::Value = resp.json().expect("token response not JSON");
    body["access_token"].as_str().expect("access_token missing").to_string()
}

/// Obtain a machine-to-machine JWT via `grant_type=client_credentials`.
///
/// `sub` in the returned JWT equals `client_id`.
fn obtain_client_token(client_id: &str, roles: &[&str], scopes: &str) -> String {
    let url = format!("{}/token", mock_jwks_url());
    let form: Vec<(&str, String)> = vec![
        ("grant_type",    "client_credentials".into()),
        ("client_id",     client_id.to_string()),
        ("client_secret", "test-secret".into()),
        ("scope",         scopes.to_string()),
        ("roles",         roles.join(",")),
    ];

    let resp = client().post(&url).form(&form).send()
        .expect("mock-jwks /token (client_credentials) failed");

    assert!(resp.status().is_success(),
        "client_credentials endpoint {}: {}", resp.status(), resp.text().unwrap_or_default());

    let body: serde_json::Value = resp.json().expect("token response not JSON");
    body["access_token"].as_str().expect("access_token missing").to_string()
}

/// Obtain an expired JWT (exp = now - 120s, outside any clock-skew window).
fn obtain_expired_token(sub: &str, grant_type: &str, roles: &[&str]) -> String {
    let url = format!("{}/token", mock_jwks_url());
    // exp_in = -120 → already expired 2 minutes ago
    let form: Vec<(&str, String)> = if grant_type == "client_credentials" {
        vec![
            ("grant_type",    "client_credentials".into()),
            ("client_id",     sub.to_string()),
            ("client_secret", "secret".into()),
            ("scope",         "api:read".into()),
            ("roles",         roles.join(",")),
            ("exp_in",        "-120".into()),
        ]
    } else {
        vec![
            ("sub",    sub.to_string()),
            ("roles",  roles.join(",")),
            ("scopes", "openid api:read".into()),
            ("exp_in", "-120".into()),
        ]
    };

    let resp = client().post(&url).form(&form).send()
        .expect("mock-jwks /token (expired) failed");

    let body: serde_json::Value = resp.json().expect("token response not JSON");
    body["access_token"].as_str().expect("access_token missing").to_string()
}

// ── whoami response parsing ────────────────────────────────────────────────────

/// Parse traefik/whoami plain-text body into a case-insensitive header map.
///
/// whoami echoes lines like:
///   X-User-Id: alice
///   X-User-Scopes: openid api:read
fn parse_whoami_headers(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in body.lines() {
        if let Some((key, val)) = line.split_once(": ") {
            map.insert(key.to_lowercase(), val.trim().to_string());
        }
    }
    map
}

// ── readiness ─────────────────────────────────────────────────────────────────

/// Poll until Pingora is up (a 401 proves the proxy is reachable).
fn wait_for_pingora(timeout_secs: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(r) = client().get(format!("{}/api/healthz", pingora_url())).send() {
            if r.status().as_u16() == 401 {
                return;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("Pingora did not become ready within {timeout_secs}s");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn setup() { wait_for_pingora(60); }

// ═════════════════════════════════════════════════════════════════════════════
// MODULE A — Authorization-Code / user token tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod user_token_e2e {
    use super::*;

    // ── A-1. Happy path ───────────────────────────────────────────────────────

    #[test]
    fn valid_user_token_injects_identity_headers() {
        setup();
        let token = obtain_user_token(
            "user-alice", &["user"], "openid api:read", Some("alice@example.com"),
        );

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200,
            "expected 200, got {}", resp.status());

        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert_eq!(h.get("x-user-id").map(String::as_str), Some("user-alice"),
            "x-user-id wrong\n{body}");
        assert!(h.get("x-user-scopes").unwrap_or(&String::new()).contains("api:read"),
            "x-user-scopes missing api:read\n{body}");
        assert_eq!(h.get("x-user-email").map(String::as_str), Some("alice@example.com"),
            "x-user-email wrong\n{body}");
        assert!(!h.get("x-internal-service-auth").unwrap_or(&String::new()).is_empty(),
            "x-internal-service-auth missing\n{body}");
    }

    // ── A-2. Raw JWT / cookie stripped from upstream ──────────────────────────

    #[test]
    fn authorization_and_cookie_headers_stripped() {
        setup();
        let token = obtain_user_token("user-bob", &["user"], "openid api:read", None);

        let resp = client()
            .get(format!("{}/api/v1/products", pingora_url()))
            .bearer_auth(&token)
            .header("cookie", "session=abc")
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);

        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert!(h.get("authorization").is_none(),
            "authorization leaked upstream\n{body}");
        assert!(h.get("cookie").is_none(),
            "cookie leaked upstream\n{body}");
    }

    // ── A-3. No token → 401 + WWW-Authenticate ───────────────────────────────

    #[test]
    fn missing_token_returns_401_with_www_authenticate() {
        setup();

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 401);

        let www = resp.headers()
            .get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(www.contains("Bearer"),
            "WWW-Authenticate malformed: {www}");
    }

    // ── A-4. Wrong role on /api/admin/* → 403 ────────────────────────────────

    #[test]
    fn user_role_rejected_on_admin_path() {
        setup();
        let token = obtain_user_token("user-charlie", &["user"], "openid api:read api:write", None);

        let resp = client()
            .get(format!("{}/api/admin/users", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 403);
        let body: serde_json::Value = resp.json().unwrap_or_default();
        assert_eq!(body["error"].as_str().unwrap_or(""), "insufficient_role");
    }

    // ── A-5. Admin role on /api/admin/* → 200 ────────────────────────────────

    #[test]
    fn admin_role_allowed_on_admin_path() {
        setup();
        let token = obtain_user_token("user-dave", &["admin"], "openid api:read api:write", None);

        let resp = client()
            .get(format!("{}/api/admin/users", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert_eq!(h.get("x-user-id").map(String::as_str), Some("user-dave"));
        assert!(h.get("x-user-roles").unwrap_or(&String::new()).contains("admin"),
            "x-user-roles missing 'admin'\n{body}");
    }

    // ── A-6. POST without api:write → 403 ────────────────────────────────────

    #[test]
    fn post_without_write_scope_blocked() {
        setup();
        let token = obtain_user_token("user-eve", &["user"], "openid api:read", None);

        let resp = client()
            .post(format!("{}/api/orders", pingora_url()))
            .bearer_auth(&token)
            .json(&serde_json::json!({"item": "widget"}))
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 403);
        let body: serde_json::Value = resp.json().unwrap_or_default();
        assert_eq!(body["error"].as_str().unwrap_or(""), "insufficient_scope");
    }

    // ── A-7. POST with api:write → 200 + headers forwarded ───────────────────

    #[test]
    fn post_with_write_scope_allowed_headers_forwarded() {
        setup();
        let token = obtain_user_token("user-frank", &["user"], "openid api:read api:write", None);

        let resp = client()
            .post(format!("{}/api/orders", pingora_url()))
            .bearer_auth(&token)
            .json(&serde_json::json!({"item": "widget"}))
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert_eq!(h.get("x-user-id").map(String::as_str), Some("user-frank"));
        assert!(h.get("x-user-scopes").unwrap_or(&String::new()).contains("api:write"),
            "x-user-scopes missing api:write\n{body}");
    }

    // ── A-8. access_token cookie accepted ────────────────────────────────────

    #[test]
    fn access_token_cookie_accepted() {
        setup();
        let token = obtain_user_token("user-grace", &["user"], "openid api:read", None);

        let resp = client()
            .get(format!("{}/api/v1/products", pingora_url()))
            .header("cookie", format!("access_token={token}"))
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert_eq!(h.get("x-user-id").map(String::as_str), Some("user-grace"),
            "x-user-id wrong with cookie token\n{body}");
    }

    // ── A-9. x-trace-id in response ──────────────────────────────────────────

    #[test]
    fn response_has_x_trace_id() {
        setup();
        let token = obtain_user_token("user-hank", &["user"], "openid api:read", None);

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let trace = resp.headers()
            .get("x-trace-id").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(!trace.is_empty(), "x-trace-id response header missing");
    }

    // ── A-10. Browser + no token → 302 to IdP ────────────────────────────────

    #[test]
    fn browser_without_token_gets_302_redirect() {
        setup();

        let resp = no_redirect_client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .header("accept", "text/html,application/xhtml+xml,*/*")
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 302,
            "expected 302 for browser without token");

        let loc = resp.headers()
            .get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(loc.contains("response_type=code"),
            "Location missing response_type=code: {loc}");
        assert!(loc.contains("client_id="),
            "Location missing client_id: {loc}");
    }

    // ── A-11. Expired user token → 401 ───────────────────────────────────────

    #[test]
    fn expired_user_token_returns_401() {
        setup();
        let token = obtain_expired_token("user-stale", "password", &["user"]);

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        // OAUTH2_CLOCK_SKEW_SECS=60 in the test stack; exp_in=-120 is well
        // outside the window, so this must be a 401.
        assert_eq!(resp.status().as_u16(), 401,
            "expired user token should be rejected");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// MODULE B — Client-Credentials (machine-to-machine) tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod client_credentials_e2e {
    use super::*;

    // ── B-1. client_id forwarded as x-user-id, no email ──────────────────────

    #[test]
    fn service_token_forwards_client_id_as_user_id() {
        setup();
        let token = obtain_client_token("svc-billing", &["service"], "api:read");

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert_eq!(h.get("x-user-id").map(String::as_str), Some("svc-billing"),
            "x-user-id should equal client_id for M2M tokens\n{body}");

        // M2M tokens carry no email — header must be absent
        assert!(h.get("x-user-email").is_none(),
            "x-user-email must not be forwarded for M2M tokens\n{body}");
    }

    // ── B-2. service role allows /api/internal/* ──────────────────────────────

    #[test]
    fn service_role_allowed_on_internal_path() {
        setup();
        let token = obtain_client_token("svc-sync", &["service"], "api:read");

        let resp = client()
            .get(format!("{}/api/internal/sync", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert!(h.get("x-user-roles").unwrap_or(&String::new()).contains("service"),
            "x-user-roles missing 'service'\n{body}");
    }

    // ── B-3. admin role also allowed on /api/internal/* ──────────────────────

    #[test]
    fn admin_role_allowed_on_internal_path() {
        setup();
        let token = obtain_client_token("svc-admin-proxy", &["admin"], "api:read api:write");

        let resp = client()
            .get(format!("{}/api/internal/sync", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
    }

    // ── B-4. wrong role on /api/internal/* → 403 ─────────────────────────────

    #[test]
    fn wrong_role_blocked_on_internal_path() {
        setup();
        let token = obtain_client_token("svc-readonly", &["reader"], "api:read");

        let resp = client()
            .get(format!("{}/api/internal/sync", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 403);
        let body: serde_json::Value = resp.json().unwrap_or_default();
        assert_eq!(body["error"].as_str().unwrap_or(""), "insufficient_role");
    }

    // ── B-5. missing M2M token → 401, not 302 ────────────────────────────────
    // Machine clients never send Accept: text/html, so they must get 401.

    #[test]
    fn missing_m2m_token_returns_401_not_redirect() {
        setup();

        let resp = client()
            .get(format!("{}/api/internal/sync", pingora_url()))
            .header("accept", "application/json")
            // no Authorization header
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 401,
            "M2M client with no token should get 401, not 302");
    }

    // ── B-6. service token with api:write can POST ────────────────────────────

    #[test]
    fn service_token_with_write_scope_can_post() {
        setup();
        let token = obtain_client_token("svc-writer", &["service"], "api:read api:write");

        let resp = client()
            .post(format!("{}/api/orders", pingora_url()))
            .bearer_auth(&token)
            .json(&serde_json::json!({"source": "svc-writer"}))
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert_eq!(h.get("x-user-id").map(String::as_str), Some("svc-writer"));
        assert!(h.get("x-user-scopes").unwrap_or(&String::new()).contains("api:write"),
            "x-user-scopes missing api:write\n{body}");
    }

    // ── B-7. service token without write scope blocked from POST ──────────────

    #[test]
    fn service_token_without_write_scope_blocked_on_post() {
        setup();
        let token = obtain_client_token("svc-readonly-post", &["service"], "api:read");

        let resp = client()
            .post(format!("{}/api/orders", pingora_url()))
            .bearer_auth(&token)
            .json(&serde_json::json!({"source": "svc-readonly-post"}))
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 403);
        let body: serde_json::Value = resp.json().unwrap_or_default();
        assert_eq!(body["error"].as_str().unwrap_or(""), "insufficient_scope");
    }

    // ── B-8. raw JWT stripped from upstream for M2M requests ─────────────────

    #[test]
    fn m2m_authorization_header_stripped_from_upstream() {
        setup();
        let token = obtain_client_token("svc-strip-test", &["service"], "api:read");

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        assert!(h.get("authorization").is_none(),
            "authorization header leaked to upstream for M2M request\n{body}");
    }

    // ── B-9. x-trace-id in M2M response ──────────────────────────────────────

    #[test]
    fn m2m_response_has_x_trace_id() {
        setup();
        let token = obtain_client_token("svc-trace", &["service"], "api:read");

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let trace = resp.headers()
            .get("x-trace-id").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(!trace.is_empty(), "x-trace-id response header missing for M2M");
    }

    // ── B-10. Expired service token → 401 ────────────────────────────────────

    #[test]
    fn expired_service_token_returns_401() {
        setup();
        let token = obtain_expired_token("svc-expired", "client_credentials", &["service"]);

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 401,
            "expired service token should be rejected (exp_in=-120 is outside clock-skew window)");
    }

    // ── B-11. x-internal-service-auth forwarded to upstream ──────────────────

    #[test]
    fn internal_service_auth_header_present_for_m2m() {
        setup();
        let token = obtain_client_token("svc-internal-check", &["service"], "api:read");

        let resp = client()
            .get(format!("{}/api/v1/orders", pingora_url()))
            .bearer_auth(&token)
            .send().unwrap();

        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().unwrap_or_default();
        let h = parse_whoami_headers(&body);

        let internal = h.get("x-internal-service-auth").cloned().unwrap_or_default();
        assert!(!internal.is_empty(),
            "x-internal-service-auth missing for M2M request\n{body}");
    }

    // ── B-12. Multiple concurrent service tokens get independent trace IDs ────

    #[test]
    fn concurrent_m2m_requests_get_independent_trace_ids() {
        setup();

        let traces: Vec<String> = (0..4)
            .map(|i| {
                let token = obtain_client_token(
                    &format!("svc-concurrent-{i}"), &["service"], "api:read",
                );
                let resp = client()
                    .get(format!("{}/api/v1/orders", pingora_url()))
                    .bearer_auth(&token)
                    .send().unwrap();
                assert_eq!(resp.status().as_u16(), 200);
                resp.headers()
                    .get("x-trace-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        // All trace IDs must be non-empty
        assert!(traces.iter().all(|t| !t.is_empty()),
            "some trace IDs were empty: {traces:?}");

        // All trace IDs must be unique
        let unique: std::collections::HashSet<_> = traces.iter().collect();
        assert_eq!(unique.len(), traces.len(),
            "duplicate trace IDs across concurrent requests: {traces:?}");
    }
}
