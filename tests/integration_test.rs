/// Integration tests covering auth, ACL, scope, canary, and OAuth2 helpers.
/// Run with: `cargo test -- --nocapture`

// ── ACL / scope tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod acl_tests {
    use pingora_middleware::auth::{
        has_role, has_scopes, required_roles_for_path, required_scopes_for_path,
    };
    use pingora_middleware::oauth2::VerifiedClaims;

    fn claims(roles: &[&str], scopes: &[&str]) -> VerifiedClaims {
        VerifiedClaims {
            sub:    "user-test".into(),
            roles:  roles.iter().map(|s| s.to_string()).collect(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            email:  None,
        }
    }

    #[test]
    fn admin_path_requires_admin_role() {
        let required = required_roles_for_path("/api/admin/users").unwrap();
        assert!(!has_role(&claims(&["user"],  &[]), required));
        assert!( has_role(&claims(&["admin"], &[]), required));
    }

    #[test]
    fn internal_path_allows_service_role() {
        let required = required_roles_for_path("/api/internal/sync").unwrap();
        assert!(has_role(&claims(&["service"], &[]), required));
        assert!(has_role(&claims(&["admin"],   &[]), required));
        assert!(!has_role(&claims(&["user"],   &[]), required));
    }

    #[test]
    fn public_path_has_no_role_requirement() {
        assert!(required_roles_for_path("/api/v1/products").is_none());
    }

    #[test]
    fn write_requires_api_write_scope() {
        let required = required_scopes_for_path("/api/orders", "POST").unwrap();
        assert!(!has_scopes(&claims(&[], &["api:read"]),  required));
        assert!( has_scopes(&claims(&[], &["api:write"]), required));
    }

    #[test]
    fn get_requires_api_read_scope() {
        let required = required_scopes_for_path("/api/orders", "GET").unwrap();
        assert!( has_scopes(&claims(&[], &["api:read"]),  required));
        assert!(!has_scopes(&claims(&[], &[]),             required));
    }

    #[test]
    fn has_scopes_requires_all_scopes() {
        let c = claims(&[], &["api:read"]);
        assert!(!has_scopes(&c, &["api:read", "api:write"]));
        let c2 = claims(&[], &["api:read", "api:write"]);
        assert!( has_scopes(&c2, &["api:read", "api:write"]));
    }
}

// ── JWT / OIDC token tests ────────────────────────────────────────────────────

#[cfg(test)]
mod token_tests {
    use pingora_middleware::oauth2::extract_token;

    fn make_header(key: &'static str, val: &'static str) -> pingora_http::RequestHeader {
        let mut h = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        h.insert_header(key, val).unwrap();
        h
    }

    #[test]
    fn extracts_bearer_from_authorization_header() {
        let h = make_header("authorization", "Bearer my.jwt.token");
        assert_eq!(extract_token(&h), Some("my.jwt.token".to_string()));
    }

    #[test]
    fn returns_none_for_missing_auth() {
        let h = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(extract_token(&h), None);
    }

    #[test]
    fn returns_none_for_non_bearer_scheme() {
        let h = make_header("authorization", "Basic dXNlcjpwYXNz");
        assert_eq!(extract_token(&h), None);
    }

    #[test]
    fn extracts_token_from_access_token_cookie() {
        let h = make_header("cookie", "session=abc; access_token=cookie.jwt.here; other=xyz");
        assert_eq!(extract_token(&h), Some("cookie.jwt.here".to_string()));
    }

    #[test]
    fn bearer_header_takes_precedence_over_cookie() {
        let mut h = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        h.insert_header("authorization", "Bearer header.token").unwrap();
        h.insert_header("cookie", "access_token=cookie.token").unwrap();
        assert_eq!(extract_token(&h), Some("header.token".to_string()));
    }
}

// ── Canary routing tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod canary_tests {
    use pingora_middleware::loadbalancer::canary_peer;

    #[test]
    fn same_user_always_gets_same_canary_decision() {
        let r1 = canary_peer("user-stable", "canary:8080", 0.5);
        let r2 = canary_peer("user-stable", "canary:8080", 0.5);
        assert_eq!(r1, r2, "canary routing must be deterministic");
    }

    #[test]
    fn zero_fraction_never_canaries() {
        for i in 0..100 {
            assert!(canary_peer(&format!("user-{i}"), "canary:8080", 0.0).is_none());
        }
    }

    #[test]
    fn full_fraction_always_canaries() {
        for i in 0..100 {
            assert!(canary_peer(&format!("user-{i}"), "canary:8080", 1.0).is_some());
        }
    }
}

// ── OAuth2 redirect URL builder test ─────────────────────────────────────────

#[cfg(test)]
mod oauth2_redirect_tests {
    use pingora_middleware::oauth2::authorization_redirect_url;

    #[test]
    fn redirect_url_contains_required_params() {
        let url = authorization_redirect_url(
            "https://idp.example.com/realms/test",
            "my-client",
            "https://app.example.com/callback",
            "state-xyz",
            &["openid", "api:read"],
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("state=state-xyz"));
        assert!(url.contains("openid"));
        assert!(url.contains("api%3Aread") || url.contains("api:read"));
    }
}
