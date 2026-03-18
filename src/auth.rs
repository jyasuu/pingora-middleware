use crate::oauth2::VerifiedClaims;

/// Returns true if the user has at least one of the required roles.
pub fn has_role(claims: &VerifiedClaims, required: &[&str]) -> bool {
    required.iter().any(|r| claims.roles.iter().any(|ur| ur == r))
}

/// Returns true if the token carries all of the required scopes.
pub fn has_scopes(claims: &VerifiedClaims, required: &[&str]) -> bool {
    let granted: std::collections::HashSet<&str> =
        claims.scopes.iter().map(String::as_str).collect();
    required.iter().all(|s| granted.contains(s))
}

/// Path-to-role ACL table.
/// Returns the roles required to access a given path prefix, or None for
/// paths where any authenticated user is allowed through.
pub fn required_roles_for_path(path: &str) -> Option<&'static [&'static str]> {
    if path.starts_with("/api/admin") {
        Some(&["admin"])
    } else if path.starts_with("/api/internal") {
        Some(&["service", "admin"])
    } else {
        None
    }
}

/// Path-to-scope table.
/// Returns the OAuth2 scopes required for write operations.
pub fn required_scopes_for_path(path: &str, method: &str) -> Option<&'static [&'static str]> {
    let is_write = matches!(method, "POST" | "PUT" | "PATCH" | "DELETE");
    if path.starts_with("/api/") && is_write {
        Some(&["api:write"])
    } else if path.starts_with("/api/") {
        Some(&["api:read"])
    } else {
        None
    }
}
