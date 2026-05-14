
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

/// Converts a slice of `"host:port"` strings into the iterator form that
/// `pingora_load_balancing::LoadBalancer::try_from_iter` expects.
pub fn build_upstream<'a>(addrs: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
    addrs.iter().map(|a| a.to_string())
}

/// Canary routing: returns an alternate backend address for a given fraction
/// of traffic, keyed by user ID for sticky assignment.
///
/// Uses `FxHasher` (rustc-hash) instead of `DefaultHasher` because
/// `DefaultHasher` is explicitly not stable across Rust versions — two binaries
/// built with different toolchains would route different users to the canary.
pub fn canary_peer(user_id: &str, canary_addr: &str, fraction: f64) -> Option<String> {
    let hash = fx_hash(user_id);
    let bucket = (hash % 100) as f64;
    if bucket < fraction * 100.0 {
        Some(canary_addr.to_string())
    } else {
        None
    }
}

fn fx_hash(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}