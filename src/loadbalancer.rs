/// Converts a slice of `"host:port"` strings into the iterator form that
/// `pingora_load_balancing::LoadBalancer::try_from_iter` expects.
pub fn build_upstream<'a>(addrs: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
    addrs.iter().map(|a| a.to_string())
}

/// Canary routing: returns an alternate backend address for a given fraction
/// of traffic, keyed by user ID for sticky assignment.
pub fn canary_peer(user_id: &str, canary_addr: &str, fraction: f64) -> Option<String> {
    let hash = simple_hash(user_id);
    let bucket = (hash % 100) as f64;
    if bucket < fraction * 100.0 {
        Some(canary_addr.to_string())
    } else {
        None
    }
}

fn simple_hash(s: &str) -> u64 {
    use std::hash::Hash;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    std::hash::Hasher::finish(&hasher)
}
