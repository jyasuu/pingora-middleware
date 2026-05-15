use anyhow::Result;
use redis::aio::MultiplexedConnection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Sliding-window rate limiter backed by Redis.
///
/// Uses a Lua script executed atomically so the check-and-increment
/// is a single round-trip with no TOCTOU race.
///
/// Limits applied (configurable via env vars):
///   RATE_LIMIT_REQUESTS  — requests allowed per window (default 100)
///   RATE_LIMIT_WINDOW_S  — window size in seconds          (default 60)
pub struct RateLimiter {
    max_requests: usize,
    window_secs: usize,
    /// Shared multiplexed connection — created once at startup, reused across
    /// all requests. Wrapping in Mutex<> satisfies Send + Sync across .await.
    conn: Arc<Mutex<MultiplexedConnection>>,
}

impl RateLimiter {
    /// Build from environment.  Must be called from inside a Tokio runtime
    /// (i.e. after `server.bootstrap()`) because it opens the Redis connection.
    pub fn from_env() -> Self {
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

        // Open the connection ONCE at startup, not once per request.
        let conn = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let client = redis::Client::open(redis_url)
                    .expect("Invalid REDIS_URL");
                client
                    .get_multiplexed_async_connection()
                    .await
                    .expect("Failed to connect to Redis at startup")
            })
        });

        Self {
            max_requests: std::env::var("RATE_LIMIT_REQUESTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            window_secs: std::env::var("RATE_LIMIT_WINDOW_S")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Returns `true` if the request should be allowed, `false` if rate-limited.
    ///
    /// The key is typically the user ID so limits are per-identity, not per-IP.
    pub async fn is_allowed(&self, key: &str) -> Result<bool> {
        let mut conn = self.conn.lock().await;

        // Lua atomic sliding window:
        //   KEYS[1]  = rate limit key (e.g. "rl:user123")
        //   ARGV[1]  = current Unix timestamp in seconds
        //   ARGV[2]  = window size in seconds
        //   ARGV[3]  = max allowed requests
        let script = redis::Script::new(r#"
            local key    = KEYS[1]
            local now    = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local limit  = tonumber(ARGV[3])

            -- Remove entries outside the current window
            redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

            local count = redis.call('ZCARD', key)
            if count >= limit then
                return 0
            end

            -- Record this request (score = timestamp, member = unique id)
            redis.call('ZADD', key, now, now .. ':' .. math.random(1e9))
            redis.call('EXPIRE', key, window)
            return 1
        "#);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let result: i32 = script
            .key(format!("rl:{key}"))
            .arg(now)
            .arg(self.window_secs)
            .arg(self.max_requests)
            .invoke_async(&mut *conn)
            .await?;

        Ok(result == 1)
    }
}
