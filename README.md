# pingora-middleware

Rust-based DMZ proxy built on [Pingora](https://github.com/cloudflare/pingora).
Sits between NGINX (edge/TLS) and your intranet business services.

```
Client → NGINX (TLS · Static · IP ACL)
       → Pingora (JWT · Rate limit · Canary · mTLS · Tracing)
       → Business Service (gRPC / HTTP · Intranet)
```

## What each file does

| File | Role |
|---|---|
| `src/main.rs` | Server bootstrap, service registration, health-check background task |
| `src/filters.rs` | `ProxyHttp` impl — all hook logic (auth, rate-limit, header injection) |
| `src/auth.rs` | JWT validation + path-based ACL table |
| `src/rate_limit.rs` | Redis sliding-window rate limiter (Lua atomic script) |
| `src/loadbalancer.rs` | Upstream list builder + canary routing helper |
| `src/observability.rs` | W3C trace header injection + structured access logging |
| `src/ctx.rs` | Per-request context threaded through all Pingora hooks |
| `nginx.conf` | NGINX edge config — TLS, IP ACL, forwarding to Pingora on :6191 |

## Running locally

```bash
# Dependencies: Redis for rate limiting
docker run -d -p 6379:6379 redis:alpine

# Required environment variables
export JWT_SECRET="your-secret-key"
export REDIS_URL="redis://127.0.0.1/"
export RATE_LIMIT_REQUESTS=100
export RATE_LIMIT_WINDOW_S=60
export INTERNAL_SERVICE_TOKEN="change-this-token"

cargo run --bin proxy
# Listens on :6191 — point NGINX upstream there
```

## Request lifecycle

1. **NGINX** terminates TLS, serves static files, blocks IPs/geos, forwards `/api/*` to Pingora.
2. **`request_filter`** — validates JWT (HS256), checks path-level ACL, enforces Redis sliding-window rate limit. Returns `401 / 403 / 429` immediately on failure.
3. **`upstream_peer`** — selects backend: 10% of traffic routes to canary build (stable hash by user ID), rest goes round-robin across the healthy pool.
4. **`upstream_request_filter`** — injects `x-internal-service-auth`, `x-user-id`, `x-user-roles`, W3C `traceparent`, and strips the client JWT.
5. **`response_filter`** — echoes `x-trace-id` back to client, strips internal headers.
6. **`logging`** — emits a structured JSON access line with latency, user ID, upstream address, and trace ID.

## Production checklist

- [ ] Load `JWT_SECRET` from a secrets manager (Vault, AWS SM, GCP SM), not env vars
- [ ] Enable mTLS to the intranet: set `tls: true` in `HttpPeer` and load client certs in server config
- [ ] Replace `tracing::info!` calls with OpenTelemetry span attributes and export to Jaeger/Tempo
- [ ] Replace the static ACL table in `auth.rs` with a database-backed config hot-reloaded via a background task
- [ ] Set `INTERNAL_SERVICE_TOKEN` via secrets manager and rotate it; the business service must validate it
- [ ] Tune `keepalive` count in `Cargo.toml` and NGINX based on observed upstream concurrency
- [ ] Enable NGINX `proxy_buffering off` only for `/api/*` — keep it on for static paths

## Key pitfalls (from the architecture doc)

**Double buffering** — `proxy_buffering off` in `nginx.conf` is mandatory for API paths. If NGINX buffers the body and Pingora also buffers it you pay twice in latency and memory.

**Header bloat** — three hops each add headers. Pingora strips `authorization` before forwarding and `x-internal-service-auth` before returning. Audit headers at each boundary.

**Rate limiter availability** — the current code fails open when Redis is unreachable. Change `Ok(true)` to an explicit `respond_with(session, 503, "Service Unavailable")` in `request_filter` if your threat model requires fail-closed.