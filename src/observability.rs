use crate::ctx::RequestCtx;
use tracing::{error, info, warn};

pub fn log_request(ctx: &RequestCtx, status: u16, path: &str, method: &str) {
    let elapsed = ctx.elapsed_ms();
    let sub     = ctx.user_id().unwrap_or("-");

    if ctx.rate_limited {
        warn!(
            trace_id   = %ctx.trace_id,
            sub        = %sub,
            path       = %path,
            method     = %method,
            status     = %status,
            latency_ms = %elapsed,
            "request rate-limited"
        );
        return;
    }

    if let Some(code) = &ctx.auth_error {
        warn!(
            trace_id   = %ctx.trace_id,
            error_code = %code,
            path       = %path,
            method     = %method,
            status     = %status,
            latency_ms = %elapsed,
            "request rejected: auth error"
        );
        return;
    }

    if status >= 500 {
        error!(
            trace_id   = %ctx.trace_id,
            sub        = %sub,
            upstream   = ?ctx.upstream_addr,
            path       = %path,
            method     = %method,
            status     = %status,
            latency_ms = %elapsed,
            "upstream error"
        );
    } else {
        info!(
            trace_id   = %ctx.trace_id,
            sub        = %sub,
            upstream   = ?ctx.upstream_addr,
            path       = %path,
            method     = %method,
            status     = %status,
            latency_ms = %elapsed,
            "request complete"
        );
    }
}

/// Inject W3C `traceparent` and `x-trace-id` headers.
///
/// W3C format: `00-<trace-id>-<parent-id>-<flags>`
///   trace-id   must be 32 lowercase hex chars
///   parent-id  must be 16 lowercase hex chars
///
/// The UUID-based `trace_id` is 36 chars with dashes; we strip the dashes to
/// produce exactly 32 hex chars.  The parent-id is taken as the first 16 chars
/// of that hex string.
pub fn inject_trace_headers(
    headers: &mut pingora_http::RequestHeader,
    trace_id: &str,
) -> anyhow::Result<()> {
    // Strip UUID dashes: "550e8400-e29b-41d4-a716-446655440000" → 32 hex chars
    let trace_hex: String = trace_id.chars().filter(|c| *c != '-').collect();

    // W3C requires exactly 32 hex chars for trace-id and 16 for parent-id.
    // Pad or truncate defensively (UUIDs are always 32 hex chars after strip).
    let trace_hex = if trace_hex.len() >= 32 {
        trace_hex[..32].to_string()
    } else {
        format!("{:0<32}", trace_hex)
    };
    let parent_id = &trace_hex[..16];

    let traceparent = format!("00-{trace_hex}-{parent_id}-01");
    headers.insert_header("traceparent", &traceparent)?;
    headers.insert_header("x-trace-id", trace_id)?;
    Ok(())
}
