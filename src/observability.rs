
use crate::ctx::RequestCtx;
use rand::Rng;
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

/// Inject W3C trace context headers.
///
/// traceparent format: 00-<32 hex trace-id>-<16 hex parent-id>-01
///
/// The trace_id is a UUID. We strip its dashes to get a valid 32-char lowercase
/// hex trace-id. The parent-id is a fresh random 64-bit value encoded as 16 hex
/// chars — per spec it must differ from the trace-id and be random per hop.
pub fn inject_trace_headers(
    headers: &mut pingora_http::RequestHeader,
    trace_id: &str,
) -> anyhow::Result<()> {
    // UUID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" → 32 hex chars, no dashes
    let tid = trace_id.replace('-', "");

    // Random 64-bit parent-id, fresh per hop
    let pid: u64 = rand::thread_rng().gen();
    let pid_hex = format!("{pid:016x}");

    let traceparent = format!("00-{tid}-{pid_hex}-01");
    headers.insert_header("traceparent", &traceparent)?;
    headers.insert_header("x-trace-id", trace_id)?;
    Ok(())
}