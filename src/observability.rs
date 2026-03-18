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

pub fn inject_trace_headers(
    headers: &mut pingora_http::RequestHeader,
    trace_id: &str,
) -> anyhow::Result<()> {
    let parent_id   = &trace_id[..16.min(trace_id.len())];
    let traceparent = format!("00-{trace_id}-{parent_id}-01");
    headers.insert_header("traceparent", &traceparent)?;
    headers.insert_header("x-trace-id", trace_id)?;
    Ok(())
}
