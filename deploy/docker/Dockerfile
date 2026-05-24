# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.94.0 AS builder

# Install C build tools required by native deps:
#   cmake        — libz-ng-sys (zstd compression in pingora)
#   gcc/make     — general C crates
#   pkg-config   — openssl-sys, libssl-dev
#   libssl-dev   — TLS support
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    gcc \
    make \
    pkg-config \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies before copying source.
# We need both main.rs (binary entry point) and lib.rs (library crate) as stubs
# otherwise Cargo skips compiling lib dependencies, breaking the real build cache.
COPY Cargo.toml ./
RUN mkdir src \
 && echo "fn main() {}" > src/main.rs \
 && echo "" > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Build the real binary
COPY src ./src
RUN cargo build --release

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 1001 --no-create-home appuser

WORKDIR /app
COPY --from=builder /app/target/release/proxy /app/proxy
COPY config ./config

USER appuser

EXPOSE 6191

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:6191/healthz || exit 1

ENTRYPOINT ["/app/proxy"]
