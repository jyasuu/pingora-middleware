use pingora_middleware::filters::ProxyMiddleware;
use pingora_middleware::loadbalancer::build_upstream;
use pingora_middleware::oauth2::OAuth2Service;

use anyhow::Result;
use pingora::prelude::*;
use pingora_load_balancing::{health_check, selection::RoundRobin, LoadBalancer};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .compact()
        .init();

    // Bootstrap OAuth2 service (fetches JWKS / discovery doc synchronously)
    let oauth2 = Arc::new(
        tokio::runtime::Runtime::new()?
            .block_on(OAuth2Service::from_env())?,
    );

    let mut server = Server::new(Some(Opt::default()))?;
    server.bootstrap();

    // Spawn background JWKS refresh loop as a Pingora background service
    let oauth2_bg = Arc::clone(&oauth2);
    let jwks_refresher = background_service("jwks-refresh", JwksRefresher(oauth2_bg));
    server.add_service(jwks_refresher);

    // Build upstream load balancer
    let mut upstream = LoadBalancer::<RoundRobin>::try_from_iter(build_upstream(&[
        "intranet-service-1:8080",
        "intranet-service-2:8080",
        "intranet-service-3:8080",
    ]))?;
    let hc = health_check::TcpHealthCheck::new();
    upstream.set_health_check(hc);
    upstream.update_frequency = Some(std::time::Duration::from_secs(5));

    let background = background_service("upstream-health-check", upstream);
    let upstream_arc: Arc<LoadBalancer<RoundRobin>> = background.task();
    server.add_service(background);

    let middleware = ProxyMiddleware::new(upstream_arc, oauth2);
    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, middleware);
    proxy.add_tcp("0.0.0.0:6191");
    server.add_service(proxy);

    info!("Pingora middleware starting on 0.0.0.0:6191");
    server.run_forever();
}

// ── JWKS refresh background service ──────────────────────────────────────────

struct JwksRefresher(Arc<OAuth2Service>);

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for JwksRefresher {
    async fn start(&self, _shutdown: pingora::server::ShutdownWatch) {
        self.0.clone().run_jwks_refresh_loop().await;
    }
}
