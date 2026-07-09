// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;

use anyhow::Result;
use log::{info, warn};
use tokio::runtime::Handle;

use crate::cli::PacketcraftArgs;
use crate::engine::config::EngineConfig;
use crate::util;

#[derive(Debug, Default)]
pub(crate) struct AppTelemetry {
    prometheus_handle: Option<util::telemetry::PrometheusExporterHandle>,
}

impl AppTelemetry {
    pub(crate) fn validate_requested_options(
        args: &PacketcraftArgs,
        config: &EngineConfig,
    ) -> Result<()> {
        if let Some(bind) = config.prometheus_bind.as_deref() {
            validate_prometheus_bind(bind, allow_public_metrics(args))?;
        }
        Ok(())
    }

    pub(crate) fn start_if_configured(
        args: &PacketcraftArgs,
        config: &EngineConfig,
        runtime_handle: &Handle,
    ) -> Result<Self> {
        let prometheus_handle = if let Some(bind) = config.prometheus_bind.as_deref() {
            validate_prometheus_bind(bind, allow_public_metrics(args))?;
            let handle = util::telemetry::spawn_prometheus_exporter(runtime_handle, bind)?;
            info!(
                "Prometheus exporter bound to http://{}/metrics",
                handle.addr
            );
            Some(handle)
        } else {
            None
        };

        Ok(Self { prometheus_handle })
    }

    pub(crate) async fn shutdown(mut self) {
        if let Some(handle) = self.prometheus_handle.take() {
            let _ = handle.shutdown_tx.send(());

            if let Err(err) = handle.join_handle.await {
                warn!("prometheus exporter task terminated with error: {err}");
            }
        }
    }
}

pub(crate) fn validate_prometheus_bind(
    bind: &str,
    allow_public_metrics: bool,
) -> Result<SocketAddr> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prometheus bind address: {}", e))?;

    if !addr.ip().is_loopback() && !allow_public_metrics {
        return Err(anyhow::anyhow!(
            "prometheus bind address '{}' is not a loopback address. Use --allow-public-metrics to allow public binding.",
            bind
        ));
    }

    Ok(addr)
}

fn allow_public_metrics(args: &PacketcraftArgs) -> bool {
    args.observability.allow_public_metrics.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[test]
    fn prometheus_bind_validation_accepts_loopback() {
        let addr = validate_prometheus_bind("127.0.0.1:9090", false).unwrap();

        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn prometheus_bind_validation_rejects_public_without_opt_in() {
        let err = validate_prometheus_bind("0.0.0.0:9090", false).unwrap_err();

        assert!(err.to_string().contains("not a loopback address"));
    }

    #[test]
    fn prometheus_bind_validation_rejects_invalid_address() {
        let err = validate_prometheus_bind("127.0.0.1", false).unwrap_err();

        assert!(err.to_string().contains("invalid prometheus bind address"));
    }

    #[test]
    fn prometheus_bind_validation_accepts_public_with_opt_in() {
        let addr = validate_prometheus_bind("0.0.0.0:9090", true).unwrap();

        assert!(!addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn shutdown_waits_for_exporter_task_completion() {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            let _ = done_tx.send(());
        });

        AppTelemetry {
            prometheus_handle: Some(util::telemetry::PrometheusExporterHandle {
                addr: "127.0.0.1:0".parse().unwrap(),
                shutdown_tx,
                join_handle,
            }),
        }
        .shutdown()
        .await;

        done_rx.await.unwrap();
    }
}
