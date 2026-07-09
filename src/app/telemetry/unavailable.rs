// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;
use tokio::runtime::Handle;

use crate::cli::PacketcraftArgs;
use crate::engine::config::EngineConfig;

#[derive(Debug, Default)]
pub(crate) struct AppTelemetry;

impl AppTelemetry {
    pub(crate) fn validate_requested_options(
        args: &PacketcraftArgs,
        config: &EngineConfig,
    ) -> Result<()> {
        if config.prometheus_bind.is_some()
            || args.observability.allow_public_metrics.unwrap_or(false)
            || one_shot_metrics_options_requested(args)
        {
            return Err(anyhow::anyhow!(
                "metrics options require packetcraftr to be built with the 'metrics' feature"
            ));
        }
        Ok(())
    }

    pub(crate) fn start_if_configured(
        _args: &PacketcraftArgs,
        _config: &EngineConfig,
        _runtime_handle: &Handle,
    ) -> Result<Self> {
        Ok(Self)
    }

    pub(crate) async fn shutdown(self) {}
}

fn one_shot_metrics_options_requested(args: &PacketcraftArgs) -> bool {
    args.one_shot_options()
        .map(|oneshot| oneshot.logging.metrics_json.is_some())
        .unwrap_or(false)
}
