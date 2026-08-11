// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::system::{DeferredInterface, SystemClient};

pub(super) struct CliTracerouteExecutor {
    pub(super) client: SystemClient,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl packetcraftr::traceroute::Executor for CliTracerouteExecutor {
    fn execute(
        &mut self,
        batch: &packetcraftr::traceroute::Batch,
    ) -> Result<packetcraftr::traceroute::Execution, packetcraftr::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        packetcraftr::ExchangeExecutor::new(&self.client, self.exchange.clone()).execute(batch)
    }
}
