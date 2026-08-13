// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::system::{DeferredInterface, SystemClient};

pub(super) struct CliScanExecutor {
    pub(super) client: SystemClient,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl packetcraftr::scan::Executor for CliScanExecutor {
    fn execute(
        &mut self,
        batch: &packetcraftr::scan::Batch,
    ) -> Result<packetcraftr::scan::Execution, packetcraftr::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        packetcraftr::ExchangeExecutor::new(&self.client, self.exchange.clone()).execute(batch)
    }
}
