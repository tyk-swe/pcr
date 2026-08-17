// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::system::{Client, DeferredInterface};

pub(super) struct Executor {
    pub(super) client: Client,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl packetcraftr::scan::Executor for Executor {
    fn execute(
        &mut self,
        batch: &packetcraftr::scan::Batch,
    ) -> Result<packetcraftr::scan::Execution, packetcraftr::BoundaryError> {
        self.interface
            .apply(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        packetcraftr::ExchangeExecutor::new(&self.client, self.exchange.clone()).execute(batch)
    }
}
