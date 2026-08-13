// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::system::{DeferredInterface, SystemClient};

pub(super) struct CliDnsExecutor {
    pub(super) client: SystemClient,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl packetcraftr::dns::Executor for CliDnsExecutor {
    fn execute(
        &mut self,
        exchange: &packetcraftr::dns::Exchange,
    ) -> Result<packetcraftr::dns::Execution, packetcraftr::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        packetcraftr::ExchangeExecutor::new(&self.client, self.exchange.clone()).execute(exchange)
    }
}
