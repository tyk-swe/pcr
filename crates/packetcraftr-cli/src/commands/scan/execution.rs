// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::core;

use crate::errors::CliError;
use crate::system::{DeferredInterface, system_client};

pub(super) struct CliScanExecutor {
    pub(super) registry: Arc<core::registry::Registry>,
    pub(super) policy: packetcraftr::policy::Policy,
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
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        packetcraftr::ExchangeExecutor::new(&client, self.exchange.clone()).execute(batch)
    }
}
