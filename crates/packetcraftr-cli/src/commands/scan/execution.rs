// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::{client, packet, workflow};

use crate::errors::CliError;
use crate::system::{DeferredInterface, system_client};

pub(super) struct CliScanExecutor {
    pub(super) registry: Arc<packet::registry::Registry>,
    pub(super) policy: client::policy::Policy,
    pub(super) exchange: client::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl workflow::scan::Executor for CliScanExecutor {
    fn execute(
        &mut self,
        batch: &workflow::scan::Batch,
    ) -> Result<workflow::scan::Execution, workflow::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        workflow::scan::ClientExecutor::new(&client, self.exchange.clone()).execute(batch)
    }
}
