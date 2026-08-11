// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::core;

use crate::errors::CliError;
use crate::system::{DeferredInterface, system_client};

pub(super) struct CliFuzzExecutor {
    pub(super) registry: Arc<core::registry::Registry>,
    pub(super) policy: packetcraftr::policy::Policy,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl packetcraftr::fuzz::Executor for CliFuzzExecutor {
    fn execute(
        &mut self,
        case: &packetcraftr::fuzz::ExecutionCase,
        timeout: Duration,
    ) -> Result<packetcraftr::fuzz::Execution, packetcraftr::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        packetcraftr::ExchangeExecutor::new(&client, self.exchange.clone()).execute(case, timeout)
    }
}
