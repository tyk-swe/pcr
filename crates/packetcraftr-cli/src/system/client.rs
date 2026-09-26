// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::{ProviderSet, SystemProviders};
use packetcraftr_core as core;

pub(crate) type Client = packetcraftr::Client<SystemProviders>;

/// The one client a command runs its workflows on: every system provider,
/// the installed cancellation signal, and one event runtime registered for
/// the `resources` report under `runtime`.
pub(crate) fn client(
    registry: Arc<core::registry::Registry>,
    policy: impl Into<Arc<packetcraftr::policy::Policy>>,
    runtime: &'static str,
) -> Client {
    Client::new(registry, policy, ProviderSet::system())
        .with_runtime(crate::resources::runtime(
            runtime,
            packetcraftr::progress::MAX_WORKER_CAPACITY,
        ))
        .with_cancellation(crate::cancellation::signal().clone())
}
