// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Staged preparation: the one path from an expanded packet to the wire.
//!
//! Every live packet passes the same stages in the same order:
//!
//! 1. the operation's count-only budget, before any provider call;
//! 2. passive route planning with destination and source authorization;
//! 3. the preliminary build, MTU, packet and wire authorization;
//! 4. the cumulative wire-byte budget;
//! 5. materialization, which may emit neighbor discovery traffic;
//! 6. the final endpoint and bytes authorization;
//! 7. transmission and [`crate::evidence::SentPacket`] construction.

mod admission;
mod construction;
mod discovery;
mod materialize;
mod streaming;

pub(crate) use admission::{Admitted, AdmittedCost, Admitting, AuthorizedRoute, RetainedAdmission};
pub(crate) use construction::{PreparedPacket, exact_bytes};
pub(crate) use discovery::authorize_neighbor_request;
pub(crate) use streaming::Streaming;

use admission::Budget;
use construction::Materializer;

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::Builder;
use packetcraftr_core::packet::Packet;

use crate::clock::Clock;
use crate::deadline::ensure_preparation_deadline;
use crate::engine::operation::Operation as Execution;
use crate::policy::Policy;
use crate::providers::{PacketProviders, TransmitProviders};
pub(crate) use crate::route;
use crate::send::options::Options;
use crate::{Client, Error};

struct Stages<'c, P, K> {
    client: &'c Client<P, K>,
    policy: Policy,
    operation: Execution,
    builder: Builder,
    options: &'c Options,
    deadline: Option<&'c Deadline>,
    admission: Arc<()>,
}

impl<'c, P: TransmitProviders, K: Clock> Stages<'c, P, K> {
    fn new(
        client: &'c Client<P, K>,
        options: &'c Options,
        deadline: Option<&'c Deadline>,
        operation: &Execution,
    ) -> Self {
        Self {
            client,
            policy: operation.policy(&client.policy),
            operation: operation.clone(),
            builder: Builder::new(operation.registry.clone()),
            options,
            deadline,
            admission: Arc::new(()),
        }
    }

    fn materializer(&self) -> Materializer<'_> {
        Materializer {
            builder: &self.builder,
            options: &self.options.build,
        }
    }

    fn within<T>(&self, limit: std::time::Duration, lookup: impl FnOnce(&Deadline) -> T) -> T {
        match self.deadline {
            Some(deadline) => lookup(deadline),
            None => lookup(&self.operation.deadline(self.client, limit)),
        }
    }

    fn check(&self) -> Result<(), Error> {
        self.client.check_cancelled()?;
        self.operation.deadline.check_cancelled()?;
        ensure_preparation_deadline(&self.operation.deadline)?;
        if let Some(deadline) = self.deadline {
            deadline.check_cancelled()?;
            ensure_preparation_deadline(deadline)?;
        }
        Ok(())
    }
}

fn changed_preparation(message: &str) -> Error {
    Error::PacketMaterialization {
        layer: 0,
        field: "preparation",
        message: message.to_owned(),
        source: None,
    }
}

#[cfg(test)]
mod work {
    std::thread_local! {
        static COUNTS: std::cell::Cell<(usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0)) };
    }
    pub(super) fn build() {
        COUNTS.with(|counts| {
            let (builds, preparations, reused) = counts.get();
            counts.set((builds + 1, preparations, reused));
        });
    }
    pub(super) fn prepare() {
        COUNTS.with(|counts| {
            let (builds, preparations, reused) = counts.get();
            counts.set((builds, preparations + 1, reused));
        });
    }
    pub(super) fn reuse() {
        COUNTS.with(|counts| {
            let (builds, preparations, reused) = counts.get();
            counts.set((builds, preparations, reused + 1));
        });
    }
    pub(super) fn take() -> (usize, usize, usize) {
        COUNTS.replace((0, 0, 0))
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug)]
pub(crate) enum RebuildError {
    Changed { admitted: usize },
    Preparation(Error),
}

impl From<Error> for RebuildError {
    fn from(source: Error) -> Self {
        Self::Preparation(source)
    }
}

impl<P: TransmitProviders, K: Clock> Client<P, K> {
    pub(crate) fn admitting_in<'c>(
        &'c self,
        options: &'c Options,
        packets: u64,
        deadline: &'c Deadline,
        operation: &Execution,
    ) -> Result<Admitting<'c, P, K>, Error> {
        let (stages, budget) = self.open_stages(options, packets, Some(deadline), operation)?;
        Ok(Admitting { stages, budget })
    }

    pub(crate) fn streaming_in<'c>(
        &'c self,
        options: &'c Options,
        packets: u64,
        operation: &Execution,
    ) -> Result<Streaming<'c, P, K>, Error> {
        let (stages, budget) = self.open_stages(options, packets, None, operation)?;
        Ok(Streaming { stages, budget })
    }

    fn open_stages<'c>(
        &'c self,
        options: &'c Options,
        packets: u64,
        deadline: Option<&'c Deadline>,
        operation: &Execution,
    ) -> Result<(Stages<'c, P, K>, Budget), Error> {
        let stages = Stages::new(self, options, deadline, operation);
        stages.check()?;
        let budget = Budget::open(&stages.policy, packets)?;
        Ok((stages, budget))
    }
}
