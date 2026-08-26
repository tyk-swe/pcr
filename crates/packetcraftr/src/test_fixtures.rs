// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Seam doubles shared by the workflow unit tests.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::BoundaryError;
use crate::authorization::Operation;
use crate::clock::Clock;
use crate::target::{Authorized, Authorizer, Error as TargetError, Hostname, Resolver, Target};

/// A clock that never actually waits.
#[derive(Default)]
pub(crate) struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A clock that records the delays it was asked to wait for.
#[derive(Default)]
pub(crate) struct RecordingClock {
    pub(crate) delays: Vec<Duration>,
}

impl Clock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.delays.push(delay);
        Ok(())
    }
}

/// An authorizer that approves every operation and hands back fixed addresses.
pub(crate) struct AddressListAuthorizer {
    pub(crate) addresses: Vec<IpAddr>,
}

impl Authorizer for AddressListAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            addresses: self.addresses.clone(),
        })
    }

    fn authorize_operation(&mut self, _operation: Operation<'_>) -> Result<(), BoundaryError> {
        Ok(())
    }
}

/// A resolver that replays a queued script of answers and counts its calls.
pub(crate) struct ScriptedResolver {
    pub(crate) calls: Arc<AtomicUsize>,
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl ScriptedResolver {
    pub(crate) fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }
}

impl Resolver for ScriptedResolver {
    fn resolve(&self, _hostname: &Hostname, _limit: usize) -> Result<Vec<IpAddr>, TargetError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .expect("resolver lock")
            .pop_front()
            .expect("scripted resolver answer"))
    }
}
