// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Mutex, TryLockError};

use crate::Error;
use crate::transmit::{Outbound, Provider, Report};

pub(super) enum Preparation<K, P> {
    Reusable { key: K, packet: P },
    Fallback,
}

pub(super) trait Backend: Send + Sync {
    type Key: Eq + Send;
    type Packet<'a>;
    type Resource: Send;

    /// Checks session context even when the packet requires one-shot fallback.
    fn prepare<'a>(
        &self,
        outbound: Outbound<'a>,
    ) -> Result<Preparation<Self::Key, Self::Packet<'a>>, Error>;
    fn open(&self, packet: &Self::Packet<'_>) -> Result<Option<Self::Resource>, Error>;
    fn send(
        &self,
        resource: &mut Self::Resource,
        packet: Self::Packet<'_>,
    ) -> Result<Report, Error>;
    fn fallback(&self, outbound: Outbound<'_>) -> Result<Report, Error>;
}

struct Cached<K, R> {
    key: K,
    resource: Result<R, Error>,
}

pub(super) struct Bounded<B: Backend> {
    backend: B,
    state: Mutex<Option<Cached<B::Key, B::Resource>>>,
}

impl<B: Backend> Bounded<B> {
    pub(super) fn new(backend: B) -> Self {
        Self {
            backend,
            state: Mutex::new(None),
        }
    }
}

impl<B: Backend> Provider for Bounded<B> {
    fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                return Err(Error::Send {
                    message: "transmission session is unavailable".to_owned(),
                    source: None,
                });
            }
        };
        let Preparation::Reusable { key, packet } = self.backend.prepare(outbound)? else {
            return self.backend.fallback(outbound);
        };
        let cached = match &mut *state {
            Some(cached) if cached.key != key => {
                return self.backend.fallback(outbound);
            }
            Some(cached) => cached,
            empty @ None => {
                let Some(resource) = self.backend.open(&packet)? else {
                    return self.backend.fallback(outbound);
                };
                empty.insert(Cached {
                    key,
                    resource: Ok(resource),
                })
            }
        };
        let resource = cached.resource.as_mut().map_err(|error| error.clone())?;
        let result = self.backend.send(resource, packet);
        if let Err(error) = &result {
            cached.resource = Err(error.clone());
        }
        result
    }
}

#[cfg(test)]
mod tests;
