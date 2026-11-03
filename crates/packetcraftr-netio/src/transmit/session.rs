// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Mutex, TryLockError};

use super::{Error, Outbound, Provider, Report};

pub(crate) trait Backend: Send + Sync {
    type Key: Eq + Send;
    type Resource: Send;

    fn key(&self, outbound: Outbound<'_>) -> Result<Option<Self::Key>, Error>;
    fn open(&self, outbound: Outbound<'_>) -> Result<Option<Self::Resource>, Error>;
    fn send(&self, resource: &mut Self::Resource, outbound: Outbound<'_>) -> Result<Report, Error>;
    fn fallback(&self, outbound: Outbound<'_>) -> Result<Report, Error>;
}

enum State<K, R> {
    Empty,
    Ready(K, R),
    Failed(K, Error),
}

pub(crate) struct Bounded<B: Backend> {
    backend: B,
    state: Mutex<State<B::Key, B::Resource>>,
}

impl<B: Backend> Bounded<B> {
    pub(crate) fn new(backend: B) -> Self {
        Self {
            backend,
            state: Mutex::new(State::Empty),
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
        let Some(key) = self.backend.key(outbound)? else {
            return self.backend.fallback(outbound);
        };
        match &*state {
            State::Ready(existing, _) | State::Failed(existing, _) if *existing != key => {
                return self.backend.fallback(outbound);
            }
            State::Failed(_, error) => return Err(error.clone()),
            State::Empty | State::Ready(_, _) => {}
        }
        if matches!(*state, State::Empty) {
            let Some(resource) = self.backend.open(outbound)? else {
                return self.backend.fallback(outbound);
            };
            *state = State::Ready(key, resource);
        }
        let State::Ready(_, resource) = &mut *state else {
            unreachable!()
        };
        let result = self.backend.send(resource, outbound);
        if let Err(error) = &result {
            let old = std::mem::replace(&mut *state, State::Empty);
            let State::Ready(key, _) = old else {
                unreachable!()
            };
            *state = State::Failed(key, error.clone());
        }
        result
    }
}
