// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetcraftr::clock::Clock;
use packetcraftr_core::budget::Deadline;

#[derive(Clone)]
pub(crate) struct VirtualClock {
    now: Arc<Mutex<Instant>>,
    delays: Arc<Mutex<Vec<Duration>>>,
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self {
            now: Arc::new(Mutex::new(Instant::now())),
            delays: Arc::default(),
        }
    }
}

impl VirtualClock {
    pub(crate) fn advance(&self, by: Duration) {
        *self.now.lock().expect("clock lock") += by;
    }

    pub(crate) fn delays(&self) -> Vec<Duration> {
        self.delays.lock().expect("delays lock").clone()
    }
}

impl Clock for VirtualClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        *self.now.lock().expect("clock lock")
    }

    fn sleep(&self, delay: Duration, _deadline: &Deadline) -> Result<(), Self::Error> {
        self.advance(delay);
        self.delays.lock().expect("delays lock").push(delay);
        Ok(())
    }
}
