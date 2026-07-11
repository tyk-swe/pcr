// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::error::Error;
use std::time::Duration;

/// Injectable delay seam shared by rate-limited and replay workflows.
pub trait Clock {
    type Error: Error + Send + Sync + 'static;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error>;
}

/// Production wall-clock implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct System;

impl Clock for System {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        std::thread::sleep(delay);
        Ok(())
    }
}
