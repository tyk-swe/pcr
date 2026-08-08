// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Shared client and exchange options for live workflow executors.
pub struct ExchangeExecutor<'a, R, N, I> {
    pub(crate) client: &'a crate::Client<R, N, I>,
    pub(crate) options: crate::exchange::Options,
}

impl<'a, R, N, I> ExchangeExecutor<'a, R, N, I> {
    pub fn new(client: &'a crate::Client<R, N, I>, options: crate::exchange::Options) -> Self {
        Self { client, options }
    }
}
