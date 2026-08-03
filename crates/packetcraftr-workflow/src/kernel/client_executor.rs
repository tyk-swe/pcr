// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::marker::PhantomData;

pub struct Dns;
pub struct Fuzz;
pub struct Scan;
pub struct Traceroute;

/// Shared client and exchange options for live workflow executors.
pub struct ClientExecutor<'a, R, N, I, W> {
    pub(crate) client: &'a packetcraftr_client::Client<R, N, I>,
    pub(crate) options: packetcraftr_client::exchange::Options,
    workflow: PhantomData<W>,
}

impl<'a, R, N, I, W> ClientExecutor<'a, R, N, I, W> {
    pub fn new(
        client: &'a packetcraftr_client::Client<R, N, I>,
        options: packetcraftr_client::exchange::Options,
    ) -> Self {
        Self {
            client,
            options,
            workflow: PhantomData,
        }
    }
}
