// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The two endpoints of an HTTP/2 connection and paired per-side state.

use std::ops::{Index, IndexMut};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Side {
    Client,
    Server,
}

impl Side {
    pub(crate) const BOTH: [Self; 2] = [Self::Client, Self::Server];

    pub(crate) fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }

    pub(crate) fn initiator_of(stream_id: u32) -> Self {
        if stream_id.is_multiple_of(2) {
            Self::Server
        } else {
            Self::Client
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PerSide<T> {
    client: T,
    server: T,
}

impl<T> PerSide<T> {
    pub(crate) fn new(client: T, server: T) -> Self {
        Self { client, server }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        [&self.client, &self.server].into_iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        [&mut self.client, &mut self.server].into_iter()
    }

    pub(crate) fn all(&self, predicate: impl Fn(&T) -> bool) -> bool {
        self.iter().all(predicate)
    }
}

impl<T> Index<Side> for PerSide<T> {
    type Output = T;
    fn index(&self, side: Side) -> &T {
        match side {
            Side::Client => &self.client,
            Side::Server => &self.server,
        }
    }
}

impl<T> IndexMut<Side> for PerSide<T> {
    fn index_mut(&mut self, side: Side) -> &mut T {
        match side {
            Side::Client => &mut self.client,
            Side::Server => &mut self.server,
        }
    }
}
