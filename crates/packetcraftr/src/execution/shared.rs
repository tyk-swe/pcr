// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex, PoisonError};

pub(crate) struct Shared<T>(Arc<Mutex<T>>);

impl<T> Shared<T> {
    pub(crate) fn update<R>(&self, update: impl FnOnce(&mut T) -> R) -> R {
        update(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl<T: Default> Shared<T> {
    /// Takes the state, leaving the default behind. The worker may drop its
    /// clone after the run returns, so the state is taken rather than
    /// unwrapped from the last reference.
    pub(crate) fn take(&self) -> T {
        self.update(std::mem::take)
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(T::default())))
    }
}
