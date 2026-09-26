// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use packetcraftr_core::error::{Classification, Kind};

use crate::BoundaryError;
use crate::execution::{Executor, Request};

pub(crate) fn private_policy() -> crate::policy::Policy {
    crate::policy::Policy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..crate::policy::Policy::default()
    }
}

/// Counts executions and shutdowns while optionally failing the `fail_at`-th
/// call, so progressive-output tests share one failure-injection executor
/// across request types. `failure_message` and `failure_code` keep the induced
/// failure workflow-specific.
pub(crate) struct ProgressiveExecutor<I> {
    pub(crate) inner: I,
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) shutdowns: Arc<AtomicUsize>,
    pub(crate) fail_at: Option<usize>,
    pub(crate) failure_message: &'static str,
    pub(crate) failure_code: &'static str,
}

impl<R, I> Executor<R> for ProgressiveExecutor<I>
where
    R: Request,
    I: Executor<R>,
{
    fn execute(&mut self, request: &R) -> Result<R::Execution, BoundaryError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at == Some(call) {
            return Err(BoundaryError::new(
                self.failure_message,
                Classification::new(self.failure_code, Kind::Io, None),
                Vec::new(),
            ));
        }
        let execution = self.inner.execute(request);
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        execution
    }
}
