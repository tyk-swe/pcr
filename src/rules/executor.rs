// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::future::Future;
use std::sync::Arc;

use log::{error, warn};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::JoinError;

use crate::domain::policy::{TrafficMode, TrafficPlan, TrafficPolicy};
use crate::domain::request::PacketRequest;
use crate::domain::spec::TransmissionSpec;
use crate::rules::error::{RuleActionError, RuleError};
use crate::util::telemetry;

type Result<T> = std::result::Result<T, RuleError>;

#[derive(Debug)]
pub enum ExecutorError {
    QueueFull,
    Closed,
    RuntimeUnavailable(String),
}

#[derive(Debug, Clone)]
enum RuntimeHandleSource {
    Current,
    Explicit(Handle),
}

impl RuntimeHandleSource {
    fn current_or_deferred() -> Self {
        match Handle::try_current() {
            Ok(handle) => Self::Explicit(handle),
            Err(_) => Self::Current,
        }
    }

    fn resolve(&self) -> std::result::Result<Handle, ExecutorError> {
        match self {
            Self::Explicit(handle) => Ok(handle.clone()),
            Self::Current => current_runtime_handle(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BoundedExecutor {
    runtime: RuntimeHandleSource,
    capacity_permits: Arc<Semaphore>,
    worker_permits: Arc<Semaphore>,
}

impl BoundedExecutor {
    pub fn new(
        name_prefix: &str,
        workers: usize,
        capacity: usize,
    ) -> std::result::Result<Self, RuleError> {
        let _ = name_prefix;
        Ok(Self::from_runtime_source(
            RuntimeHandleSource::current_or_deferred(),
            workers,
            capacity,
        ))
    }

    pub fn new_with_handle(
        handle: Handle,
        workers: usize,
        capacity: usize,
    ) -> std::result::Result<Self, RuleError> {
        Ok(Self::from_runtime_source(
            RuntimeHandleSource::Explicit(handle),
            workers,
            capacity,
        ))
    }

    fn from_runtime_source(runtime: RuntimeHandleSource, workers: usize, capacity: usize) -> Self {
        let capacity_permits = Arc::new(Semaphore::new(capacity));
        let worker_permits = Arc::new(Semaphore::new(workers.max(1)));

        Self {
            runtime,
            capacity_permits,
            worker_permits,
        }
    }

    pub fn spawn_async<F, Fut>(&self, job: F) -> std::result::Result<(), ExecutorError>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let runtime = self.runtime.resolve()?;
        let capacity_permit = self
            .capacity_permits
            .clone()
            .try_acquire_owned()
            .map_err(|err| match err {
                TryAcquireError::NoPermits => ExecutorError::QueueFull,
                TryAcquireError::Closed => ExecutorError::Closed,
            })?;
        let worker_permits = Arc::clone(&self.worker_permits);

        let task = runtime.spawn(async move {
            let _capacity_permit = capacity_permit;
            let Ok(worker_permit) = worker_permits.acquire_owned().await else {
                warn!("bounded executor worker semaphore closed before task started");
                return;
            };
            let _worker_permit = worker_permit;
            job().await;
        });

        runtime.spawn(async move {
            if let Err(join_err) = task.await {
                log_join_error(join_err);
            }
        });

        Ok(())
    }
}

fn log_join_error(join_err: JoinError) {
    if join_err.is_cancelled() {
        warn!("bounded executor task was cancelled before completion");
    } else if join_err.is_panic() {
        error!("bounded executor task panicked");
    }
}

fn current_runtime_handle() -> std::result::Result<Handle, ExecutorError> {
    match Handle::try_current() {
        Ok(handle) => Ok(handle),
        Err(err) => Err(ExecutorError::RuntimeUnavailable(format!(
            "rule executor requires an application Tokio runtime: {err}"
        ))),
    }
}

pub(crate) fn validate_rule_send_request(
    rule_name: &str,
    request: &PacketRequest,
    policy: TrafficPolicy,
) -> Result<()> {
    TransmissionSpec::from_request(&request.transmit).map_err(|source| {
        warn!("rule '{}' send action rejected: {}", rule_name, source);
        telemetry::record_rule_executor_drop("send", "invalid_send_mode");
        RuleActionError::InvalidSendMode {
            rule: rule_name.to_string(),
        }
    })?;

    let plan = TrafficPlan::from_packet_request(request, TrafficMode::RuleSend, &policy);
    policy.authorize(&plan).map_err(|source| {
        warn!("rule '{}' send action rejected: {}", rule_name, source);
        telemetry::record_rule_executor_drop("send", "policy_rejected");
        RuleActionError::InvalidSendMode {
            rule: rule_name.to_string(),
        }
    })?;

    Ok(())
}
