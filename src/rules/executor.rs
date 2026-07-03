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
pub(crate) enum ExecutorError {
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
pub(crate) struct BoundedExecutor {
    runtime: RuntimeHandleSource,
    capacity_permits: Arc<Semaphore>,
    worker_permits: Arc<Semaphore>,
}

impl BoundedExecutor {
    pub(crate) fn new(
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

    pub(crate) fn new_with_handle(
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

    pub(crate) fn spawn_async<F, Fut>(&self, job: F) -> std::result::Result<(), ExecutorError>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{DestinationRequest, TransmissionRequest};
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{sleep, timeout, Duration};

    #[test]
    fn bounded_executor_without_runtime_reports_runtime_unavailable_on_spawn() {
        let executor = BoundedExecutor::new("test", 1, 1).unwrap();

        let err = executor.spawn_async(|| async {}).unwrap_err();

        assert!(matches!(err, ExecutorError::RuntimeUnavailable(_)));
    }

    #[tokio::test]
    async fn bounded_executor_new_with_handle_spawns_job() {
        let executor = BoundedExecutor::new_with_handle(Handle::current(), 1, 1).unwrap();
        let (done_tx, done_rx) = oneshot::channel();

        executor
            .spawn_async(move || async move {
                done_tx.send(()).unwrap();
            })
            .unwrap();

        timeout(Duration::from_secs(1), done_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn bounded_executor_rejects_when_capacity_is_full() {
        let executor = BoundedExecutor::new_with_handle(Handle::current(), 1, 1).unwrap();
        let (release_tx, release_rx) = oneshot::channel();

        executor
            .spawn_async(move || async move {
                let _ = release_rx.await;
            })
            .unwrap();
        let err = executor.spawn_async(|| async {}).unwrap_err();

        assert!(matches!(err, ExecutorError::QueueFull));
        release_tx.send(()).unwrap();
    }

    #[tokio::test]
    async fn bounded_executor_releases_capacity_after_completion() {
        let executor = BoundedExecutor::new_with_handle(Handle::current(), 1, 1).unwrap();
        let (done_tx, done_rx) = oneshot::channel();

        executor
            .spawn_async(move || async move {
                done_tx.send(()).unwrap();
            })
            .unwrap();
        timeout(Duration::from_secs(1), done_rx)
            .await
            .unwrap()
            .unwrap();

        for _ in 0..20 {
            match executor.spawn_async(|| async {}) {
                Ok(()) => return,
                Err(ExecutorError::QueueFull) => sleep(Duration::from_millis(5)).await,
                Err(err) => panic!("unexpected executor error: {err:?}"),
            }
        }

        panic!("capacity permit was not released");
    }

    #[tokio::test]
    async fn bounded_executor_serializes_jobs_with_single_worker() {
        let executor = BoundedExecutor::new_with_handle(Handle::current(), 1, 2).unwrap();
        let (release_tx, release_rx) = oneshot::channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let first_events = event_tx.clone();

        executor
            .spawn_async(move || async move {
                first_events.send("first-started").unwrap();
                let _ = release_rx.await;
                first_events.send("first-done").unwrap();
            })
            .unwrap();
        executor
            .spawn_async(move || async move {
                event_tx.send("second-started").unwrap();
            })
            .unwrap();

        assert_eq!(
            timeout(Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some("first-started")
        );
        sleep(Duration::from_millis(20)).await;
        assert!(event_rx.try_recv().is_err());

        release_tx.send(()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some("first-done")
        );
        assert_eq!(
            timeout(Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some("second-started")
        );
    }

    #[test]
    fn validate_rule_send_request_accepts_bounded_request() {
        let request = PacketRequest {
            destination: DestinationRequest {
                destination: Some("192.0.2.10".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        validate_rule_send_request("bounded", &request, TrafficPolicy::default()).unwrap();
    }

    #[test]
    fn validate_rule_send_request_rejects_invalid_mode_and_policy_denial() {
        let zero_count = PacketRequest {
            transmit: TransmissionRequest {
                count: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        let public_target = PacketRequest {
            destination: DestinationRequest {
                destination: Some("8.8.8.8".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        for (rule, request) in [("zero", zero_count), ("public", public_target)] {
            let err =
                validate_rule_send_request(rule, &request, TrafficPolicy::default()).unwrap_err();

            assert!(matches!(
                err,
                RuleError::Action(RuleActionError::InvalidSendMode { rule: ref actual })
                    if actual == rule
            ));
        }
    }
}
