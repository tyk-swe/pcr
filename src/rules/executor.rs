// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::future::Future;
use std::sync::Arc;

use log::{error, info, warn};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::JoinError;

use crate::engine::policy::{TrafficMode, TrafficPlan, TrafficPolicy};
use crate::engine::request::{PacketRequest, TransportProtocolRequest};
use crate::engine::send::PacketSendService;
use crate::engine::spec::TransmissionSpec;
use crate::rules::config::{
    RuleExecutorConfig, RULE_SEND_EXECUTOR_QUEUE_CAPACITY, RULE_SEND_EXECUTOR_WORKERS,
};
use crate::rules::error::{RuleActionError, RuleError};
use crate::rules::model::PacketContext;
use crate::rules::template::{apply_template, render_option};
use crate::util::telemetry;

type Result<T> = std::result::Result<T, RuleError>;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_support;

#[derive(Debug)]
pub enum ExecutorError {
    QueueFull,
    Closed,
    #[cfg_attr(test, allow(dead_code))]
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

    #[cfg(test)]
    pub fn spawn<F>(&self, job: F) -> std::result::Result<(), ExecutorError>
    where
        F: FnOnce() + Send + 'static,
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
        let blocking_runtime = runtime.clone();

        let task = runtime.spawn(async move {
            let _capacity_permit = capacity_permit;
            let Ok(worker_permit) = worker_permits.acquire_owned().await else {
                warn!("bounded executor worker semaphore closed before task started");
                return;
            };
            let _worker_permit = worker_permit;
            if let Err(join_err) = blocking_runtime.spawn_blocking(job).await {
                log_join_error(join_err);
            }
        });

        runtime.spawn(async move {
            if let Err(join_err) = task.await {
                log_join_error(join_err);
            }
        });

        Ok(())
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
        Err(err) => {
            #[cfg(test)]
            {
                let _ = err;
                Ok(test_support::runtime_handle())
            }
            #[cfg(not(test))]
            {
                Err(ExecutorError::RuntimeUnavailable(format!(
                    "rule executor requires an application Tokio runtime: {err}"
                )))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleSendTemplate {
    request: PacketRequest,
}

impl RuleSendTemplate {
    pub fn new(request: PacketRequest) -> Self {
        Self { request }
    }

    pub fn render(&self, packet: Option<&PacketContext>) -> PacketRequest {
        let mut request = self.request.clone();
        render_option(&mut request.destination.destination, packet);
        render_option(&mut request.destination.destination_ip, packet);
        render_option(&mut request.destination.interface, packet);
        render_option(&mut request.layer2.source_mac, packet);
        render_option(&mut request.layer2.destination_mac, packet);
        render_option(&mut request.layer2.ethertype, packet);
        render_option(&mut request.ip.source_ip, packet);
        render_option(&mut request.ip.destination_ip, packet);
        render_vec(&mut request.ipv6.extensions, packet);
        render_option(&mut request.payload.data, packet);
        render_option(&mut request.payload.data_hex, packet);
        render_option(&mut request.payload.data_file, packet);
        render_option(&mut request.payload.dns_query, packet);
        render_option(&mut request.payload.dns_type, packet);
        render_option(&mut request.payload.http_method, packet);
        render_option(&mut request.payload.http_path, packet);
        render_option(&mut request.payload.http_host, packet);
        render_option(&mut request.payload.tls_client_hello, packet);
        render_option(&mut request.transmit.interval, packet);
        render_option(&mut request.listener.filter, packet);
        render_option(&mut request.listener.capture_file, packet);
        render_option(&mut request.rules_file, packet);
        render_option(&mut request.logging.log_file, packet);
        render_option(&mut request.logging.pcap_write, packet);
        render_option(&mut request.logging.metrics_json, packet);
        render_option(&mut request.logging.prometheus_bind, packet);

        if let Some(TransportProtocolRequest::Tcp(tcp)) = request.transport.command.as_mut() {
            render_option(&mut tcp.flags, packet);
            render_option(&mut tcp.timestamps, packet);
            render_option(&mut tcp.options_hex, packet);
        }

        request
    }
}

fn render_vec(fields: &mut [String], packet: Option<&PacketContext>) {
    for field in fields {
        *field = apply_template(field, packet);
    }
}

#[derive(Debug, Clone)]
pub struct RuleSendExecutor {
    executor: Arc<BoundedExecutor>,
    traffic_policy: TrafficPolicy,
    dry_run: bool,
}

fn validate_rule_send_mode(
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

impl RuleSendExecutor {
    pub fn new() -> std::result::Result<Self, RuleError> {
        Self::new_configured(RuleExecutorConfig {
            workers: RULE_SEND_EXECUTOR_WORKERS,
            queue_capacity: RULE_SEND_EXECUTOR_QUEUE_CAPACITY,
            traffic_policy: TrafficPolicy::default(),
            dry_run: false,
        })
    }

    pub fn new_configured(config: RuleExecutorConfig) -> std::result::Result<Self, RuleError> {
        Self::new_configured_with_runtime_source(config, RuntimeHandleSource::current_or_deferred())
    }

    pub fn new_with_runtime_handle(handle: Handle) -> std::result::Result<Self, RuleError> {
        Self::new_configured_with_runtime_handle(
            RuleExecutorConfig {
                workers: RULE_SEND_EXECUTOR_WORKERS,
                queue_capacity: RULE_SEND_EXECUTOR_QUEUE_CAPACITY,
                traffic_policy: TrafficPolicy::default(),
                dry_run: false,
            },
            handle,
        )
    }

    pub fn new_configured_with_runtime_handle(
        config: RuleExecutorConfig,
        handle: Handle,
    ) -> std::result::Result<Self, RuleError> {
        Self::new_configured_with_runtime_source(config, RuntimeHandleSource::Explicit(handle))
    }

    fn new_configured_with_runtime_source(
        config: RuleExecutorConfig,
        runtime: RuntimeHandleSource,
    ) -> std::result::Result<Self, RuleError> {
        Ok(Self {
            executor: Arc::new(BoundedExecutor::from_runtime_source(
                runtime,
                config.workers,
                config.workers + config.queue_capacity,
            )),
            traffic_policy: config.traffic_policy,
            dry_run: config.dry_run,
        })
    }

    pub fn dispatch(
        &self,
        rule_name: &str,
        template: &RuleSendTemplate,
        packet: Option<&PacketContext>,
    ) -> Result<()> {
        let rendered = template.render(packet);
        let policy = self.transmission_policy();
        validate_rule_send_mode(rule_name, &rendered, policy)?;

        if self.dry_run {
            info!(
                "rule '{}' send action validated (dry-run); would dispatch templated packet",
                rule_name
            );
            telemetry::record_rule_action("send", "dry_run_validated");
            return Ok(());
        }

        let rule_name_owned = rule_name.to_string();
        let spawn_result = self.executor.spawn_async(move || async move {
            telemetry::record_rule_action("send", "started");
            match Self::send(rule_name_owned.clone(), rendered, policy).await {
                Ok(_) => {
                    telemetry::record_rule_action("send", "succeeded");
                    info!("rule '{}' dispatched templated packet", rule_name_owned)
                }
                Err(err) => {
                    telemetry::record_rule_action("send", "failed");
                    error!("rule '{}' send action failed: {err}", rule_name_owned)
                }
            }
        });

        match spawn_result {
            Ok(()) => {
                telemetry::record_rule_action("send", "queued");
                Ok(())
            }
            Err(ExecutorError::QueueFull) => {
                warn!(
                    "rule '{}' send action dropped: executor queue is full",
                    rule_name
                );
                telemetry::record_rule_executor_drop("send", "queue_full");
                Err(RuleActionError::SendQueueFull {
                    rule: rule_name.to_string(),
                }
                .into())
            }
            Err(ExecutorError::Closed) => {
                error!(
                    "rule '{}' send action failed: executor unavailable",
                    rule_name
                );
                telemetry::record_rule_executor_drop("send", "executor_closed");
                Err(RuleActionError::SendExecutorUnavailable {
                    rule: rule_name.to_string(),
                }
                .into())
            }
            Err(ExecutorError::RuntimeUnavailable(details)) => {
                error!(
                    "rule '{}' send action failed: executor runtime unavailable: {}",
                    rule_name, details
                );
                telemetry::record_rule_executor_drop("send", "runtime_unavailable");
                Err(RuleActionError::SendExecutorUnavailable {
                    rule: rule_name.to_string(),
                }
                .into())
            }
        }
    }

    fn transmission_policy(&self) -> TrafficPolicy {
        self.traffic_policy.with_dry_run(self.dry_run)
    }

    async fn send(rule_name: String, request: PacketRequest, policy: TrafficPolicy) -> Result<()> {
        #[cfg(any(test, feature = "test_utils"))]
        if let Some(handler) = test_support::send_hook() {
            return handler(rule_name, request);
        }

        let service = PacketSendService::new(policy);
        let prepared = service.prepare(request, true).await.map_err(|source| {
            RuleActionError::SendExecution {
                rule: rule_name.clone(),
                stage: "preparing packet send",
                source,
            }
        })?;
        service
            .execute_plan(prepared.plan)
            .await
            .map_err(|source| RuleActionError::SendExecution {
                rule: rule_name,
                stage: "executing transmission",
                source,
            })?;
        Ok(())
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_send_hook(hook: test_support::TestSendHook) {
        test_support::set_send_hook(hook);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reproduction_test;
