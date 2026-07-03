// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use log::{error, info, warn};
use tokio::runtime::Handle;

use crate::domain::policy::TrafficPolicy;
use crate::domain::request::PacketRequest;
use crate::engine::ports::RuleActionTelemetry;
use crate::engine::send::SendUseCase;
use crate::rules::{
    validate_rule_send_request, BoundedExecutor, ExecutorError, PacketContext, RuleActionError,
    RuleError, RuleSendDispatcher, RuleSendTemplate,
};

const RULE_SEND_EXECUTOR_WORKERS: usize = 4;
const RULE_SEND_EXECUTOR_QUEUE_CAPACITY: usize = 64;

type Result<T> = std::result::Result<T, RuleError>;

#[derive(Debug, Clone)]
pub(crate) struct RuleSendConfig {
    workers: usize,
    queue_capacity: usize,
    traffic_policy: TrafficPolicy,
    dry_run: bool,
}

impl RuleSendConfig {
    pub(crate) fn from_options(
        workers: Option<usize>,
        queue_capacity: Option<usize>,
        traffic_policy: TrafficPolicy,
        dry_run: bool,
    ) -> Self {
        Self {
            workers: workers.unwrap_or(RULE_SEND_EXECUTOR_WORKERS),
            queue_capacity: queue_capacity.unwrap_or(RULE_SEND_EXECUTOR_QUEUE_CAPACITY),
            traffic_policy: traffic_policy.with_dry_run(dry_run),
            dry_run,
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuleSendExecutor {
    executor: Arc<BoundedExecutor>,
    send: Arc<SendUseCase>,
    telemetry: Arc<dyn RuleActionTelemetry>,
    traffic_policy: TrafficPolicy,
    dry_run: bool,
}

impl RuleSendExecutor {
    pub(crate) fn new_configured(
        config: RuleSendConfig,
        send: Arc<SendUseCase>,
        telemetry: Arc<dyn RuleActionTelemetry>,
    ) -> Result<Self> {
        let executor = BoundedExecutor::new(
            "rule-send-worker",
            config.workers,
            config.workers + config.queue_capacity,
        )?;
        Ok(Self::from_executor(config, send, telemetry, executor))
    }

    pub(crate) fn new_configured_with_runtime_handle(
        config: RuleSendConfig,
        send: Arc<SendUseCase>,
        telemetry: Arc<dyn RuleActionTelemetry>,
        handle: Handle,
    ) -> Result<Self> {
        let executor = BoundedExecutor::new_with_handle(
            handle,
            config.workers,
            config.workers + config.queue_capacity,
        )?;
        Ok(Self::from_executor(config, send, telemetry, executor))
    }

    fn from_executor(
        config: RuleSendConfig,
        send: Arc<SendUseCase>,
        telemetry: Arc<dyn RuleActionTelemetry>,
        executor: BoundedExecutor,
    ) -> Self {
        Self {
            executor: Arc::new(executor),
            send,
            telemetry,
            traffic_policy: config.traffic_policy,
            dry_run: config.dry_run,
        }
    }

    fn transmission_policy(&self) -> TrafficPolicy {
        self.traffic_policy.with_dry_run(self.dry_run)
    }

    async fn send(rule_name: String, request: PacketRequest, send: Arc<SendUseCase>) -> Result<()> {
        let prepared =
            send.prepare(request, true)
                .await
                .map_err(|source| RuleActionError::SendExecution {
                    rule: rule_name.clone(),
                    stage: "preparing packet send",
                    source,
                })?;
        send.execute_plan(prepared.plan).await.map_err(|source| {
            RuleActionError::SendExecution {
                rule: rule_name,
                stage: "executing transmission",
                source,
            }
        })?;
        Ok(())
    }
}

impl std::fmt::Debug for RuleSendExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSendExecutor")
            .field("traffic_policy", &self.traffic_policy)
            .field("dry_run", &self.dry_run)
            .finish_non_exhaustive()
    }
}

impl RuleSendDispatcher for RuleSendExecutor {
    fn dispatch(
        &self,
        rule_name: &str,
        template: &RuleSendTemplate,
        packet: Option<&PacketContext>,
    ) -> Result<()> {
        let rendered = template.render(packet);
        let policy = self.transmission_policy();
        validate_rule_send_request(rule_name, &rendered, policy)?;

        if self.dry_run {
            info!(
                "rule '{}' send action validated (dry-run); would dispatch templated packet",
                rule_name
            );
            self.telemetry
                .record_rule_action("send", "dry_run_validated");
            return Ok(());
        }

        let rule_name_owned = rule_name.to_string();
        let send = Arc::clone(&self.send);
        let telemetry = Arc::clone(&self.telemetry);
        let spawn_result = self.executor.spawn_async(move || async move {
            telemetry.record_rule_action("send", "started");
            match Self::send(rule_name_owned.clone(), rendered, send).await {
                Ok(_) => {
                    telemetry.record_rule_action("send", "succeeded");
                    info!("rule '{}' dispatched templated packet", rule_name_owned)
                }
                Err(err) => {
                    telemetry.record_rule_action("send", "failed");
                    error!("rule '{}' send action failed: {err}", rule_name_owned)
                }
            }
        });

        match spawn_result {
            Ok(()) => {
                self.telemetry.record_rule_action("send", "queued");
                Ok(())
            }
            Err(ExecutorError::QueueFull) => {
                warn!(
                    "rule '{}' send action dropped: executor queue is full",
                    rule_name
                );
                self.telemetry
                    .record_rule_executor_drop("send", "queue_full");
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
                self.telemetry
                    .record_rule_executor_drop("send", "executor_closed");
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
                self.telemetry
                    .record_rule_executor_drop("send", "runtime_unavailable");
                Err(RuleActionError::SendExecutorUnavailable {
                    rule: rule_name.to_string(),
                }
                .into())
            }
        }
    }
}
