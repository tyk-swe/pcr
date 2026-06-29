// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use log::{error, info, warn};
use tokio::runtime::Handle;

use crate::domain::policy::TrafficPolicy;
use crate::domain::request::PacketRequest;
use crate::engine::send::PacketSendService;
use crate::rules::send::{RuleSendDispatcher, RuleSendTemplate};
use crate::rules::{
    validate_rule_send_request, BoundedExecutor, ExecutorError, PacketContext, RuleActionError,
    RuleError,
};
use crate::util::telemetry;

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

#[derive(Debug, Clone)]
pub(crate) struct RuleSendExecutor {
    executor: Arc<BoundedExecutor>,
    traffic_policy: TrafficPolicy,
    dry_run: bool,
}

impl RuleSendExecutor {
    pub(crate) fn new_configured(config: RuleSendConfig) -> Result<Self> {
        let executor = BoundedExecutor::new(
            "rule-send-worker",
            config.workers,
            config.workers + config.queue_capacity,
        )?;
        Ok(Self::from_executor(config, executor))
    }

    pub(crate) fn new_configured_with_runtime_handle(
        config: RuleSendConfig,
        handle: Handle,
    ) -> Result<Self> {
        let executor = BoundedExecutor::new_with_handle(
            handle,
            config.workers,
            config.workers + config.queue_capacity,
        )?;
        Ok(Self::from_executor(config, executor))
    }

    fn from_executor(config: RuleSendConfig, executor: BoundedExecutor) -> Self {
        Self {
            executor: Arc::new(executor),
            traffic_policy: config.traffic_policy,
            dry_run: config.dry_run,
        }
    }

    fn transmission_policy(&self) -> TrafficPolicy {
        self.traffic_policy.with_dry_run(self.dry_run)
    }

    async fn send(rule_name: String, request: PacketRequest, policy: TrafficPolicy) -> Result<()> {
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
}
