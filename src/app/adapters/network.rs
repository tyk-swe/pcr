// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "daemon")]
use std::future::Future;
#[cfg(feature = "daemon")]
use std::pin::Pin;
#[cfg(any(feature = "daemon", feature = "pcap"))]
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
#[cfg(feature = "daemon")]
use std::task::{Context, Poll};

use anyhow::Context as _;
use pnet::packet::ip::IpNextHeaderProtocol;

#[cfg(feature = "pcap")]
use crate::domain::command::ListenRequest;
use crate::domain::policy::TransmissionPolicy;
#[cfg(feature = "daemon")]
use crate::domain::request::ListenerRequest;
use crate::domain::spec::{ListenerSpec, PacketSpec};
use crate::domain::transmission::{PlanningMode, TransmissionPlan, TransmissionProtocol};
use crate::engine::error::EngineError;
#[cfg(feature = "daemon")]
use crate::engine::ports::DaemonListenerRuntime;
use crate::engine::ports::{
    ListenerEventHandler, ListenerRunner, PacketPlanner, PacketTransmitter, PortFuture,
};

#[derive(Debug, Default)]
pub(crate) struct NetworkPacketPlanner;

impl PacketPlanner for NetworkPacketPlanner {
    fn plan_packet(
        &self,
        spec: Arc<PacketSpec>,
        mode: PlanningMode,
        policy: TransmissionPolicy,
    ) -> PortFuture<TransmissionPlan> {
        Box::pin(async move {
            let plan = tokio::task::spawn_blocking(move || {
                match mode {
                    PlanningMode::DryRun => {
                        crate::network::io::sender::plan_transmission_dry_run_with_policy(
                            spec.as_ref(),
                            policy,
                        )
                    }
                    PlanningMode::Live => {
                        crate::network::io::sender::plan_transmission_with_policy(
                            spec.as_ref(),
                            policy,
                        )
                    }
                }
                .map_err(|e| EngineError::TransmissionPlan(e.into()))
            })
            .await
            .context("transmission planning task failed")
            .map_err(EngineError::TransmissionPlan)??;

            Ok(network_plan_to_domain_plan(plan))
        })
    }
}

#[cfg(feature = "daemon")]
impl DaemonListenerRuntime for NetworkListenerRunner {
    fn validate_options(&self, options: &ListenerRequest) -> crate::engine::ports::PortResult<()> {
        crate::network::io::listener::validate_options(options).map_err(anyhow::Error::from)
    }

    fn spawn_background(
        &self,
        options: ListenerRequest,
        interface_hint: Option<String>,
        handler: ListenerEventHandler,
        shutdown: Arc<AtomicBool>,
        startup: Option<crate::engine::ports::ListenerStartupSignal>,
    ) -> crate::engine::ports::PortResult<
        tokio::task::JoinHandle<crate::engine::ports::PortResult<()>>,
    > {
        crate::network::io::listener::spawn_background(
            &options,
            interface_hint.as_deref(),
            handler,
            shutdown,
            startup,
        )
        .map(|handle| {
            tokio::spawn(async move {
                AbortOnDropJoinHandle::new(handle)
                    .await
                    .map_err(anyhow::Error::from)?
                    .map_err(anyhow::Error::from)
            })
        })
        .map_err(anyhow::Error::from)
    }
}

#[cfg(feature = "daemon")]
struct AbortOnDropJoinHandle<T> {
    handle: tokio::task::JoinHandle<T>,
}

#[cfg(feature = "daemon")]
impl<T> AbortOnDropJoinHandle<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self { handle }
    }
}

#[cfg(feature = "daemon")]
impl<T> Future for AbortOnDropJoinHandle<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx)
    }
}

#[cfg(feature = "daemon")]
impl<T> Drop for AbortOnDropJoinHandle<T> {
    fn drop(&mut self) {
        if !self.handle.is_finished() {
            self.handle.abort();
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct NetworkListenerRunner;

impl ListenerRunner for NetworkListenerRunner {
    #[cfg(not(feature = "pcap"))]
    fn run_for_packet(
        &self,
        spec: ListenerSpec,
        interface_hint: Option<String>,
        handler: ListenerEventHandler,
    ) -> PortFuture<()> {
        Box::pin(async move {
            crate::network::io::listener::run_from_spec(&spec, interface_hint.as_deref(), handler)
                .await
                .map_err(anyhow::Error::from)
        })
    }

    #[cfg(feature = "pcap")]
    fn run_for_packet_with_lifecycle(
        &self,
        spec: ListenerSpec,
        interface_hint: Option<String>,
        handler: ListenerEventHandler,
        shutdown: Arc<AtomicBool>,
        startup: Option<crate::engine::ports::ListenerStartupSignal>,
    ) -> PortFuture<()> {
        Box::pin(async move {
            crate::network::io::listener::run_from_spec_with_lifecycle(
                &spec,
                interface_hint.as_deref(),
                handler,
                shutdown,
                startup,
            )
            .await
            .map_err(anyhow::Error::from)
        })
    }

    #[cfg(feature = "pcap")]
    fn run_command(&self, request: ListenRequest, handler: ListenerEventHandler) -> PortFuture<()> {
        Box::pin(async move {
            crate::network::io::listener::run_command(&request, None, handler)
                .await
                .map_err(anyhow::Error::from)
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct NetworkPacketTransmitter;

impl PacketTransmitter for NetworkPacketTransmitter {
    fn transmit(&self, plan: TransmissionPlan) -> PortFuture<()> {
        Box::pin(async move {
            let plan = domain_plan_to_network_plan(plan)?;
            crate::network::io::sender::emit_metrics_snapshot(&plan)
                .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
            crate::network::io::sender::execute_transmission(plan)
                .await
                .map_err(|e| EngineError::TransmissionExecution(e.into()))?;
            Ok(())
        })
    }
}

fn network_plan_to_domain_plan(
    plan: crate::network::io::sender::NetworkTransmissionPlan,
) -> TransmissionPlan {
    TransmissionPlan {
        frames: plan.frames,
        link_type: plan.link_type,
        transmit: plan.transmit,
        destination: plan.destination,
        interface_name: plan.interface.name,
        selection: plan.selection,
        protocol: TransmissionProtocol(plan.protocol.0),
        summary: plan.summary,
        logging: plan.logging,
        mode: plan.mode,
        policy: plan.policy,
    }
}

fn domain_plan_to_network_plan(
    plan: TransmissionPlan,
) -> Result<crate::network::io::sender::NetworkTransmissionPlan, EngineError> {
    let interface = pnet::datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == plan.interface_name)
        .ok_or_else(|| {
            EngineError::transmission_plan(format!(
                "selected interface '{}' is no longer available",
                plan.interface_name
            ))
        })?;

    Ok(crate::network::io::sender::NetworkTransmissionPlan {
        frames: plan.frames,
        link_type: plan.link_type,
        transmit: plan.transmit,
        destination: plan.destination,
        interface,
        selection: plan.selection,
        protocol: IpNextHeaderProtocol(plan.protocol.0),
        summary: plan.summary,
        logging: plan.logging,
        mode: plan.mode,
        policy: plan.policy,
    })
}
