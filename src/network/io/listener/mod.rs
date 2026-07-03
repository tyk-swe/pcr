// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "daemon")]
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[cfg(any(feature = "daemon", feature = "pcap"))]
use tokio::sync::oneshot;
#[cfg(feature = "daemon")]
use tokio::task::JoinHandle;

#[cfg(feature = "pcap")]
use crate::domain::command::ListenRequest;
use crate::domain::event::ListenerEvent;
#[cfg(feature = "daemon")]
use crate::domain::request::ListenerRequest;
use crate::domain::spec::ListenerSpec;

#[cfg(feature = "pcap")]
mod capture;
#[cfg(any(feature = "daemon", feature = "pcap"))]
mod config;
pub(crate) mod error;
#[cfg(feature = "pcap")]
mod process;
mod runtime;

pub(crate) use error::ListenerError;

pub(crate) type ListenerResult<T> = std::result::Result<T, ListenerError>;
pub(crate) type ListenerEventHandler = Arc<dyn Fn(ListenerEvent) + Send + Sync>;
#[cfg(any(feature = "daemon", feature = "pcap"))]
pub(crate) type ListenerStartupSignal = oneshot::Sender<std::result::Result<(), String>>;

/// Run the listener using the CLI `listen` subcommand configuration.
#[cfg(feature = "pcap")]
pub(crate) async fn run_command(
    opts: &ListenRequest,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
) -> ListenerResult<()> {
    runtime::run_command(opts, interface_hint, handler).await
}

/// Run the listener when requested from a one-shot transmission plan.
pub(crate) async fn run_from_spec(
    spec: &ListenerSpec,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
) -> ListenerResult<()> {
    runtime::run_from_spec(spec, interface_hint, handler).await
}

#[cfg(feature = "daemon")]
pub(crate) fn spawn_background(
    options: &ListenerRequest,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
    shutdown: Arc<AtomicBool>,
    startup: Option<ListenerStartupSignal>,
) -> ListenerResult<JoinHandle<ListenerResult<()>>> {
    runtime::spawn_background(options, interface_hint, handler, shutdown, startup)
}

#[cfg(feature = "daemon")]
pub(crate) fn validate_options(options: &ListenerRequest) -> ListenerResult<()> {
    runtime::validate_options(options)
}
