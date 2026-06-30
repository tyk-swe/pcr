// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(any(feature = "daemon", feature = "pcap"))]
use std::sync::atomic::AtomicBool;
#[cfg(feature = "pcap")]
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[cfg(feature = "pcap")]
use log::{info, warn};
#[cfg(feature = "pcap")]
use tokio::sync::mpsc;
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
use crate::network::interface;

#[cfg(feature = "pcap")]
pub(crate) mod capture;
#[cfg(any(feature = "daemon", feature = "pcap"))]
mod config;
pub(crate) mod error;
#[cfg(feature = "pcap")]
pub(crate) mod process;

pub(crate) use error::ListenerError;

#[cfg(feature = "pcap")]
use capture::spawn_capture_thread;
#[cfg(any(feature = "daemon", feature = "pcap"))]
use config::ListenerRuntimeConfig;
#[cfg(feature = "pcap")]
use process::process_packet;

pub(crate) type ListenerResult<T> = std::result::Result<T, ListenerError>;
pub(crate) type ListenerEventHandler = Arc<dyn Fn(ListenerEvent) + Send + Sync>;
#[cfg(any(feature = "daemon", feature = "pcap"))]
pub(crate) type ListenerStartupSignal = oneshot::Sender<std::result::Result<(), String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "pcap")]
enum ListenerRunOutcome {
    Completed,
    ShutdownRequested,
}

/// Run the listener using the CLI `listen` subcommand configuration.
#[cfg(feature = "pcap")]
pub(crate) async fn run_command(
    opts: &ListenRequest,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
) -> ListenerResult<()> {
    let mut listen = opts.listen.clone();
    listen.listen = Some(true);
    let runtime = ListenerRuntimeConfig::from_request(&listen)?;
    if opts.persistent.unwrap_or(false) {
        loop {
            let outcome =
                run_internal(runtime.clone(), interface_hint, handler.clone(), None, None).await?;
            if !should_rearm_listener(&runtime, outcome) {
                break;
            }
            info!("Persistent mode rearming listener after timeout");
        }
        Ok(())
    } else {
        run_internal(runtime, interface_hint, handler, None, None)
            .await
            .map(|_| ())
    }
}

/// Run the listener when requested from a one-shot transmission plan.
pub(crate) async fn run_from_spec(
    spec: &ListenerSpec,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
) -> ListenerResult<()> {
    if !spec.enabled {
        return Ok(());
    }

    #[cfg(not(feature = "pcap"))]
    {
        let _ = (interface_hint, handler);
        Err(ListenerError::ListenerRequiresPcap)
    }

    #[cfg(feature = "pcap")]
    {
        let runtime = ListenerRuntimeConfig::from_spec(spec)?;
        run_internal(runtime, interface_hint, handler, None, None)
            .await
            .map(|_| ())
    }
}

#[cfg(feature = "daemon")]
pub(crate) fn spawn_background(
    options: &ListenerRequest,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
    shutdown: Arc<AtomicBool>,
    startup: Option<ListenerStartupSignal>,
) -> ListenerResult<JoinHandle<ListenerResult<()>>> {
    #[cfg(not(feature = "pcap"))]
    {
        let _ = (options, interface_hint, handler, shutdown, startup);
        Err(ListenerError::ListenerRequiresPcap)
    }

    #[cfg(feature = "pcap")]
    {
        let runtime = ListenerRuntimeConfig::from_request(options)?;
        let interface_hint = interface_hint.map(|s| s.to_string());

        Ok(tokio::spawn(async move {
            run_internal(
                runtime,
                interface_hint.as_deref(),
                handler,
                Some(shutdown),
                startup,
            )
            .await
            .map(|_| ())
        }))
    }
}

#[cfg(feature = "daemon")]
pub(crate) fn validate_options(options: &ListenerRequest) -> ListenerResult<()> {
    ListenerRuntimeConfig::from_request(options).map(|_| ())
}

#[cfg(feature = "pcap")]
async fn run_internal(
    runtime: ListenerRuntimeConfig,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
    shutdown: Option<Arc<AtomicBool>>,
    startup: Option<ListenerStartupSignal>,
) -> ListenerResult<ListenerRunOutcome> {
    let interface = match interface::find_interface(interface_hint) {
        Ok(interface) => interface,
        Err(source) => {
            let err = ListenerError::InterfaceLookup {
                hint: interface_hint.map(|s| s.to_string()),
                source,
            };
            if let Some(startup) = startup {
                let _ = startup.send(Err(err.to_string()));
            }
            return Err(err);
        }
    };

    info!(
        "Listener active on {} filter={:?} promisc={} timeout={:?} capture={:?} queue_capacity={}",
        interface.name,
        runtime.filter,
        runtime.promiscuous,
        runtime.timeout,
        runtime
            .capture_file
            .as_ref()
            .map(|path| path.display().to_string()),
        runtime.queue_capacity
    );

    if runtime.promiscuous {
        warn!("Promiscuous mode requested; ensure interface supports this setting.");
    }

    let running = shutdown
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicBool::new(true)));
    running.store(true, Ordering::SeqCst);

    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(runtime.queue_capacity);
    let capture_handle = spawn_capture_thread(
        runtime.clone(),
        interface.clone(),
        packet_tx,
        running.clone(),
        startup,
    );

    let mut captured = 0usize;
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());
    let mut outcome = ListenerRunOutcome::Completed;

    loop {
        tokio::select! {
            biased;
            _ = &mut ctrl_c => {
                info!("Listener received shutdown signal");
                running.store(false, Ordering::SeqCst);
                outcome = ListenerRunOutcome::ShutdownRequested;
                break;
            }
            packet = packet_rx.recv() => {
                match packet {
                    Some(data) => {
                        captured += 1;
                        let event = process_packet(&data, runtime.show_reply);
                        handler(event);
                    }
                    None => break,
                }
            }
        }
    }

    if matches!(outcome, ListenerRunOutcome::Completed)
        && shutdown.is_some()
        && !running.load(Ordering::SeqCst)
    {
        outcome = ListenerRunOutcome::ShutdownRequested;
    }

    running.store(false, Ordering::SeqCst);
    if let Some(handle) = capture_handle {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err(err);
            }
            Err(join_err) => {
                // Leverage the `#[from] JoinError` conversion implemented by `ListenerError`.
                Err(join_err)?;
            }
        }
    }

    info!(
        "Listener on {} finished after capturing {} packet(s)",
        interface.name, captured
    );

    Ok(outcome)
}

#[cfg(feature = "pcap")]
fn should_rearm_listener(runtime: &ListenerRuntimeConfig, outcome: ListenerRunOutcome) -> bool {
    runtime.timeout.is_some() && matches!(outcome, ListenerRunOutcome::Completed)
}
