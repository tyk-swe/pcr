// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use log::{info, warn};
use tokio::sync::mpsc;
#[cfg(feature = "daemon")]
use tokio::task::JoinHandle;

use crate::domain::command::ListenRequest;
#[cfg(feature = "daemon")]
use crate::domain::request::ListenerRequest;
use crate::domain::spec::ListenerSpec;
use crate::network::interface;
use crate::network::io::listener::capture::spawn_capture_thread;
use crate::network::io::listener::config::ListenerRuntimeConfig;
use crate::network::io::listener::error::PcapListenerError;
use crate::network::io::listener::process::process_packet;
use crate::network::io::listener::{ListenerEventHandler, ListenerResult, ListenerStartupSignal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerRunOutcome {
    Completed,
    ShutdownRequested,
}

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

pub(crate) async fn run_from_spec_with_lifecycle(
    spec: &ListenerSpec,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
    shutdown: Arc<AtomicBool>,
    startup: Option<ListenerStartupSignal>,
) -> ListenerResult<()> {
    if !spec.enabled {
        return Ok(());
    }

    let runtime = ListenerRuntimeConfig::from_spec(spec)?;
    run_internal(runtime, interface_hint, handler, Some(shutdown), startup)
        .await
        .map(|_| ())
}

#[cfg(feature = "daemon")]
pub(crate) fn spawn_background(
    options: &ListenerRequest,
    interface_hint: Option<&str>,
    handler: ListenerEventHandler,
    shutdown: Arc<AtomicBool>,
    startup: Option<ListenerStartupSignal>,
) -> ListenerResult<JoinHandle<ListenerResult<()>>> {
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

#[cfg(feature = "daemon")]
pub(crate) fn validate_options(options: &ListenerRequest) -> ListenerResult<()> {
    ListenerRuntimeConfig::from_request(options).map(|_| ())
}

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
            let err = PcapListenerError::InterfaceLookup {
                hint: interface_hint.map(|s| s.to_string()),
                source,
            };
            if let Some(startup) = startup {
                let _ = startup.send(Err(err.to_string()));
            }
            return Err(err.into());
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
                return Err(PcapListenerError::CaptureTaskJoin { source: join_err }.into());
            }
        }
    }

    info!(
        "Listener on {} finished after capturing {} packet(s)",
        interface.name, captured
    );

    Ok(outcome)
}

fn should_rearm_listener(runtime: &ListenerRuntimeConfig, outcome: ListenerRunOutcome) -> bool {
    runtime.timeout.is_some() && matches!(outcome, ListenerRunOutcome::Completed)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn runtime(timeout: Option<Duration>) -> ListenerRuntimeConfig {
        ListenerRuntimeConfig {
            filter: None,
            promiscuous: false,
            timeout,
            show_reply: false,
            capture_file: None,
            queue_capacity: 64,
        }
    }

    #[test]
    fn should_rearm_listener_requires_timeout_and_completed_outcome() {
        assert!(should_rearm_listener(
            &runtime(Some(Duration::from_secs(1))),
            ListenerRunOutcome::Completed
        ));
        assert!(!should_rearm_listener(
            &runtime(Some(Duration::from_secs(1))),
            ListenerRunOutcome::ShutdownRequested
        ));
        assert!(!should_rearm_listener(
            &runtime(None),
            ListenerRunOutcome::Completed
        ));
    }

    #[tokio::test]
    async fn run_internal_sends_startup_error_for_interface_lookup_failure() {
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();

        let err = run_internal(
            runtime(Some(Duration::from_millis(1))),
            Some("definitely-not-a-real-interface"),
            Arc::new(|_| {}),
            Some(Arc::new(AtomicBool::new(true))),
            Some(startup_tx),
        )
        .await
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("failed to determine capture interface"));
        assert!(startup_rx
            .await
            .unwrap()
            .unwrap_err()
            .contains("failed to determine capture interface"));
    }
}
