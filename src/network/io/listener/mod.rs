#[cfg(any(feature = "daemon", feature = "pcap"))]
use std::sync::atomic::AtomicBool;
#[cfg(feature = "pcap")]
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[cfg(feature = "pcap")]
use log::{info, warn};
#[cfg(feature = "pcap")]
use tokio::sync::mpsc;
#[cfg(feature = "daemon")]
use tokio::task::JoinHandle;

#[cfg(feature = "pcap")]
use crate::engine::command::ListenRequest;
#[cfg(any(test, feature = "daemon"))]
use crate::engine::request::ListenerRequest;
use crate::engine::ListenerEvent;
use crate::engine::{spec::ListenerSpec, EngineConfig};
#[cfg(feature = "pcap")]
use crate::network::interface;

#[cfg(feature = "pcap")]
pub mod capture;
pub mod config;
pub mod error;
#[cfg(feature = "pcap")]
pub mod process;

pub use config::ListenerRuntimeConfig;
pub use error::ListenerError;

#[cfg(feature = "pcap")]
use capture::spawn_capture_thread;
#[cfg(feature = "pcap")]
use process::process_packet;

pub type ListenerResult<T> = std::result::Result<T, ListenerError>;
pub type ListenerEventHandler = Arc<dyn Fn(ListenerEvent) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, feature = "pcap"))]
enum ListenerRunOutcome {
    Completed,
    ShutdownRequested,
}

/// Run the listener using the CLI `listen` subcommand configuration.
#[cfg(feature = "pcap")]
pub async fn run_command(
    opts: &ListenRequest,
    interface_hint: Option<&str>,
    config: &EngineConfig,
    handler: ListenerEventHandler,
) -> ListenerResult<()> {
    let mut listen = opts.listen.clone();
    listen.listen = Some(true);
    let runtime = ListenerRuntimeConfig::from_request(&listen)?;
    if opts.persistent.unwrap_or(false) {
        loop {
            let outcome = run_internal(
                runtime.clone(),
                interface_hint,
                config.clone(),
                handler.clone(),
                None,
            )
            .await?;
            if !should_rearm_listener(&runtime, outcome) {
                break;
            }
            info!("Persistent mode rearming listener after timeout");
        }
        Ok(())
    } else {
        run_internal(runtime, interface_hint, config.clone(), handler, None)
            .await
            .map(|_| ())
    }
}

/// Run the listener when requested from a one-shot transmission plan.
pub async fn run_from_spec(
    spec: &ListenerSpec,
    interface_hint: Option<&str>,
    config: &EngineConfig,
    handler: ListenerEventHandler,
) -> ListenerResult<()> {
    if !spec.enabled {
        return Ok(());
    }

    #[cfg(not(feature = "pcap"))]
    {
        let _ = (interface_hint, config, handler);
        Err(ListenerError::ListenerRequiresPcap)
    }

    #[cfg(feature = "pcap")]
    {
        let runtime = ListenerRuntimeConfig::from_spec(spec)?;
        run_internal(runtime, interface_hint, config.clone(), handler, None)
            .await
            .map(|_| ())
    }
}

#[cfg(feature = "daemon")]
pub(crate) fn spawn_background(
    options: &ListenerRequest,
    interface_hint: Option<&str>,
    config: &EngineConfig,
    handler: ListenerEventHandler,
    shutdown: Arc<AtomicBool>,
) -> ListenerResult<JoinHandle<ListenerResult<()>>> {
    #[cfg(not(feature = "pcap"))]
    {
        let _ = (options, interface_hint, config, handler, shutdown);
        Err(ListenerError::ListenerRequiresPcap)
    }

    #[cfg(feature = "pcap")]
    {
        let runtime = ListenerRuntimeConfig::from_request(options)?;
        let interface_hint = interface_hint.map(|s| s.to_string());
        let config = config.clone();

        Ok(tokio::spawn(async move {
            run_internal(
                runtime,
                interface_hint.as_deref(),
                config,
                handler,
                Some(shutdown),
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
    _config: EngineConfig,
    handler: ListenerEventHandler,
    shutdown: Option<Arc<AtomicBool>>,
) -> ListenerResult<ListenerRunOutcome> {
    let interface = interface::find_interface(interface_hint).map_err(|source| {
        ListenerError::InterfaceLookup {
            hint: interface_hint.map(|s| s.to_string()),
            source,
        }
    })?;

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

#[cfg(any(test, feature = "pcap"))]
fn should_rearm_listener(runtime: &ListenerRuntimeConfig, outcome: ListenerRunOutcome) -> bool {
    runtime.timeout.is_some() && matches!(outcome, ListenerRunOutcome::Completed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "pcap")]
    fn empty_engine_config() -> EngineConfig {
        EngineConfig {
            output_format: None,
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            allow_unbounded_sends: false,
            dry_run: false,
        }
    }

    #[cfg(feature = "pcap")]
    #[tokio::test]
    async fn dedicated_listen_command_does_not_exit_early() {
        let opts = ListenRequest {
            listen: ListenerRequest::default(),
            persistent: None,
        };
        let config = empty_engine_config();
        let handler: ListenerEventHandler = Arc::new(|_| {});

        let result = run_command(
            &opts,
            Some("__packetcraftr_missing_listener_interface__"),
            &config,
            handler,
        )
        .await;

        assert!(matches!(
            result,
            Err(ListenerError::InterfaceLookup { hint: Some(ref hint), .. })
                if hint == "__packetcraftr_missing_listener_interface__"
        ));
    }

    #[test]
    fn persistent_shutdown_does_not_rearm() {
        let listen = ListenerRequest {
            timeout: Some(5),
            ..Default::default()
        };
        let runtime = ListenerRuntimeConfig::from_request(&listen)
            .expect("runtime configuration should succeed");

        assert!(!should_rearm_listener(
            &runtime,
            ListenerRunOutcome::ShutdownRequested
        ));
    }

    #[test]
    fn persistent_completed_with_timeout_rearms() {
        let listen = ListenerRequest {
            timeout: Some(5),
            ..Default::default()
        };
        let runtime = ListenerRuntimeConfig::from_request(&listen)
            .expect("runtime configuration should succeed");

        assert!(should_rearm_listener(
            &runtime,
            ListenerRunOutcome::Completed
        ));
    }

    #[test]
    fn persistent_completed_without_timeout_does_not_rearm() {
        let listen = ListenerRequest::default();
        let runtime = ListenerRuntimeConfig::from_request(&listen)
            .expect("runtime configuration should succeed");

        assert!(!should_rearm_listener(
            &runtime,
            ListenerRunOutcome::Completed
        ));
    }
}
