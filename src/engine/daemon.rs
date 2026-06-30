// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, MissedTickBehavior};

#[cfg(unix)]
mod control;

#[cfg(unix)]
use control::{cleanup_control_socket, preflight_control_socket, spawn_control_socket};

use crate::domain::command::DaemonRequest;
use crate::domain::request::ListenerRequest;
use crate::engine::config::EngineConfig;
use crate::engine::ports::{DaemonListenerRuntime, EngineOutput, ListenerEventHandler};
use crate::rules::{RuleEngine, RuleLoadOptions, RuleLoadReport};

const TIMER_TICK: Duration = Duration::from_secs(5);
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROL_COMMAND_QUEUE_CAPACITY: usize = 512;
const LISTENER_STARTUP_TIMEOUT: Duration = Duration::from_secs(2);

type CommandResponse = anyhow::Result<String>;

#[derive(Debug)]
pub(crate) struct DaemonStartupPreflight {
    rules: Option<RuleLoadReport>,
}

impl DaemonStartupPreflight {
    pub(crate) fn rules_were_loaded(&self) -> bool {
        self.rules.is_some()
    }

    pub(crate) fn into_rules(self) -> Option<RuleLoadReport> {
        self.rules
    }
}

pub(crate) fn preflight(opts: &DaemonRequest) -> Result<DaemonStartupPreflight> {
    if opts.rules_file.is_none() && opts.control_socket.is_none() {
        return Err(anyhow!(
            "daemon startup requires --rules or --control-socket so it can be configured after launch"
        ));
    }

    let rules = if let Some(rules_file) = opts.rules_file.as_ref() {
        let report =
            RuleEngine::load_rules_from_path_with_options(rules_file, RuleLoadOptions::default())
                .with_context(|| format!("load rule file failed: path={rules_file}"))?;
        if report.has_receive_triggers() {
            ensure_listener_feature_available()?;
        }
        Some(report)
    } else {
        None
    };

    #[cfg(unix)]
    if let Some(path) = opts.control_socket.as_ref() {
        preflight_control_socket(path)
            .with_context(|| format!("control socket preflight failed for {}", path))?;
    }

    #[cfg(not(unix))]
    if let Some(path) = opts.control_socket.as_ref() {
        return Err(anyhow!(
            "--control-socket ({path}) is only available on Unix platforms"
        ));
    }

    Ok(DaemonStartupPreflight { rules })
}

pub async fn run(
    opts: &DaemonRequest,
    _config: &EngineConfig,
    rules: &mut RuleEngine,
    output: Arc<dyn EngineOutput>,
    listener_runtime: Arc<dyn DaemonListenerRuntime>,
) -> Result<()> {
    info!(
        "Daemon started (mode: {})",
        if opts.foreground.unwrap_or(false) {
            "foreground"
        } else {
            "background"
        }
    );

    if rules.is_empty() {
        warn!("No rules loaded; daemon will idle until rules are provided.");
    } else {
        if rules.has_receive_triggers() {
            ensure_listener_feature_available()?;
        }
        if rules.has_startup_triggers() {
            info!("Executing startup rules prior to event loop");
            rules.run_startup_actions();
        }
    }

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<DaemonCommand>(CONTROL_COMMAND_QUEUE_CAPACITY);

    let mut sigint = Box::pin(tokio::signal::ctrl_c());
    let mut timer = time::interval(TIMER_TICK);
    timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    #[cfg(unix)]
    let mut control_socket = if let Some(path) = opts.control_socket.as_ref() {
        match spawn_control_socket(path, cmd_tx.clone()) {
            Ok(active) => Some(active),
            Err(err) => {
                return Err(err.context(format!("failed to bind control socket {}", path)));
            }
        }
    } else {
        None
    };

    #[cfg(not(unix))]
    if let Some(path) = opts.control_socket.as_ref() {
        return Err(anyhow!(
            "--control-socket ({path}) is only available on Unix platforms"
        ));
    }

    let mut state = DaemonState::new();

    if rules.has_receive_triggers() {
        debug!("Auto-starting listener because receive rules are active");
        if let Err(err) = start_listener(
            &mut state,
            default_listener_options(),
            rules,
            Arc::clone(&output),
            Arc::clone(&listener_runtime),
        )
        .await
        {
            #[cfg(unix)]
            cleanup_control_socket(&mut control_socket).await;
            return Err(err);
        }
    }

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;

        loop {
            tokio::select! {
                _ = &mut sigint => {
                    info!("Daemon received SIGINT (Ctrl+C), initiating graceful shutdown");
                    break;
                }
                _ = sigterm.recv() => {
                    info!("Daemon received SIGTERM, initiating graceful shutdown");
                    break;
                }
                Some(command) = cmd_rx.recv() => {
                    if handle_command(
                        command,
                        &mut state,
                        rules,
                        Arc::clone(&output),
                        Arc::clone(&listener_runtime),
                    )
                    .await?
                    {
                        info!("Daemon received shutdown command via control socket");
                        break;
                    }
                }
                _ = timer.tick(), if rules.has_timer_triggers() => {
                    debug!("Timer tick firing timer-triggered rules");
                    rules.run_timer_actions();
                }
            }
        }
    }

    #[cfg(not(unix))]
    loop {
        tokio::select! {
            _ = &mut sigint => {
                info!("Daemon received SIGINT (Ctrl+C), initiating graceful shutdown");
                break;
            }
            Some(command) = cmd_rx.recv() => {
                if handle_command(
                    command,
                    &mut state,
                    rules,
                    Arc::clone(&output),
                    Arc::clone(&listener_runtime),
                )
                .await?
                {
                    info!("Daemon received shutdown command via control socket");
                    break;
                }
            }
            _ = timer.tick(), if rules.has_timer_triggers() => {
                debug!("Timer tick firing timer-triggered rules");
                rules.run_timer_actions();
            }
        }
    }

    stop_listener(&mut state).await?;

    #[cfg(unix)]
    cleanup_control_socket(&mut control_socket).await;

    info!("Daemon shutdown complete");
    Ok(())
}

struct ActiveListener {
    shutdown: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

struct DaemonState {
    listener: Option<ActiveListener>,
    listener_options: Option<ListenerRequest>,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            listener: None,
            listener_options: None,
        }
    }
}

#[derive(Debug)]
enum DaemonCommand {
    LoadRules {
        path: String,
        respond_to: oneshot::Sender<CommandResponse>,
    },
    Listen {
        options: ListenerRequest,
        respond_to: oneshot::Sender<CommandResponse>,
    },
    StopListener {
        respond_to: oneshot::Sender<CommandResponse>,
    },
    Status {
        respond_to: oneshot::Sender<CommandResponse>,
    },
    Shutdown {
        respond_to: oneshot::Sender<CommandResponse>,
    },
}

async fn handle_command(
    command: DaemonCommand,
    state: &mut DaemonState,
    rules: &mut RuleEngine,
    output: Arc<dyn EngineOutput>,
    listener_runtime: Arc<dyn DaemonListenerRuntime>,
) -> Result<bool> {
    match command {
        DaemonCommand::LoadRules { path, respond_to } => {
            let result =
                load_rules_from_command(&path, state, rules, output, listener_runtime).await;
            send_response(respond_to, result);
            Ok(false)
        }
        DaemonCommand::Listen {
            options,
            respond_to,
        } => {
            let mut opts = options;
            opts.listen = Some(true);
            let outcome = start_listener(state, opts.clone(), rules, output, listener_runtime)
                .await
                .map(|_| {
                    format!(
                        "listener active with filter {:?} promisc {}",
                        opts.filter,
                        opts.promiscuous.unwrap_or(false)
                    )
                });
            send_response(respond_to, outcome);
            Ok(false)
        }
        DaemonCommand::StopListener { respond_to } => {
            let outcome = stop_listener(state)
                .await
                .map(|_| "listener stopped".to_string());
            send_response(respond_to, outcome);
            Ok(false)
        }
        DaemonCommand::Status { respond_to } => {
            let active = listener_is_active(state);
            let message = format!(
                "rules={} receive_rules={} listener={}",
                rules.len(),
                rules.has_receive_triggers(),
                if active { "active" } else { "inactive" }
            );
            send_response(respond_to, Ok(message));
            Ok(false)
        }
        DaemonCommand::Shutdown { respond_to } => {
            let _ = stop_listener(state).await;
            send_response(respond_to, Ok("shutting down".to_string()));
            Ok(true)
        }
    }
}

struct RuleReloadCandidate {
    rules: RuleEngine,
    loaded_count: usize,
}

async fn load_rules_from_command(
    path: &str,
    state: &mut DaemonState,
    rules: &mut RuleEngine,
    output: Arc<dyn EngineOutput>,
    listener_runtime: Arc<dyn DaemonListenerRuntime>,
) -> CommandResponse {
    let candidate = build_rule_reload_candidate(path, rules)?;

    prepare_listener_for_rule_reload(state, &candidate.rules, output, listener_runtime).await?;
    replace_rules_after_reload(rules, candidate.rules);

    Ok(format!("loaded {} rule(s)", candidate.loaded_count))
}

fn build_rule_reload_candidate(path: &str, rules: &RuleEngine) -> Result<RuleReloadCandidate> {
    let loaded_rules = RuleEngine::load_rules_from_path(path).map_err(anyhow::Error::from)?;
    let mut candidate_rules = rules.clone();
    candidate_rules.replace_rules(loaded_rules);
    let loaded_count = candidate_rules.len();

    if candidate_rules.has_receive_triggers() {
        ensure_listener_feature_available()?;
    }

    Ok(RuleReloadCandidate {
        rules: candidate_rules,
        loaded_count,
    })
}

async fn prepare_listener_for_rule_reload(
    state: &mut DaemonState,
    candidate_rules: &RuleEngine,
    output: Arc<dyn EngineOutput>,
    listener_runtime: Arc<dyn DaemonListenerRuntime>,
) -> Result<()> {
    if candidate_rules.has_receive_triggers() {
        let options = state
            .listener_options
            .clone()
            .unwrap_or_else(default_listener_options);
        return start_listener(state, options, candidate_rules, output, listener_runtime)
            .await
            .map_err(|err| {
                warn!("failed to restart listener after rule reload: {err}");
                anyhow!("loaded rules but failed to restart listener: {err}")
            });
    }

    if listener_is_active(state) {
        warn!("no receive rules after reload; stopping listener");
    }
    stop_listener(state).await
}

fn replace_rules_after_reload(rules: &mut RuleEngine, candidate_rules: RuleEngine) {
    *rules = candidate_rules;
    if rules.has_startup_triggers() {
        debug!("Running startup actions after rule reload");
        rules.run_startup_actions();
    }
}

async fn start_listener(
    state: &mut DaemonState,
    options: ListenerRequest,
    rules: &RuleEngine,
    output: Arc<dyn EngineOutput>,
    listener_runtime: Arc<dyn DaemonListenerRuntime>,
) -> Result<()> {
    start_listener_with_interface_hint(state, options, rules, output, listener_runtime, None).await
}

async fn start_listener_with_interface_hint(
    state: &mut DaemonState,
    mut options: ListenerRequest,
    rules: &RuleEngine,
    output: Arc<dyn EngineOutput>,
    listener_runtime: Arc<dyn DaemonListenerRuntime>,
    interface_hint: Option<&str>,
) -> Result<()> {
    ensure_listener_feature_available()?;
    listener_runtime.validate_options(&options)?;
    stop_listener(state).await?;
    let shutdown = Arc::new(AtomicBool::new(true));
    let (startup_tx, startup_rx) = oneshot::channel();
    let handle = listener_runtime.spawn_background(
        options.clone(),
        interface_hint.map(str::to_string),
        listener_event_handler(rules, output),
        shutdown.clone(),
        Some(startup_tx),
    )?;
    match time::timeout(LISTENER_STARTUP_TIMEOUT, startup_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(message))) => {
            shutdown.store(false, Ordering::SeqCst);
            let _ = stop_joined_listener(handle).await;
            return Err(anyhow!(message));
        }
        Ok(Err(_)) => {
            shutdown.store(false, Ordering::SeqCst);
            return stop_unacknowledged_listener(handle).await;
        }
        Err(_) => {
            debug!("listener startup acknowledgement timed out; treating listener as active");
        }
    }
    state.listener = Some(ActiveListener { shutdown, handle });
    options.listen = Some(true);
    state.listener_options = Some(options);
    Ok(())
}

fn listener_event_handler(
    rules: &RuleEngine,
    output: Arc<dyn EngineOutput>,
) -> ListenerEventHandler {
    let rules = rules.clone();

    Arc::new(move |event| {
        output.emit_listener_event(&event);

        if rules.is_empty() {
            return;
        }

        let context = crate::rules::PacketContext::from_listener_event(&event);
        rules.notify_receive(&context);
    })
}

pub(crate) fn ensure_listener_feature_available() -> Result<()> {
    #[cfg(not(feature = "pcap"))]
    {
        Err(anyhow!("listener support requires the 'pcap' feature"))
    }

    #[cfg(feature = "pcap")]
    {
        Ok(())
    }
}

fn listener_is_active(state: &DaemonState) -> bool {
    state
        .listener
        .as_ref()
        .is_some_and(|listener| !listener.handle.is_finished())
}

async fn stop_listener(state: &mut DaemonState) -> Result<()> {
    if let Some(active) = state.listener.take() {
        active.shutdown.store(false, Ordering::SeqCst);
        let mut handle = active.handle;
        tokio::select! {
            res = &mut handle => {
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!("listener task ended with error: {err}");
                    }
                    Err(join_err) => {
                        warn!("listener task join failed: {join_err}");
                        Err(join_err)?;
                    }
                }
            }
            _ = time::sleep(LISTENER_SHUTDOWN_TIMEOUT) => {
                warn!(
                    "listener did not shut down gracefully within {}s; aborting",
                    LISTENER_SHUTDOWN_TIMEOUT.as_secs()
                );
                handle.abort();
                match handle.await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!("listener task ended with error after abort: {err}");
                    }
                    Err(join_err) if join_err.is_cancelled() => {}
                    Err(join_err) => {
                        warn!("listener task join failed after abort: {join_err}");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn stop_joined_listener(handle: tokio::task::JoinHandle<anyhow::Result<()>>) -> Result<()> {
    match handle.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(join_err) => Err(anyhow::Error::from(join_err)),
    }
}

async fn stop_unacknowledged_listener(
    mut handle: tokio::task::JoinHandle<anyhow::Result<()>>,
) -> Result<()> {
    let missing_ack =
        || anyhow!("listener startup ended before the capture worker reported readiness");

    tokio::select! {
        result = &mut handle => {
            match result {
                Ok(Ok(())) => Err(missing_ack()),
                Ok(Err(err)) => Err(err),
                Err(join_err) => Err(anyhow::Error::from(join_err)),
            }
        }
        _ = time::sleep(LISTENER_SHUTDOWN_TIMEOUT) => {
            handle.abort();
            let _ = handle.await;
            Err(missing_ack())
        }
    }
}

fn send_response(tx: oneshot::Sender<CommandResponse>, result: CommandResponse) {
    if let Err(result) = tx.send(result) {
        match result {
            Ok(message) => {
                warn!("failed to deliver daemon response '{message}'; receiver dropped before receiving it")
            }
            Err(err) => {
                warn!("failed to deliver daemon error response: {err}");
            }
        }
    }
}

fn default_listener_options() -> ListenerRequest {
    ListenerRequest {
        listen: Some(true),
        ..Default::default()
    }
}
