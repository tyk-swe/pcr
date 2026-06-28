// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, MissedTickBehavior};

use crate::engine::command::DaemonRequest;
use crate::engine::request::ListenerRequest;
use crate::engine::EngineConfig;
use crate::network::listener;
use crate::output::OutputController;
use crate::rules::RuleEngine;
use crate::util::error::operation_failed;

const TIMER_TICK: Duration = Duration::from_secs(5);
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;
const CONTROL_COMMAND_QUEUE_CAPACITY: usize = 512;
const COMMAND_QUEUE_SEND_TIMEOUT: Duration = Duration::from_secs(2);

type CommandResponse = anyhow::Result<String>;

pub async fn run(
    opts: &DaemonRequest,
    config: &EngineConfig,
    rules: &mut RuleEngine,
    output: &OutputController,
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
            Ok(handle) => Some((handle, path.clone())),
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
        start_listener(
            &mut state,
            default_listener_options(),
            config,
            rules,
            output,
        )
        .await?;
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
                    if handle_command(command, &mut state, rules, config, output).await? {
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
                if handle_command(command, &mut state, rules, config, output).await? {
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
    if let Some((handle, path)) = control_socket.take() {
        handle.abort();
        let _ = handle.await;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                if let Err(err) = std::fs::remove_file(&path) {
                    warn!("failed to remove control socket '{}': {err}", path);
                }
            }
            Ok(_) => {
                warn!(
                    "control socket cleanup skipped for '{}': path is not a socket",
                    path
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => warn!(
                "failed to inspect control socket path '{}' during cleanup: {}",
                path, err
            ),
        }
    }

    info!("Daemon shutdown complete");
    Ok(())
}

struct ActiveListener {
    shutdown: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<crate::network::listener::ListenerResult<()>>,
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

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;
    use crate::rules::RuleSendExecutor;

    #[tokio::test]
    async fn control_socket_is_rejected_on_non_unix() {
        let opts = DaemonRequest {
            rules_file: None,
            foreground: Some(false),
            control_socket: Some("/tmp/pc.sock".to_string()),
        };

        let config = EngineConfig {
            output_format: None,
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            allow_unbounded_sends: false,
            dry_run: false,
        };

        let mut rules = RuleEngine::new().expect("rule engine initialisation");
        rules.configure_sender(RuleSendExecutor::new().expect("rule send executor initialisation"));
        let output = OutputController::new(None);

        let result = run(&opts, &config, &mut rules, &output).await;
        assert!(
            result.is_err(),
            "control socket should be rejected on non-Unix targets"
        );
    }
}

#[cfg(test)]
mod command_tests;

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
    config: &EngineConfig,
    output: &OutputController,
) -> Result<bool> {
    match command {
        DaemonCommand::LoadRules { path, respond_to } => {
            let candidate_result: Result<(RuleEngine, usize)> =
                RuleEngine::load_rules_from_path(&path)
                    .map_err(anyhow::Error::from)
                    .and_then(|loaded_rules| {
                        let mut candidate_rules = rules.clone();
                        candidate_rules.replace_rules(loaded_rules);
                        let loaded_count = candidate_rules.len();

                        if candidate_rules.has_receive_triggers() {
                            ensure_listener_feature_available()?;
                        }

                        Ok((candidate_rules, loaded_count))
                    });

            let result: CommandResponse = match candidate_result {
                Ok((candidate_rules, loaded_count)) => {
                    if candidate_rules.has_receive_triggers() {
                        let options = state
                            .listener_options
                            .clone()
                            .unwrap_or_else(default_listener_options);
                        match start_listener(state, options, config, &candidate_rules, output).await
                        {
                            Ok(()) => {
                                *rules = candidate_rules;
                                if rules.has_startup_triggers() {
                                    debug!("Running startup actions after rule reload");
                                    rules.run_startup_actions();
                                }
                                Ok(format!("loaded {loaded_count} rule(s)"))
                            }
                            Err(err) => {
                                warn!("failed to restart listener after rule reload: {err}");
                                Err(anyhow!(
                                    "loaded rules but failed to restart listener: {err}"
                                ))
                            }
                        }
                    } else {
                        if listener_is_active(state) {
                            warn!("no receive rules after reload; stopping listener");
                        }
                        match stop_listener(state).await {
                            Ok(()) => {
                                *rules = candidate_rules;
                                if rules.has_startup_triggers() {
                                    debug!("Running startup actions after rule reload");
                                    rules.run_startup_actions();
                                }
                                Ok(format!("loaded {loaded_count} rule(s)"))
                            }
                            Err(err) => Err(err),
                        }
                    }
                }
                Err(err) => Err(err),
            };

            send_response(respond_to, result);
            Ok(false)
        }
        DaemonCommand::Listen {
            options,
            respond_to,
        } => {
            let mut opts = options;
            opts.listen = Some(true);
            let outcome = start_listener(state, opts.clone(), config, rules, output)
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

async fn start_listener(
    state: &mut DaemonState,
    mut options: ListenerRequest,
    config: &EngineConfig,
    rules: &RuleEngine,
    output: &OutputController,
) -> Result<()> {
    ensure_listener_feature_available()?;
    listener::validate_options(&options).map_err(anyhow::Error::from)?;
    stop_listener(state).await?;
    let shutdown = Arc::new(AtomicBool::new(true));
    let handle = listener::spawn_background(
        &options,
        None,
        config,
        listener_event_handler(rules, output),
        shutdown.clone(),
    )
    .map_err(anyhow::Error::from)?;
    state.listener = Some(ActiveListener { shutdown, handle });
    options.listen = Some(true);
    state.listener_options = Some(options);
    Ok(())
}

fn listener_event_handler(
    rules: &RuleEngine,
    output: &OutputController,
) -> listener::ListenerEventHandler {
    let rules = rules.clone();
    let output = output.clone();

    Arc::new(move |event| {
        output.emit_listener_event(&event);

        if rules.is_empty() {
            return;
        }

        let context = crate::engine::event::listener_event_rule_context(&event);
        rules.notify_receive(&context);
    })
}

fn ensure_listener_feature_available() -> Result<()> {
    #[cfg(not(feature = "pcap"))]
    {
        Err(anyhow::Error::new(
            listener::ListenerError::ListenerRequiresPcap,
        ))
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

#[cfg(unix)]
fn sanitize_log_fragment(input: &str) -> String {
    input.chars().filter(|c| !c.is_control()).collect()
}

fn default_listener_options() -> ListenerRequest {
    ListenerRequest {
        listen: Some(true),
        ..Default::default()
    }
}

#[cfg(unix)]
fn spawn_control_socket(
    path: &str,
    tx: mpsc::Sender<DaemonCommand>,
) -> Result<tokio::task::JoinHandle<()>> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use tokio::net::UnixListener;

    let socket_path = std::path::Path::new(path);

    // Use symlink_metadata to inspect the file itself, not what it points to.
    // This allows safe cleanup of symlinks (which remove_file handles) and
    // detection of broken symlinks, while refusing to delete actual files.
    match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_socket() || file_type.is_symlink() {
                if let Err(source) = std::fs::remove_file(socket_path) {
                    if source.kind() == std::io::ErrorKind::PermissionDenied {
                        return Err(anyhow::anyhow!(
                            "{}",
                            operation_failed(
                                "remove stale socket",
                                format!("path={path}; permission denied ({source})")
                            )
                        ));
                    }
                    return Err(anyhow::Error::new(source).context(operation_failed(
                        "remove stale socket",
                        format!("path={path}"),
                    )));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "control socket path exists but is not a socket or symlink: {}",
                    path
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Path does not exist; safe to bind
        }
        Err(err) => {
            return Err(err).context(operation_failed(
                "inspect existing socket path",
                format!("path={path}"),
            ));
        }
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| operation_failed("bind control socket", format!("path={path}")))?;

    let mut perms = std::fs::metadata(socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(socket_path, perms).with_context(|| {
        operation_failed("set control socket permissions", format!("path={path}"))
    })?;

    // Use nix wrapper for safe getuid call
    let daemon_uid = nix::unistd::getuid().as_raw();

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => match stream.peer_cred() {
                    Ok(peer) if peer.uid() == daemon_uid => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_control_stream(stream, tx).await {
                                warn!("control connection error: {err}");
                            }
                        });
                    }
                    Ok(peer) => {
                        warn!(
                                "control socket connection rejected from uid {}: does not match daemon uid {}",
                                peer.uid(),
                                daemon_uid
                            );
                    }
                    Err(err) => {
                        let clean_err = sanitize_log_fragment(&err.to_string());
                        warn!(
                            "control socket connection rejected: failed to get peer credentials: {}",
                            clean_err
                        );
                    }
                },
                Err(err) => {
                    let clean_err = sanitize_log_fragment(&err.to_string());
                    warn!("control socket accept failed: {}", clean_err);
                    break;
                }
            }
        }
    }))
}

#[cfg(unix)]
async fn handle_control_stream(
    stream: tokio::net::UnixStream,
    tx: mpsc::Sender<DaemonCommand>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();

    loop {
        buf.clear();
        let mut line_complete = false;

        while !line_complete {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                break;
            }

            let (chunk, consumed, found_newline) =
                if let Some(i) = available.iter().position(|&b| b == b'\n') {
                    (&available[..=i], i + 1, true)
                } else {
                    (available, available.len(), false)
                };

            if buf.len() + chunk.len() > MAX_CONTROL_LINE_BYTES {
                let message = "ERR line too long";
                writer.write_all(message.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                return Ok(());
            }

            buf.extend_from_slice(chunk);
            reader.consume(consumed);

            if found_newline {
                line_complete = true;
            }
        }

        if buf.is_empty() {
            break;
        }

        // Convert to string, checking for valid UTF-8
        let line_str = match String::from_utf8(buf.clone()) {
            Ok(s) => s,
            Err(_) => {
                let message = "ERR invalid utf8";
                writer.write_all(message.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let line = line_str.trim();
        if line.is_empty() {
            continue;
        }

        match dispatch_control_command(line, &tx).await {
            Ok(response) => {
                writer.write_all(response.as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }
            Err(err) => {
                let message = format!("ERR {err}");
                writer.write_all(message.as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn dispatch_control_command(line: &str, tx: &mpsc::Sender<DaemonCommand>) -> Result<String> {
    // Try to parse as JSON first for structured communication
    if let Ok(json_cmd) = serde_json::from_str::<JsonCommand>(line) {
        return dispatch_json_command(json_cmd, tx).await;
    }

    // Fall back to simple text commands for backward compatibility and manual testing
    dispatch_text_command(line, tx).await
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum JsonCommand {
    Status,
    LoadRules { path: String },
    Listen { options: ListenerRequest },
    StopListener,
    Shutdown,
}

#[cfg(unix)]
async fn dispatch_json_command(
    cmd: JsonCommand,
    tx: &mpsc::Sender<DaemonCommand>,
) -> Result<String> {
    match cmd {
        JsonCommand::Status => {
            request_response_with_builder(tx, |respond_to| DaemonCommand::Status { respond_to })
                .await
        }
        JsonCommand::LoadRules { path } => {
            request_response_with_builder(tx, move |respond_to| DaemonCommand::LoadRules {
                path,
                respond_to,
            })
            .await
        }
        JsonCommand::Listen { options } => {
            request_response_with_builder(tx, move |respond_to| DaemonCommand::Listen {
                options,
                respond_to,
            })
            .await
        }
        JsonCommand::StopListener => {
            request_response_with_builder(tx, |respond_to| DaemonCommand::StopListener {
                respond_to,
            })
            .await
        }
        JsonCommand::Shutdown => {
            request_response_with_builder(tx, |respond_to| DaemonCommand::Shutdown { respond_to })
                .await
        }
    }
}

#[cfg(unix)]
async fn dispatch_text_command(line: &str, tx: &mpsc::Sender<DaemonCommand>) -> Result<String> {
    let trimmed = line.trim();
    let mut command_parts = trimmed.splitn(2, char::is_whitespace);
    let command = command_parts
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| anyhow!("empty command"))?;
    let remainder = command_parts.next().map(str::trim).unwrap_or_default();

    match command {
        "status" => {
            request_response_with_builder(tx, |respond_to| DaemonCommand::Status { respond_to })
                .await
        }
        "load" => {
            if remainder.is_empty() {
                anyhow::bail!("load command requires a path");
            }

            let path = remainder.to_string();
            request_response_with_builder(tx, move |respond_to| DaemonCommand::LoadRules {
                path,
                respond_to,
            })
            .await
        }
        "listen" => {
            if remainder == "stop" {
                request_response_with_builder(tx, |respond_to| DaemonCommand::StopListener {
                    respond_to,
                })
                .await
            } else {
                anyhow::bail!(
                    "listen command requires subcommand 'stop' or JSON format for options"
                )
            }
        }
        "shutdown" => {
            request_response_with_builder(tx, |respond_to| DaemonCommand::Shutdown { respond_to })
                .await
        }
        other => Err(anyhow!("unknown command: {other}")),
    }
}

async fn request_response_with_builder<F>(
    tx: &mpsc::Sender<DaemonCommand>,
    build: F,
) -> Result<String>
where
    F: FnOnce(oneshot::Sender<CommandResponse>) -> DaemonCommand,
{
    let (resp_tx, resp_rx) = oneshot::channel();
    let command = build(resp_tx);
    time::timeout(COMMAND_QUEUE_SEND_TIMEOUT, tx.send(command))
        .await
        .map_err(|_| anyhow!("daemon command queue is full; try again"))?
        .map_err(|_| anyhow!("daemon channel closed"))?;
    let response = time::timeout(Duration::from_secs(10), resp_rx)
        .await
        .map_err(|_| anyhow!("command timed out"))?
        .map_err(|_| anyhow!("command response channel closed"))?;
    match response {
        Ok(message) => Ok(format!("OK {message}")),
        Err(err) => Ok(format!("ERR {err}")),
    }
}

#[cfg(all(test, unix))]
mod parsing_tests;
