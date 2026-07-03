// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::warn;
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

use crate::domain::request::ListenerRequest;

use super::{CommandResponse, DaemonCommand};

pub(super) const MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;
const COMMAND_QUEUE_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const COMMAND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct ActiveControlSocket {
    handle: tokio::task::JoinHandle<()>,
    path: String,
}

fn operation_failed(operation: &str, details: impl std::fmt::Display) -> String {
    format!("{operation} failed: {details}")
}

pub(super) fn preflight_control_socket(path: &str) -> Result<()> {
    use std::os::unix::net::UnixListener;

    prepare_control_socket_path(path)?;
    let socket_path = std::path::Path::new(path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| operation_failed("bind control socket", format!("path={path}")))?;
    drop(listener);
    cleanup_control_socket_path(path);
    Ok(())
}

pub(super) fn spawn_control_socket(
    path: &str,
    tx: mpsc::Sender<DaemonCommand>,
) -> Result<ActiveControlSocket> {
    use tokio::net::UnixListener;

    let socket_path = std::path::Path::new(path);
    prepare_control_socket_path(path)?;

    let listener = UnixListener::bind(socket_path)
        .with_context(|| operation_failed("bind control socket", format!("path={path}")))?;

    let mut perms = std::fs::metadata(socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(socket_path, perms).with_context(|| {
        operation_failed("set control socket permissions", format!("path={path}"))
    })?;

    let daemon_uid = nix::unistd::getuid().as_raw();

    let handle = tokio::spawn(async move {
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
    });

    Ok(ActiveControlSocket {
        handle,
        path: path.to_string(),
    })
}

pub(super) async fn cleanup_control_socket(control_socket: &mut Option<ActiveControlSocket>) {
    if let Some(ActiveControlSocket { handle, path }) = control_socket.take() {
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
}

fn prepare_control_socket_path(path: &str) -> Result<()> {
    let socket_path = std::path::Path::new(path);

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
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).context(operation_failed(
                "inspect existing socket path",
                format!("path={path}"),
            ));
        }
    }

    Ok(())
}

fn cleanup_control_socket_path(path: &str) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let _ = std::fs::remove_file(path);
        }
        _ => {}
    }
}

fn sanitize_log_fragment(input: &str) -> String {
    input.chars().filter(|c| !c.is_control()).collect()
}

pub(super) async fn handle_control_stream(
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

pub(super) async fn dispatch_control_command(
    line: &str,
    tx: &mpsc::Sender<DaemonCommand>,
) -> Result<String> {
    if let Ok(json_cmd) = serde_json::from_str::<JsonCommand>(line) {
        return dispatch_json_command(json_cmd, tx).await;
    }

    dispatch_text_command(line, tx).await
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub(super) enum JsonCommand {
    Status,
    LoadRules { path: String },
    Listen { options: ListenerRequest },
    StopListener,
    Shutdown,
}

pub(super) async fn dispatch_json_command(
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

pub(super) async fn dispatch_text_command(
    line: &str,
    tx: &mpsc::Sender<DaemonCommand>,
) -> Result<String> {
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
    let response = time::timeout(COMMAND_RESPONSE_TIMEOUT, resp_rx)
        .await
        .map_err(|_| anyhow!("command timed out"))?
        .map_err(|_| anyhow!("command response channel closed"))?;
    match response {
        Ok(message) => Ok(format!("OK {message}")),
        Err(err) => Ok(format!("ERR {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_ok(respond_to: oneshot::Sender<CommandResponse>, message: &str) {
        respond_to.send(Ok(message.to_string())).unwrap();
    }

    #[tokio::test]
    async fn dispatch_text_status_maps_to_status_command() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::Status { respond_to } => send_ok(respond_to, "ready"),
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response = dispatch_text_command("status", &tx).await.unwrap();

        assert_eq!(response, "OK ready");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_text_load_maps_trimmed_path() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::LoadRules { path, respond_to } => {
                    assert_eq!(path, "/tmp/rules.yml");
                    send_ok(respond_to, "loaded");
                }
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response = dispatch_text_command("load   /tmp/rules.yml  ", &tx)
            .await
            .unwrap();

        assert_eq!(response, "OK loaded");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_text_listen_stop_maps_to_stop_listener() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::StopListener { respond_to } => send_ok(respond_to, "stopped"),
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response = dispatch_text_command("listen stop", &tx).await.unwrap();

        assert_eq!(response, "OK stopped");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_text_shutdown_maps_to_shutdown() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::Shutdown { respond_to } => send_ok(respond_to, "bye"),
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response = dispatch_text_command("shutdown", &tx).await.unwrap();

        assert_eq!(response, "OK bye");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_json_status_maps_to_status_command() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::Status { respond_to } => send_ok(respond_to, "json-ready"),
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response = dispatch_control_command(r#"{"command":"status"}"#, &tx)
            .await
            .unwrap();

        assert_eq!(response, "OK json-ready");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_json_load_rules_maps_path() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::LoadRules { path, respond_to } => {
                    assert_eq!(path, "rules.yml");
                    send_ok(respond_to, "loaded");
                }
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response =
            dispatch_control_command(r#"{"command":"load_rules","path":"rules.yml"}"#, &tx)
                .await
                .unwrap();

        assert_eq!(response, "OK loaded");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_json_listen_maps_options() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::Listen {
                    options,
                    respond_to,
                } => {
                    assert_eq!(options.filter.as_deref(), Some("icmp"));
                    assert_eq!(options.promiscuous, Some(true));
                    assert_eq!(options.timeout, Some(5));
                    send_ok(respond_to, "listening");
                }
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response = dispatch_control_command(
            r#"{"command":"listen","options":{"filter":"icmp","promiscuous":true,"timeout":5}}"#,
            &tx,
        )
        .await
        .unwrap();

        assert_eq!(response, "OK listening");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_json_shutdown_maps_to_shutdown() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::Shutdown { respond_to } => send_ok(respond_to, "shutting down"),
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let response = dispatch_control_command(r#"{"command":"shutdown"}"#, &tx)
            .await
            .unwrap();

        assert_eq!(response, "OK shutting down");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_text_invalid_commands_return_errors() {
        let (tx, _rx) = mpsc::channel(1);

        assert!(dispatch_text_command("bogus", &tx)
            .await
            .unwrap_err()
            .to_string()
            .contains("unknown command"));
        assert!(dispatch_text_command("load", &tx)
            .await
            .unwrap_err()
            .to_string()
            .contains("requires a path"));
        assert!(dispatch_text_command("listen start", &tx)
            .await
            .unwrap_err()
            .to_string()
            .contains("requires subcommand"));
    }

    #[tokio::test]
    async fn dispatch_reports_closed_daemon_channel() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        let err = dispatch_text_command("status", &tx).await.unwrap_err();

        assert!(err.to_string().contains("daemon channel closed"));
    }

    #[tokio::test]
    async fn dispatch_reports_dropped_response_channel() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            match rx.recv().await.unwrap() {
                DaemonCommand::Status { respond_to } => drop(respond_to),
                other => panic!("unexpected command: {other:?}"),
            }
        });

        let err = dispatch_text_command("status", &tx).await.unwrap_err();

        assert!(err.to_string().contains("command response channel closed"));
        task.await.unwrap();
    }

    #[test]
    fn sanitize_log_fragment_removes_control_characters() {
        assert_eq!(
            sanitize_log_fragment("accept\nfailed\t\u{7f}"),
            "acceptfailed"
        );
    }
}
