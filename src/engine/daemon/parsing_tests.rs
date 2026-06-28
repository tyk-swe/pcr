// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::os::unix::fs::FileTypeExt;
use tokio::sync::mpsc;

async fn mock_daemon_loop(mut rx: mpsc::Receiver<DaemonCommand>) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            DaemonCommand::Status { respond_to } => {
                let _ = respond_to.send(Ok("rules=0".to_string()));
            }
            DaemonCommand::LoadRules { path, respond_to } => {
                let _ = respond_to.send(Ok(format!("loaded {}", path)));
            }
            DaemonCommand::Listen {
                options: _,
                respond_to,
            } => {
                let _ = respond_to.send(Ok("listener active".to_string()));
            }
            DaemonCommand::StopListener { respond_to } => {
                let _ = respond_to.send(Ok("listener stopped".to_string()));
            }
            DaemonCommand::Shutdown { respond_to } => {
                let _ = respond_to.send(Ok("shutting down".to_string()));
            }
        }
    }
}

fn is_permission_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            return io_err.kind() == std::io::ErrorKind::PermissionDenied;
        }
        let message = cause.to_string();
        message.contains("Operation not permitted") || message.contains("permission denied")
    })
}

#[tokio::test]
async fn dispatch_text_command_status() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let response = dispatch_text_command("status", &tx).await.unwrap();
    assert_eq!(response, "OK rules=0");
}

#[tokio::test]
async fn dispatch_text_command_load() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let response = dispatch_text_command("load /tmp/rules.yaml", &tx)
        .await
        .unwrap();
    assert_eq!(response, "OK loaded /tmp/rules.yaml");
}

#[tokio::test]
async fn dispatch_text_command_load_preserves_spaces_in_path() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let response = dispatch_text_command("load /tmp/rules with spaces.yaml", &tx)
        .await
        .unwrap();
    assert_eq!(response, "OK loaded /tmp/rules with spaces.yaml");
}

#[tokio::test]
async fn dispatch_text_command_listen_stop() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let response = dispatch_text_command("listen stop", &tx).await.unwrap();
    assert_eq!(response, "OK listener stopped");
}

#[tokio::test]
async fn dispatch_text_command_shutdown() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let response = dispatch_text_command("shutdown", &tx).await.unwrap();
    assert_eq!(response, "OK shutting down");
}

#[tokio::test]
async fn dispatch_text_command_unknown() {
    let (tx, _rx) = mpsc::channel(8);
    let result = dispatch_text_command("unknown_cmd", &tx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn dispatch_json_command_status() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let cmd = JsonCommand::Status;
    let response = dispatch_json_command(cmd, &tx).await.unwrap();
    assert_eq!(response, "OK rules=0");
}

#[tokio::test]
async fn dispatch_control_command_detects_json() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let line = r#"{"command": "status"}"#;
    let response = dispatch_control_command(line, &tx).await.unwrap();
    assert_eq!(response, "OK rules=0");
}

#[tokio::test]
async fn dispatch_control_command_falls_back_to_text() {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(mock_daemon_loop(rx));
    let line = "status";
    let response = dispatch_control_command(line, &tx).await.unwrap();
    assert_eq!(response, "OK rules=0");
}

#[tokio::test]
async fn reject_huge_line() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let (mut client, server) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("failed to create unix stream pair: {err}"),
    };
    let (tx, _rx) = mpsc::channel(8);

    // Spawn handler
    tokio::spawn(async move {
        handle_control_stream(server, tx).await.ok();
    });

    // Construct a huge line
    let huge_line = vec![b'a'; super::MAX_CONTROL_LINE_BYTES + 10];
    if let Err(err) = client.write_all(&huge_line).await {
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("failed to write huge line: {err}");
    }
    if let Err(err) = client.write_all(b"\n").await {
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("failed to write newline: {err}");
    }

    // Read response
    let mut buf = [0u8; 1024];
    let n = match client.read(&mut buf).await {
        Ok(n) => n,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("failed to read control response: {err}"),
    };
    let response = String::from_utf8_lossy(&buf[..n]);

    assert!(response.contains("ERR line too long") || n == 0);
}

#[tokio::test]
async fn spawn_control_socket_refuses_regular_file() {
    use std::fs::File;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_file");
    File::create(&file_path).unwrap();

    let (tx, _rx) = mpsc::channel(8);
    let result = spawn_control_socket(file_path.to_str().unwrap(), tx);

    assert!(result.is_err(), "should refuse to overwrite regular file");
    assert!(file_path.exists(), "should not delete regular file");
}

#[tokio::test]
async fn spawn_control_socket_cleans_up_stale_socket() {
    use std::os::unix::net::UnixListener;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("stale.sock");
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("failed to bind stale socket: {err}"),
    };
    drop(listener);

    assert!(socket_path.exists());

    let (tx, _rx) = mpsc::channel(8);
    let result = spawn_control_socket(socket_path.to_str().unwrap(), tx);
    match result {
        Ok(handle) => {
            handle.abort();
        }
        Err(err) if is_permission_error(&err) => return,
        Err(err) => panic!("should replace stale socket: {err}"),
    }
}

#[tokio::test]
async fn spawn_control_socket_cleans_up_symlink() {
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    let dir = tempdir().unwrap();
    let symlink_path = dir.path().join("socket_link");
    let target_path = dir.path().join("target_file");

    // Create a symlink pointing to a non-existent file (broken link)
    // or a real file. Either way, we should remove the symlink itself.
    // Let's test broken link first as it's common for stale state.
    symlink(&target_path, &symlink_path).unwrap();

    let (tx, _rx) = mpsc::channel(8);
    let result = spawn_control_socket(symlink_path.to_str().unwrap(), tx);

    let handle = match result {
        Ok(handle) => handle,
        Err(err) if is_permission_error(&err) => return,
        Err(err) => panic!("should replace symlink: {err}"),
    };
    handle.abort();

    assert!(
        std::fs::symlink_metadata(&symlink_path)
            .unwrap()
            .file_type()
            .is_socket(),
        "path should now be a socket"
    );
}
