// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, PrivilegeError>;

#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[error("failed to create raw socket: CAP_NET_RAW capability not available")]
    RawSocketUnavailable {
        #[source]
        source: std::io::Error,
    },
    #[error(
        "raw socket operations require root privileges (UID=0) or CAP_NET_RAW capability.\n\
         To grant CAP_NET_RAW to this binary, run:\n  sudo setcap cap_net_raw+ep {binary}"
    )]
    MissingCapability {
        binary: PathBuf,
        #[source]
        source: Option<Box<PrivilegeError>>,
    },
}

pub fn assert_raw_socket_capability() -> Result<()> {
    #[cfg(unix)]
    if nix::unistd::geteuid().is_root() {
        // Fast path: root has all capabilities
        return Ok(());
    }

    // Slow path: test if we actually have CAP_NET_RAW by attempting to create a raw socket
    // This handles file capabilities, ambient capabilities, and bounding sets reliably
    match try_create_raw_socket() {
        Ok(_) => Ok(()),
        Err(err) => {
            let binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("packetcraftr"));
            Err(PrivilegeError::MissingCapability {
                binary,
                source: Some(Box::new(err)),
            })
        }
    }
}

/// Try to create a raw socket to test for CAP_NET_RAW capability.
/// This is the most reliable way to check for raw socket permissions.
fn try_create_raw_socket() -> Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) // Attempt raw socket creation (requires CAP_NET_RAW)
        .map_err(|source| PrivilegeError::RawSocketUnavailable { source })?;

    drop(socket);
    Ok(())
}
