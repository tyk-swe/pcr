// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;
#[cfg(feature = "pcap")]
use tokio::task::JoinError;

#[cfg(feature = "pcap")]
use crate::network::interface::InterfaceError;

#[derive(Debug, Error)]
pub(crate) enum ListenerError {
    #[cfg(not(feature = "pcap"))]
    #[error("listener capture requires PacketcraftR to be built with the 'pcap' feature")]
    ListenerRequiresPcap,
    #[cfg(all(not(feature = "pcap"), feature = "daemon"))]
    #[error("--filter requires Packetcraft to be built with the 'pcap' feature")]
    FilterRequiresPcap,
    #[cfg(all(not(feature = "pcap"), feature = "daemon"))]
    #[error("--pcap-save requires Packetcraft to be built with the 'pcap' feature")]
    CaptureRequiresPcap,
    #[cfg(any(feature = "daemon", feature = "pcap"))]
    #[error("--queue-capacity must be greater than zero")]
    QueueCapacityZero,
    #[cfg(any(feature = "daemon", feature = "pcap"))]
    #[error("--queue-capacity must not exceed {max} entries")]
    QueueCapacityTooLarge { max: usize },
    #[cfg(feature = "pcap")]
    #[error("listener queue_capacity must be greater than zero when supplied")]
    SpecQueueCapacityZero,
    #[cfg(feature = "pcap")]
    #[error("listener queue_capacity must not exceed {max} entries")]
    SpecQueueCapacityTooLarge { max: usize },
    #[cfg(feature = "pcap")]
    #[error("validate captured frame length failed: len={len} bytes")]
    CaptureFrameLength {
        len: usize,
        #[source]
        source: std::num::TryFromIntError,
    },
    #[cfg(feature = "pcap")]
    #[error(
        "failed to determine capture interface{hint}",
        hint = match hint {
            Some(value) => format!(" for hint={value}"),
            None => String::new(),
        }
    )]
    InterfaceLookup {
        hint: Option<String>,
        #[source]
        source: InterfaceError,
    },
    #[cfg(feature = "pcap")]
    #[error("failed to join capture task: task panicked or was cancelled")]
    CaptureTaskJoin {
        #[from]
        source: JoinError,
    },
    #[cfg(feature = "pcap")]
    #[error("capture worker task aborted before completion")]
    CaptureWorkerAborted {
        #[source]
        source: JoinError,
    },
    #[cfg(feature = "pcap")]
    #[error("error reading packet from {interface}")]
    CaptureRead {
        interface: String,
        #[source]
        source: std::io::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("error reading packet from {interface} via pcap")]
    CaptureReadPcap {
        interface: String,
        #[source]
        source: pcap::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("create pcap directory failed: path={path}")]
    CaptureDirectory {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("create pcap capture handle failed: Capture::dead returned error")]
    CaptureHandle {
        #[source]
        source: pcap::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("open listener capture failed: path={path}")]
    CaptureOpen {
        path: String,
        #[source]
        source: pcap::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("flush listener capture failed: savefile flush error")]
    CaptureFlush {
        #[source]
        source: pcap::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("pcap device {name} not found")]
    PcapDeviceNotFound { name: String },
    #[cfg(feature = "pcap")]
    #[error("pcap device enumeration failed")]
    PcapDeviceList {
        #[source]
        source: pcap::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("failed to open datalink channel on {interface}")]
    CaptureChannel {
        interface: String,
        #[source]
        source: std::io::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("interface {interface} does not support Ethernet channel operations")]
    UnsupportedChannel { interface: String },
    #[cfg(feature = "pcap")]
    #[error("failed to apply BPF filter '{filter}' on {interface}: {detail}")]
    BpfFilterFailed {
        filter: String,
        interface: String,
        detail: String,
    },
}
