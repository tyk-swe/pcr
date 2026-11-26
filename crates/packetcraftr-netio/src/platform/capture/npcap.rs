// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::platform::common::npcap::handles::{
    NpcapBreakLoop, NpcapHandle, PromiscuousMode, create_handle, open_handle,
};
use crate::{
    Error,
    capture::live::{
        CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
        NativeCaptureStats,
    },
    capture::{Limits, Metadata, NativeSettings, TimestampPrecision, TimestampType},
    interface::Id as InterfaceId,
    platform::common::pcap_api::{
        Diagnostic, PCAP_NETMASK_UNKNOWN, canonical_link_type, realize_settings,
        validate_effective_snapshot_length,
    },
};

pub(crate) fn open_capture(
    interface: &InterfaceId,
    limits: Limits,
    capture_filter: Option<&str>,
    netmask: Option<u32>,
    promiscuous: bool,
    native: &NativeSettings,
) -> Result<NativeCaptureParts, Error> {
    let snap_length =
        i32::try_from(limits.snap_length).map_err(|_| Error::InvalidCaptureQueueLimit {
            field: "snap_length",
            value: limits.snap_length,
            reason: "Npcap snap length exceeds i32",
        })?;
    let promiscuous_mode = if promiscuous {
        PromiscuousMode::Enabled
    } else {
        PromiscuousMode::Disabled
    };
    let mut handle = open_handle(interface, snap_length, promiscuous_mode, native)?;
    if let Some(filter) = capture_filter {
        handle.install_capture_filter(
            interface,
            filter,
            netmask.unwrap_or(PCAP_NETMASK_UNKNOWN),
        )?;
    }
    let datalink = handle.datalink();
    let link_type = u32::try_from(datalink)
        .map(canonical_link_type)
        .map_err(|_| Error::Capture {
            message: format!(
                "Npcap could not report the data-link type for {}",
                interface.name
            ),
            source: Diagnostic::new(Some(datalink), handle.error_message()).into_source(),
        })?;
    let reported_snap_length = handle.snapshot();
    let snap_length = validate_effective_snapshot_length(
        "Npcap",
        interface,
        limits.snap_length,
        reported_snap_length,
    )?;
    let (native, timestamp_precision) =
        realize_settings("Npcap", interface, native, handle.reported_precision())?;
    let interrupt = Arc::new(NpcapInterrupt(handle.breakloop_handle()));
    Ok(NativeCaptureParts {
        source: Box::new(NpcapCaptureSource {
            handle,
            snap_length,
            timestamp_precision,
        }),
        interrupt,
        metadata: Metadata {
            interface: interface.clone(),
            link_type,
            snap_length,
            native,
        },
    })
}

pub(crate) fn timestamp_types(interface: &InterfaceId) -> Result<Vec<TimestampType>, Error> {
    let mut handle = create_handle(interface)?;
    handle.list_timestamp_types(interface)
}

struct NpcapCaptureSource {
    handle: NpcapHandle,
    snap_length: usize,
    timestamp_precision: TimestampPrecision,
}

impl NativeCaptureSource for NpcapCaptureSource {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
        self.handle
            .next_packet(self.snap_length, self.timestamp_precision)
    }

    fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
        self.handle.stats()
    }
}

struct NpcapInterrupt(NpcapBreakLoop);

impl CaptureInterrupt for NpcapInterrupt {
    fn interrupt(&self) {
        self.0.breakloop();
    }
}
