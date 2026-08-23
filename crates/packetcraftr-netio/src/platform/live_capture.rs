// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned native capture worker and bounded queue shared by libpcap and Npcap.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::frame::LinkType;

use crate::{
    Error as LiveIoError, capture::Metadata as CaptureMetadata, interface::Id as InterfaceId,
};

pub(super) use session::NativeCaptureSession;
pub(super) use time::{monotonic_packet_time, system_time};

mod queue;
mod session;
mod time;
mod worker;

pub(super) struct NativeCapturedPacket {
    pub timestamp: SystemTime,
    /// Conservative monotonic time derived from the kernel packet timestamp.
    pub received_at: Option<Instant>,
    pub captured_length: u32,
    pub original_length: u32,
    pub bytes: Bytes,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeCaptureStatistics {
    pub capture_dropped_frames: u32,
    pub network_dropped_frames: u32,
    pub interface_dropped_frames: u32,
}

pub(super) enum NativeCaptureEvent {
    Packet(NativeCapturedPacket),
    Timeout,
    Closed,
}

pub(super) trait NativeCaptureSource: Send {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError>;
    fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError>;
}

pub(super) trait CaptureInterrupt: Send + Sync {
    fn interrupt(&self);
}

const DLT_ATM_RFC1483: u32 = 11;
const LINKTYPE_ATM_RFC1483: LinkType = LinkType(100);
const DLT_RAW: u32 = 12;
const DLT_SLIP_BSDOS: u32 = 15;
const LINKTYPE_SLIP_BSDOS: LinkType = LinkType(102);
const DLT_PPP_BSDOS: u32 = 16;
const LINKTYPE_PPP_BSDOS: LinkType = LinkType(103);
const DLT_ATM_CLIP: u32 = 19;
const LINKTYPE_ATM_CLIP: LinkType = LinkType(106);

#[cfg(target_os = "macos")]
const DLT_PFSYNC: u32 = 18;
#[cfg(target_os = "macos")]
const LINKTYPE_PFSYNC: LinkType = LinkType(246);
#[cfg(target_os = "macos")]
const DLT_PKTAP: u32 = 149;
#[cfg(target_os = "macos")]
const LINKTYPE_PKTAP: LinkType = LinkType(258);

pub(super) fn canonical_link_type(datalink: u32) -> LinkType {
    match datalink {
        DLT_ATM_RFC1483 => LINKTYPE_ATM_RFC1483,
        DLT_RAW => LinkType::RAW,
        DLT_SLIP_BSDOS => LINKTYPE_SLIP_BSDOS,
        DLT_PPP_BSDOS => LINKTYPE_PPP_BSDOS,
        DLT_ATM_CLIP => LINKTYPE_ATM_CLIP,
        #[cfg(target_os = "macos")]
        DLT_PFSYNC => LINKTYPE_PFSYNC,
        #[cfg(target_os = "macos")]
        DLT_PKTAP => LINKTYPE_PKTAP,
        _ => LinkType(datalink),
    }
}

pub(super) fn validate_effective_snapshot_length(
    backend: &str,
    interface: &InterfaceId,
    requested: usize,
    reported: i32,
) -> Result<usize, LiveIoError> {
    let effective = usize::try_from(reported).map_err(|_| LiveIoError::Capture {
        message: format!(
            "{backend} returned invalid snapshot length {reported} for {}",
            interface.name
        ),
    })?;
    if effective == 0 {
        return Err(LiveIoError::Capture {
            message: format!(
                "{backend} returned zero snapshot length for {}",
                interface.name
            ),
        });
    }
    if effective > requested {
        return Err(LiveIoError::Capture {
            message: format!(
                "{backend} effective snapshot length {effective} exceeds configured maximum {requested} for {}",
                interface.name
            ),
        });
    }
    Ok(effective)
}

pub(super) struct NativeCaptureParts {
    pub source: Box<dyn NativeCaptureSource>,
    pub interrupt: Arc<dyn CaptureInterrupt>,
    pub metadata: CaptureMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "fixture0".to_owned(),
            index: 7,
        }
    }

    #[test]
    fn native_datalink_types_use_portable_savefile_linktypes() {
        for (datalink, expected) in [
            (0, LinkType::NULL),
            (1, LinkType::ETHERNET),
            (DLT_ATM_RFC1483, LINKTYPE_ATM_RFC1483),
            (DLT_RAW, LinkType::RAW),
            (DLT_SLIP_BSDOS, LINKTYPE_SLIP_BSDOS),
            (DLT_PPP_BSDOS, LINKTYPE_PPP_BSDOS),
            (DLT_ATM_CLIP, LINKTYPE_ATM_CLIP),
            (LinkType::LINUX_SLL2.0, LinkType::LINUX_SLL2),
        ] {
            assert_eq!(canonical_link_type(datalink), expected);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_datalink_types_use_portable_savefile_linktypes() {
        assert_eq!(canonical_link_type(DLT_PFSYNC), LINKTYPE_PFSYNC);
        assert_eq!(canonical_link_type(DLT_PKTAP), LINKTYPE_PKTAP);
    }

    #[test]
    fn effective_snapshot_length_is_positive_and_cannot_relax_the_requested_bound() {
        assert_eq!(
            validate_effective_snapshot_length("fixture", &interface(), 64, 32),
            Ok(32)
        );
        for reported in [-1, 0, 65] {
            assert!(matches!(
                validate_effective_snapshot_length("fixture", &interface(), 64, reported),
                Err(LiveIoError::Capture { .. })
            ));
        }
    }
}
