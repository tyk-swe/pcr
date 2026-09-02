// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Rules shared by the libpcap and Npcap backends: portable link-type
//! canonicalization, snapshot-length validation, and error phrasing.

use packetcraftr_core::frame::LinkType;

use crate::{Error, interface::Id as InterfaceId};

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

pub(crate) fn canonical_link_type(datalink: u32) -> LinkType {
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

pub(crate) fn validate_effective_snapshot_length(
    backend: &str,
    interface: &InterfaceId,
    requested: usize,
    reported: i32,
) -> Result<usize, Error> {
    let effective = usize::try_from(reported).map_err(|_| Error::Capture {
        message: format!(
            "{backend} returned invalid snapshot length {reported} for {}",
            interface.name
        ),
        source: None,
    })?;
    if effective == 0 {
        return Err(Error::Capture {
            message: format!(
                "{backend} returned zero snapshot length for {}",
                interface.name
            ),
            source: None,
        });
    }
    if effective > requested {
        return Err(Error::Capture {
            message: format!(
                "{backend} effective snapshot length {effective} exceeds configured maximum {requested} for {}",
                interface.name
            ),
            source: None,
        });
    }
    Ok(effective)
}

/// Recognizes the missing-interface refusals libpcap and Npcap phrase
/// differently, so both backends classify them as device failures.
pub(crate) fn is_missing_device(message: &str) -> bool {
    const PHRASES: [&str; 3] = ["no such device", "not found", "does not exist"];
    let message = message.to_ascii_lowercase();
    PHRASES.iter().any(|phrase| message.contains(phrase))
}

/// Recognizes the privilege refusals libpcap and Npcap phrase differently.
///
/// libpcap reports `Permission denied` or `Operation not permitted`; Npcap
/// reports `Access is denied` or asks to be run as an administrator. One list
/// keeps the classification identical on every target.
pub(crate) fn is_permission_denied(message: &str) -> bool {
    const PHRASES: [&str; 4] = [
        "permission denied",
        "not permitted",
        "access is denied",
        "administrator",
    ];
    let message = message.to_ascii_lowercase();
    PHRASES.iter().any(|phrase| message.contains(phrase))
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
    fn privilege_refusals_are_recognized_in_every_backend_phrasing() {
        for message in [
            "eth0: You don't have permission to capture on that device (socket: Operation not permitted)",
            "en0: Permission denied",
            r"\Device\NPF_{0}: Access is denied.",
            "The requested operation requires elevation; run as Administrator",
        ] {
            assert!(is_permission_denied(message), "{message}");
        }
        for message in [
            "eth0: No such device exists",
            "libpcap statistics failed: not supported",
        ] {
            assert!(!is_permission_denied(message), "{message}");
        }
    }

    #[test]
    fn effective_snapshot_length_is_positive_and_cannot_relax_the_requested_bound() {
        assert_eq!(
            validate_effective_snapshot_length("fixture", &interface(), 64, 32)
                .expect("a reported length inside the requested bound is accepted"),
            32
        );
        for reported in [-1, 0, 65] {
            assert!(matches!(
                validate_effective_snapshot_length("fixture", &interface(), 64, reported),
                Err(Error::Capture { .. })
            ));
        }
    }
}
