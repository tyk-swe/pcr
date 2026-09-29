// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::c_int;
use std::fmt;

use packetcraftr_core::error::Source;
use packetcraftr_core::frame::LinkType;

use crate::{
    Error,
    capture::{NativeSettings, Realized, RealizedSettings, TimestampPrecision, TimestampSource},
    interface::Id as InterfaceId,
};

pub(in crate::platform) const PCAP_TSTAMP_HOST: c_int = 0;
pub(in crate::platform) const PCAP_TSTAMP_HOST_LOWPREC: c_int = 1;
pub(in crate::platform) const PCAP_TSTAMP_HOST_HIPREC: c_int = 2;
pub(in crate::platform) const PCAP_TSTAMP_ADAPTER: c_int = 3;
pub(in crate::platform) const PCAP_TSTAMP_PRECISION_MICRO: c_int = 0;
pub(in crate::platform) const PCAP_TSTAMP_PRECISION_NANO: c_int = 1;

pub(in crate::platform) const PCAP_WARNING_TSTAMP_TYPE_NOTSUP: c_int = 3;
pub(in crate::platform) const PCAP_ERROR_CANTSET_TSTAMP_TYPE: c_int = -10;
pub(in crate::platform) const PCAP_ERROR_TSTAMP_PRECISION_NOTSUP: c_int = -12;

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

pub(in crate::platform) fn canonical_link_type(datalink: u32) -> LinkType {
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

/// Native dead-handle layout for a capture source, distinct from its transmit layout.
pub(in crate::platform) fn filter_datalink(
    interface: &crate::interface::Info,
) -> Result<c_int, Error> {
    if interface.flags.loopback {
        #[cfg(target_os = "linux")]
        return Ok(1); // Linux libpcap presents loopback through an Ethernet capture header.
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        return Ok(0); // Native BSD/Npcap loopback captures use DLT_NULL.
    }
    let canonical = interface.link_type;
    let native = match canonical {
        LinkType::RAW => DLT_RAW,
        LINKTYPE_ATM_RFC1483 => DLT_ATM_RFC1483,
        LINKTYPE_SLIP_BSDOS => DLT_SLIP_BSDOS,
        LINKTYPE_PPP_BSDOS => DLT_PPP_BSDOS,
        LINKTYPE_ATM_CLIP => DLT_ATM_CLIP,
        #[cfg(target_os = "macos")]
        LINKTYPE_PFSYNC => DLT_PFSYNC,
        #[cfg(target_os = "macos")]
        LINKTYPE_PKTAP => DLT_PKTAP,
        LinkType(value) => value,
    };
    c_int::try_from(native).map_err(|_| Error::InvalidCaptureFilter {
        interface: interface.id.name.clone(),
        message: "capture link type exceeds native BPF range".to_owned(),
    })
}

pub(in crate::platform) const fn timestamp_source_value(source: TimestampSource) -> c_int {
    match source {
        TimestampSource::Host => PCAP_TSTAMP_HOST,
        TimestampSource::HostLowPrec => PCAP_TSTAMP_HOST_LOWPREC,
        TimestampSource::HostHighPrec => PCAP_TSTAMP_HOST_HIPREC,
        TimestampSource::Adapter => PCAP_TSTAMP_ADAPTER,
    }
}

pub(in crate::platform) const fn timestamp_precision_value(precision: TimestampPrecision) -> c_int {
    match precision {
        TimestampPrecision::Micro => PCAP_TSTAMP_PRECISION_MICRO,
        TimestampPrecision::Nano => PCAP_TSTAMP_PRECISION_NANO,
    }
}

pub(in crate::platform) const fn timestamp_source_of_value(
    value: c_int,
) -> Option<TimestampSource> {
    match value {
        PCAP_TSTAMP_HOST => Some(TimestampSource::Host),
        PCAP_TSTAMP_HOST_LOWPREC => Some(TimestampSource::HostLowPrec),
        PCAP_TSTAMP_HOST_HIPREC => Some(TimestampSource::HostHighPrec),
        PCAP_TSTAMP_ADAPTER => Some(TimestampSource::Adapter),
        _ => None,
    }
}

pub(in crate::platform) const fn timestamp_precision_of_value(
    value: c_int,
) -> Option<TimestampPrecision> {
    match value {
        PCAP_TSTAMP_PRECISION_MICRO => Some(TimestampPrecision::Micro),
        PCAP_TSTAMP_PRECISION_NANO => Some(TimestampPrecision::Nano),
        _ => None,
    }
}

#[derive(Debug)]
pub(in crate::platform) struct Diagnostic {
    status: Option<c_int>,
    text: String,
}

impl Diagnostic {
    pub(in crate::platform) fn new(status: Option<c_int>, text: impl Into<String>) -> Self {
        Self {
            status,
            text: text.into(),
        }
    }

    pub(in crate::platform) fn into_source(self) -> Option<Source> {
        Some(Source::new(self))
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) => write!(formatter, "{} (status {status})", self.text),
            None => formatter.write_str(&self.text),
        }
    }
}

impl std::error::Error for Diagnostic {}

pub(in crate::platform) fn check_setting_status(
    backend: &str,
    interface: &InterfaceId,
    operation: &'static str,
    setting: &'static str,
    requested: &str,
    status: c_int,
    diagnostic: &str,
) -> Result<(), Error> {
    if status == 0 {
        return Ok(());
    }
    if matches!(
        status,
        PCAP_WARNING_TSTAMP_TYPE_NOTSUP
            | PCAP_ERROR_CANTSET_TSTAMP_TYPE
            | PCAP_ERROR_TSTAMP_PRECISION_NOTSUP
    ) {
        return Err(Error::UnsupportedCaptureSetting {
            setting,
            interface: interface.name.clone(),
            message: format!(
                "{backend} rejected {requested} through {operation} (status {status}): {diagnostic}"
            )
            .into(),
        });
    }
    Err(Error::Capture {
        message: format!("{backend} {operation} failed for {}", interface.name),
        source: Diagnostic::new(Some(status), diagnostic).into_source(),
    })
}

pub(in crate::platform) fn realize_settings(
    backend: &str,
    interface: &InterfaceId,
    settings: &NativeSettings,
    reported_precision: Option<c_int>,
) -> Result<(RealizedSettings, TimestampPrecision), Error> {
    let confirmed = reported_precision
        .map(|value| {
            timestamp_precision_of_value(value).ok_or_else(|| Error::Capture {
                message: format!(
                    "{backend} reported unknown timestamp precision {value} for {}",
                    interface.name
                ),
                source: None,
            })
        })
        .transpose()?;
    if let (Some(applied), Some(actual)) = (settings.timestamp_precision, confirmed)
        && applied != actual
    {
        return Err(Error::Capture {
            message: format!(
                "{backend} confirmed {actual} timestamp precision after accepting {applied} for {}",
                interface.name
            ),
            source: None,
        });
    }
    let delivered = confirmed
        .or(settings.timestamp_precision)
        .unwrap_or_default();
    Ok((
        RealizedSettings {
            direction: Realized {
                requested: settings.direction,
                applied: settings.direction,
                effective: settings.direction,
            },
            buffer_size: Realized {
                requested: settings.buffer_size,
                applied: settings.buffer_size,
                effective: None,
            },
            timestamp_source: Realized {
                requested: settings.timestamp_source,
                applied: settings.timestamp_source,
                effective: None,
            },
            timestamp_precision: Realized {
                requested: settings.timestamp_precision,
                applied: settings.timestamp_precision,
                effective: confirmed,
            },
        },
        delivered,
    ))
}

pub(in crate::platform) fn validate_effective_snapshot_length(
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

// Open and send failures report only error-buffer text, so matching it is the only classifier.

pub(in crate::platform) fn is_missing_device(message: &str) -> bool {
    const PHRASES: [&str; 3] = ["no such device", "not found", "does not exist"];
    let message = message.to_ascii_lowercase();
    PHRASES.iter().any(|phrase| message.contains(phrase))
}

pub(in crate::platform) fn is_permission_denied(message: &str) -> bool {
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
            #[cfg(target_os = "macos")]
            (DLT_PFSYNC, LINKTYPE_PFSYNC),
            #[cfg(target_os = "macos")]
            (DLT_PKTAP, LINKTYPE_PKTAP),
        ] {
            assert_eq!(canonical_link_type(datalink), expected);
        }
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
    fn timestamp_values_round_trip_through_the_pcap_abi() {
        for source in [
            TimestampSource::Host,
            TimestampSource::HostLowPrec,
            TimestampSource::HostHighPrec,
            TimestampSource::Adapter,
        ] {
            assert_eq!(
                timestamp_source_of_value(timestamp_source_value(source)),
                Some(source)
            );
        }
        for value in [4, 5, -1, 99] {
            assert_eq!(timestamp_source_of_value(value), None);
        }
        for precision in [TimestampPrecision::Micro, TimestampPrecision::Nano] {
            assert_eq!(
                timestamp_precision_of_value(timestamp_precision_value(precision)),
                Some(precision)
            );
        }
        for value in [-1, 2, 99] {
            assert_eq!(timestamp_precision_of_value(value), None);
        }
    }

    #[test]
    fn setting_statuses_classify_unsupported_values() {
        assert!(
            check_setting_status("fixture", &interface(), "pcap_set_x", "setting", "v", 0, "")
                .is_ok()
        );
        for status in [
            PCAP_WARNING_TSTAMP_TYPE_NOTSUP,
            PCAP_ERROR_CANTSET_TSTAMP_TYPE,
            PCAP_ERROR_TSTAMP_PRECISION_NOTSUP,
        ] {
            let error = check_setting_status(
                "fixture",
                &interface(),
                "pcap_set_x",
                "setting",
                "v",
                status,
                "no",
            )
            .unwrap_err();
            assert!(
                matches!(error, Error::UnsupportedCaptureSetting { .. }),
                "status {status}"
            );
        }
        for status in [1, -1, -99] {
            let error = check_setting_status(
                "fixture",
                &interface(),
                "pcap_set_x",
                "setting",
                "v",
                status,
                "no",
            )
            .unwrap_err();
            assert!(matches!(error, Error::Capture { .. }), "status {status}");
        }
    }

    #[test]
    fn a_failed_setting_keeps_the_backend_diagnostic_as_its_source() {
        use packetcraftr_core::error::Classified;

        let error = check_setting_status(
            "libpcap",
            &interface(),
            "pcap_set_buffer_size",
            "buffer_size",
            "4096",
            -1,
            "fixture0: buffer is locked",
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "capture failed: libpcap pcap_set_buffer_size failed for fixture0"
        );
        assert_eq!(error.causes(), ["fixture0: buffer is locked (status -1)"]);
        assert_eq!(error.classification().code, "io.capture");
    }

    #[test]
    fn realized_settings_separate_requested_applied_and_confirmed() {
        let settings = NativeSettings {
            buffer_size: Some(4 * 1024 * 1024),
            timestamp_source: Some(TimestampSource::HostLowPrec),
            timestamp_precision: Some(TimestampPrecision::Nano),
            direction: None,
        };
        let (realized, delivered) =
            realize_settings("fixture", &interface(), &settings, Some(1)).unwrap();
        assert_eq!(realized.buffer_size.requested, Some(4 * 1024 * 1024));
        assert_eq!(realized.buffer_size.applied, Some(4 * 1024 * 1024));
        assert_eq!(realized.buffer_size.effective, None);
        assert_eq!(
            realized.timestamp_source.applied,
            Some(TimestampSource::HostLowPrec)
        );
        assert_eq!(realized.timestamp_source.effective, None);
        assert_eq!(
            realized.timestamp_precision.effective,
            Some(TimestampPrecision::Nano)
        );
        assert_eq!(delivered, TimestampPrecision::Nano);
    }

    #[test]
    fn realized_settings_reject_a_confirmed_precision_mismatch() {
        let settings = NativeSettings {
            timestamp_precision: Some(TimestampPrecision::Nano),
            ..Default::default()
        };
        assert!(matches!(
            realize_settings("fixture", &interface(), &settings, Some(0)),
            Err(Error::Capture { .. })
        ));
        let (_, delivered) = realize_settings("fixture", &interface(), &settings, None).unwrap();
        assert_eq!(delivered, TimestampPrecision::Nano);
        let (realized, delivered) =
            realize_settings("fixture", &interface(), &NativeSettings::default(), Some(0)).unwrap();
        assert_eq!(delivered, TimestampPrecision::Micro);
        assert_eq!(
            realized.timestamp_precision.effective,
            Some(TimestampPrecision::Micro)
        );
        assert!(matches!(
            realize_settings("fixture", &interface(), &NativeSettings::default(), Some(7)),
            Err(Error::Capture { .. })
        ));
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
