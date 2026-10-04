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

/// Validate the native list pointer before either freeing or constructing a slice.
pub(in crate::platform) fn validate_timestamp_list<T>(list: *const T) -> Result<(), Error> {
    if list.is_null() {
        return Err(Error::Capture {
            message: "native capture reported timestamp types without a list".to_owned(),
            source: None,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonempty_timestamp_list_rejects_null_pointer() {
        assert!(matches!(
            validate_timestamp_list(std::ptr::null::<i32>()),
            Err(Error::Capture { .. })
        ));
        let types = [0, 1];
        assert!(validate_timestamp_list(types.as_ptr()).is_ok());
    }
}
