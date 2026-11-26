// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_ushort};
use std::fmt;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::error::Source;
use packetcraftr_core::frame::LinkType;

use crate::{
    Error,
    capture::{
        MAX_NATIVE_BUFFER_SIZE, MAX_TIMESTAMP_TYPES, NativeSettings, Realized, RealizedSettings,
        TimestampPrecision, TimestampSource, TimestampType,
        live::{NativeCapturedPacket, monotonic_packet_time, system_time},
    },
    interface::Id as InterfaceId,
};

pub(in crate::platform) const PCAP_NETMASK_UNKNOWN: u32 = u32::MAX;

#[repr(C)]
pub(in crate::platform) struct BpfInstruction {
    pub(in crate::platform) code: c_ushort,
    pub(in crate::platform) jump_true: c_uchar,
    pub(in crate::platform) jump_false: c_uchar,
    pub(in crate::platform) value: c_uint,
}

#[repr(C)]
pub(in crate::platform) struct BpfProgram {
    pub(in crate::platform) instruction_count: c_uint,
    pub(in crate::platform) instructions: *mut BpfInstruction,
}

impl BpfProgram {
    pub(in crate::platform) const fn empty() -> Self {
        Self {
            instruction_count: 0,
            instructions: std::ptr::null_mut(),
        }
    }
}

pub(in crate::platform) struct RawPacketHeader {
    pub(in crate::platform) tv_sec: i64,
    pub(in crate::platform) tv_usec: i64,
    pub(in crate::platform) observed_at: Instant,
    pub(in crate::platform) observed_wall: SystemTime,
    pub(in crate::platform) captured_length: u32,
    pub(in crate::platform) original_length: u32,
}

pub(in crate::platform) fn validate_captured_packet(
    backend: &str,
    snap_length: usize,
    timestamp_precision: TimestampPrecision,
    header: RawPacketHeader,
    data: &[u8],
) -> Result<NativeCapturedPacket, Error> {
    let timestamp = system_time(header.tv_sec, header.tv_usec, timestamp_precision)?;
    let received_at = monotonic_packet_time(timestamp, header.observed_wall, header.observed_at);
    if data.len() > snap_length {
        return Err(Error::Capture {
            message: format!(
                "{backend} returned {} bytes beyond configured snap length {snap_length}",
                data.len(),
            ),
            source: None,
        });
    }
    if data.len() != header.captured_length as usize {
        return Err(Error::Capture {
            message: format!(
                "{backend} packet data contains {} bytes but declares captured length {}",
                data.len(),
                header.captured_length
            ),
            source: None,
        });
    }
    if header.original_length < header.captured_length {
        return Err(Error::Capture {
            message: format!(
                "{backend} returned captured length {} above original length {}",
                header.captured_length, header.original_length
            ),
            source: None,
        });
    }
    Ok(NativeCapturedPacket {
        timestamp,
        received_at,
        captured_length: header.captured_length,
        original_length: header.original_length,
        bytes: Bytes::copy_from_slice(data),
    })
}

pub(in crate::platform) fn validate_layer2_length(
    backend: &str,
    length: usize,
) -> Result<c_int, Error> {
    c_int::try_from(length).map_err(|_| Error::InvalidTransmissionFrame {
        message: format!("Layer 2 frame length {length} exceeds the {backend} signed-length limit"),
    })
}

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

const fn timestamp_source_value(source: TimestampSource) -> c_int {
    match source {
        TimestampSource::Host => PCAP_TSTAMP_HOST,
        TimestampSource::HostLowPrec => PCAP_TSTAMP_HOST_LOWPREC,
        TimestampSource::HostHighPrec => PCAP_TSTAMP_HOST_HIPREC,
        TimestampSource::Adapter => PCAP_TSTAMP_ADAPTER,
    }
}

const fn timestamp_precision_value(precision: TimestampPrecision) -> c_int {
    match precision {
        TimestampPrecision::Micro => PCAP_TSTAMP_PRECISION_MICRO,
        TimestampPrecision::Nano => PCAP_TSTAMP_PRECISION_NANO,
    }
}

const fn timestamp_source_of_value(value: c_int) -> Option<TimestampSource> {
    match value {
        PCAP_TSTAMP_HOST => Some(TimestampSource::Host),
        PCAP_TSTAMP_HOST_LOWPREC => Some(TimestampSource::HostLowPrec),
        PCAP_TSTAMP_HOST_HIPREC => Some(TimestampSource::HostHighPrec),
        PCAP_TSTAMP_ADAPTER => Some(TimestampSource::Adapter),
        _ => None,
    }
}

const fn timestamp_precision_of_value(value: c_int) -> Option<TimestampPrecision> {
    match value {
        PCAP_TSTAMP_PRECISION_MICRO => Some(TimestampPrecision::Micro),
        PCAP_TSTAMP_PRECISION_NANO => Some(TimestampPrecision::Nano),
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub(in crate::platform) enum NativeSetting {
    BufferSize,
    TimestampSource,
    TimestampPrecision,
}

impl NativeSetting {
    pub(in crate::platform) const fn operation(self) -> &'static str {
        match self {
            Self::BufferSize => "pcap_set_buffer_size",
            Self::TimestampSource => "pcap_set_tstamp_type",
            Self::TimestampPrecision => "pcap_set_tstamp_precision",
        }
    }

    pub(in crate::platform) const fn field(self) -> &'static str {
        match self {
            Self::BufferSize => "buffer_size",
            Self::TimestampSource => "timestamp_source",
            Self::TimestampPrecision => "timestamp_precision",
        }
    }
}

pub(in crate::platform) fn apply_native_settings(
    backend: &str,
    interface: &InterfaceId,
    settings: &NativeSettings,
    mut set: impl FnMut(NativeSetting, c_int) -> Result<Result<(), (c_int, String)>, Error>,
) -> Result<(), Error> {
    if let Some(buffer_size) = settings.buffer_size {
        let size = c_int::try_from(buffer_size).map_err(|_| Error::InvalidCaptureSetting {
            field: "buffer_size",
            message: format!("exceeds the native maximum of {MAX_NATIVE_BUFFER_SIZE} bytes"),
        })?;
        if let Err((status, diagnostic)) = set(NativeSetting::BufferSize, size)? {
            return Err(map_setting_error(
                backend,
                interface,
                NativeSetting::BufferSize,
                &buffer_size.to_string(),
                status,
                diagnostic,
            ));
        }
    }
    if let Some(source) = settings.timestamp_source
        && let Err((status, diagnostic)) = set(
            NativeSetting::TimestampSource,
            timestamp_source_value(source),
        )?
    {
        return Err(map_setting_error(
            backend,
            interface,
            NativeSetting::TimestampSource,
            source.as_str(),
            status,
            diagnostic,
        ));
    }
    if let Some(precision) = settings.timestamp_precision
        && let Err((status, diagnostic)) = set(
            NativeSetting::TimestampPrecision,
            timestamp_precision_value(precision),
        )?
    {
        return Err(map_setting_error(
            backend,
            interface,
            NativeSetting::TimestampPrecision,
            precision.as_str(),
            status,
            diagnostic,
        ));
    }
    Ok(())
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

fn map_setting_error(
    backend: &str,
    interface: &InterfaceId,
    setting: NativeSetting,
    requested: &str,
    status: c_int,
    diagnostic: String,
) -> Error {
    let operation = setting.operation();
    if matches!(
        status,
        PCAP_WARNING_TSTAMP_TYPE_NOTSUP
            | PCAP_ERROR_CANTSET_TSTAMP_TYPE
            | PCAP_ERROR_TSTAMP_PRECISION_NOTSUP
    ) {
        return Error::UnsupportedCaptureSetting {
            setting: setting.field(),
            interface: interface.name.clone(),
            message: format!(
                "{backend} rejected {requested} through {operation} (status {status}): {diagnostic}"
            )
            .into(),
        };
    }
    Error::Capture {
        message: format!("{backend} {operation} failed for {}", interface.name),
        source: Diagnostic::new(Some(status), diagnostic).into_source(),
    }
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

/// Bounds one runtime's timestamp type list and copies it out exactly once. `free` and
/// `copy` wrap the runtime's list, which a zero count leaves unallocated.
pub(in crate::platform) fn timestamp_type_list(
    backend: &str,
    interface: &InterfaceId,
    count: c_int,
    error_message: impl FnOnce() -> String,
    free: impl FnOnce(),
    copy: impl FnOnce(usize) -> Vec<c_int>,
) -> Result<Vec<c_int>, Error> {
    if count < 0 {
        return Err(Error::Capture {
            message: format!(
                "{backend} could not enumerate timestamp types for {}",
                interface.name
            ),
            source: Diagnostic::new(Some(count), error_message()).into_source(),
        });
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let count = usize::try_from(count).unwrap_or(0);
    if count > MAX_TIMESTAMP_TYPES {
        free();
        return Err(Error::Capture {
            message: format!(
                "{backend} reported {count} timestamp types for {}, above the {MAX_TIMESTAMP_TYPES} bound",
                interface.name
            ),
            source: None,
        });
    }
    let values = copy(count);
    free();
    Ok(values)
}

pub(in crate::platform) fn map_timestamp_types(
    values: Vec<c_int>,
    mut name: impl FnMut(c_int) -> Option<String>,
    mut description: impl FnMut(c_int) -> Option<String>,
) -> Vec<TimestampType> {
    values
        .into_iter()
        .map(|value| TimestampType {
            value,
            name: name(value),
            description: description(value),
            source: timestamp_source_of_value(value),
        })
        .collect()
}

/// # Safety
///
/// `raw` is NULL or points to a static NUL-terminated string the pcap runtime owns.
#[expect(unsafe_code, reason = "reads a C string returned by the pcap runtime")]
pub(in crate::platform) unsafe fn tstamp_type_string(raw: *const c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is non-NULL and the caller guarantees it is NUL-terminated.
    let value = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    (!value.is_empty()).then_some(value)
}

// Open and send failures report only error-buffer text, so matching it is the only classifier.

fn is_missing_device(message: &str) -> bool {
    const PHRASES: [&str; 3] = ["no such device", "not found", "does not exist"];
    let message = message.to_ascii_lowercase();
    PHRASES.iter().any(|phrase| message.contains(phrase))
}

fn is_permission_denied(message: &str) -> bool {
    const PHRASES: [&str; 4] = [
        "permission denied",
        "not permitted",
        "access is denied",
        "administrator",
    ];
    let message = message.to_ascii_lowercase();
    PHRASES.iter().any(|phrase| message.contains(phrase))
}

pub(in crate::platform) fn map_open_error(
    backend: &str,
    privilege_hint: &str,
    interface: &InterfaceId,
    diagnostic: &str,
    source: Option<Source>,
) -> Error {
    if is_permission_denied(diagnostic) {
        Error::Privilege {
            message: format!(
                "cannot open {} through {backend}; {privilege_hint}",
                interface.name
            ),
            source,
        }
    } else if is_missing_device(diagnostic) {
        Error::Device {
            interface: interface.name.clone(),
            message: format!("{backend} could not open this interface"),
            source,
        }
    } else {
        Error::Capture {
            message: format!("could not open {} through {backend}", interface.name),
            source,
        }
    }
}

pub(in crate::platform) fn map_send_error(
    backend: &str,
    privilege_hint: &str,
    interface: &InterfaceId,
    diagnostic: &str,
    source: Option<Source>,
) -> Error {
    if is_permission_denied(diagnostic) {
        Error::Privilege {
            message: format!(
                "cannot inject on {} through {backend}; {privilege_hint}",
                interface.name
            ),
            source,
        }
    } else {
        Error::Send {
            message: format!("{backend} injection on {} failed", interface.name),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::clock::{Clock, SystemClock};

    #[test]
    fn oversized_layer2_frame_reports_invalid_transmission_frame() {
        assert_eq!(validate_layer2_length("libpcap", 64).unwrap(), 64);
        assert!(matches!(
            validate_layer2_length("Npcap", (c_int::MAX as usize) + 1),
            Err(Error::InvalidTransmissionFrame { .. })
        ));
    }

    #[test]
    fn captured_packet_validation_rejects_inconsistent_lengths() {
        let now = SystemClock.now();
        let wall = SystemClock.wall_now();
        let make = |caplen, origlen| RawPacketHeader {
            tv_sec: 1_700_000_000,
            tv_usec: 123,
            observed_at: now,
            observed_wall: wall,
            captured_length: caplen,
            original_length: origlen,
        };
        assert!(
            validate_captured_packet(
                "libpcap",
                64,
                TimestampPrecision::Micro,
                make(4, 4),
                b"abcd"
            )
            .is_ok()
        );
        assert!(matches!(
            validate_captured_packet("libpcap", 3, TimestampPrecision::Micro, make(4, 4), b"abcd"),
            Err(Error::Capture { .. })
        ));
        assert!(matches!(
            validate_captured_packet(
                "libpcap",
                64,
                TimestampPrecision::Micro,
                make(5, 5),
                b"abcd"
            ),
            Err(Error::Capture { .. })
        ));
        assert!(matches!(
            validate_captured_packet(
                "libpcap",
                64,
                TimestampPrecision::Micro,
                make(4, 3),
                b"abcd"
            ),
            Err(Error::Capture { .. })
        ));
    }
}
