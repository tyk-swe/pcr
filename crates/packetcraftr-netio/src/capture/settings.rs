// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native timestamp selection and requested, applied, and effective settings.

use super::{Error, Limits};

/// Timestamp fraction precision a native backend delivers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampPrecision {
    /// Microsecond fractions; the libpcap and Npcap default.
    #[default]
    Micro,
    /// Nanosecond fractions.
    Nano,
}

impl TimestampPrecision {
    /// The one spelling this precision is named by, in help text, in the
    /// `--timestamp-precision` values a caller passes, and in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Nano => "nano",
        }
    }
}

packetcraftr_core::display_via_as_str!(TimestampPrecision);

/// A packet timestamp source the frame-time contract can represent.
///
/// Only sources whose stamps are synchronized with the host system clock are
/// representable: an unsynchronized adapter or host clock cannot be projected
/// into host monotonic time or labeled Unix time without inventing a
/// conversion. libpcap's `adapter_unsynced` and `host_hiprec_unsynced` values
/// therefore have no variant here; timestamp-type discovery still reports
/// them with [`TimestampType::source`] set to `None`.
///
/// The serialized spellings match libpcap's canonical type names so the same
/// value names a type in `--timestamp-source`, reports, and discovery output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum TimestampSource {
    /// Host-provided timestamps of unspecified characteristics
    /// (`PCAP_TSTAMP_HOST`, the backend default).
    #[serde(rename = "host")]
    Host,
    /// Low-precision host timestamps synchronized with the system clock
    /// (`PCAP_TSTAMP_HOST_LOWPREC`).
    #[serde(rename = "host_lowprec")]
    HostLowPrec,
    /// High-precision host timestamps synchronized with the system clock
    /// (`PCAP_TSTAMP_HOST_HIPREC`).
    #[serde(rename = "host_hiprec")]
    HostHighPrec,
    /// Adapter-provided high-precision timestamps synchronized with the
    /// system clock (`PCAP_TSTAMP_ADAPTER`).
    #[serde(rename = "adapter")]
    Adapter,
}

impl TimestampSource {
    /// The libpcap-canonical name of this source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::HostLowPrec => "host_lowprec",
            Self::HostHighPrec => "host_hiprec",
            Self::Adapter => "adapter",
        }
    }
}

packetcraftr_core::display_via_as_str!(TimestampSource);

/// One packet timestamp type a native backend advertises for an interface.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TimestampType {
    /// The backend's numeric timestamp-type value.
    pub value: i32,
    /// The backend's canonical name for the type, when it assigns one.
    pub name: Option<String>,
    /// The backend's description of the type, when it assigns one.
    pub description: Option<String>,
    /// The [`TimestampSource`] selecting this type; `None` when the type's
    /// clock domain cannot be represented safely by the frame-time contract.
    pub source: Option<TimestampSource>,
}

/// Upper bound on a backend's advertised timestamp-type list. Real backends
/// enumerate a handful of types; a larger answer is a broken backend.
pub const MAX_TIMESTAMP_TYPES: usize = 64;

/// Optional native-driver capture settings applied before backend activation.
///
/// Every `None` keeps the backend's own default. These settings configure the
/// driver's capture buffer and timestamp generation per interface; they are
/// distinct from the PacketcraftR capture-queue budgets in [`Limits`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeSettings {
    /// Kernel/driver capture-buffer size in bytes (`pcap_set_buffer_size`).
    /// The backend accepts the request during configuration; neither backend
    /// can report the size the kernel actually allocated.
    pub buffer_size: Option<usize>,
    /// Packet timestamp source (`pcap_set_tstamp_type`).
    pub timestamp_source: Option<TimestampSource>,
    /// Packet timestamp fraction precision (`pcap_set_tstamp_precision`).
    pub timestamp_precision: Option<TimestampPrecision>,
}

/// Largest driver-buffer request the pcap-family ABI can express; both
/// backends take the size as a C `int`.
pub const MAX_NATIVE_BUFFER_SIZE: usize = i32::MAX as usize;

impl NativeSettings {
    /// Validates finite ranges and the buffer/snapshot relationship before
    /// any backend is configured or activated.
    pub fn validate(&self, limits: &Limits) -> Result<(), Error> {
        if let Some(buffer_size) = self.buffer_size {
            if buffer_size == 0 {
                return Err(Error::InvalidCaptureSetting {
                    field: "buffer_size",
                    message: "must be greater than zero".to_owned(),
                });
            }
            if buffer_size > MAX_NATIVE_BUFFER_SIZE {
                return Err(Error::InvalidCaptureSetting {
                    field: "buffer_size",
                    message: format!(
                        "exceeds the native maximum of {MAX_NATIVE_BUFFER_SIZE} bytes"
                    ),
                });
            }
            if buffer_size < limits.snap_length {
                return Err(Error::InvalidCaptureSetting {
                    field: "buffer_size",
                    message: format!("must hold one snapshot of {} bytes", limits.snap_length),
                });
            }
        }
        Ok(())
    }
}

/// What an activated session made of one optional [`NativeSettings`] field.
///
/// The three values stay deliberately distinct: a request the backend
/// accepted during configuration is not proof the driver realized exactly
/// that value, and an effective value is reported only when the backend can
/// confirm one after activation. `effective = None` means the backend cannot
/// report the realized value — never a claim of zero or default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Realized<T> {
    /// The explicit request echoed back; `None` when the caller asked for the
    /// backend default.
    pub requested: Option<T>,
    /// The value the backend's configuration call accepted; `None` when no
    /// explicit value was applied.
    pub applied: Option<T>,
    /// The value independently confirmed after activation; `None` when the
    /// backend cannot report it.
    pub effective: Option<T>,
}

impl<T> Default for Realized<T> {
    fn default() -> Self {
        Self {
            requested: None,
            applied: None,
            effective: None,
        }
    }
}

impl<T: PartialEq> Realized<T> {
    /// Whether this realization faithfully describes the request it answers:
    /// the backend echoes the request and reports that same value as applied.
    /// `effective` stays unconstrained; a backend that confirms a different
    /// value than requested must reject the session rather than report the
    /// mismatch.
    pub(crate) fn consistent_with(&self, request: Option<T>) -> bool {
        self.requested == request && self.applied == request
    }
}

/// Backend-realized values for each [`NativeSettings`] field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RealizedSettings {
    /// Both backends accept a request but cannot report the allocated size.
    pub buffer_size: Realized<usize>,
    /// Both backends apply a request at configuration time but cannot report
    /// the source in effect afterwards.
    pub timestamp_source: Realized<TimestampSource>,
    /// Precision is confirmed after activation: the read path must interpret
    /// the native timestamp fraction with the delivered unit.
    pub timestamp_precision: Realized<TimestampPrecision>,
}

impl RealizedSettings {
    /// Whether any requested, applied, or effective value is present; an
    /// all-default realization is omitted from serialized reports.
    pub fn reported(&self) -> bool {
        fn present<T>(realized: &Realized<T>) -> bool {
            realized.requested.is_some()
                || realized.applied.is_some()
                || realized.effective.is_some()
        }
        present(&self.buffer_size)
            || present(&self.timestamp_source)
            || present(&self.timestamp_precision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            snap_length: 64,
            ..Limits::default()
        }
    }

    #[test]
    fn native_settings_validate_finite_ranges_before_activation() {
        let limits = limits();
        // Defaults and a buffer that holds one snapshot pass.
        NativeSettings::default().validate(&limits).unwrap();
        NativeSettings {
            buffer_size: Some(64),
            ..Default::default()
        }
        .validate(&limits)
        .unwrap();
        NativeSettings {
            buffer_size: Some(MAX_NATIVE_BUFFER_SIZE),
            timestamp_source: Some(TimestampSource::Adapter),
            timestamp_precision: Some(TimestampPrecision::Nano),
        }
        .validate(&limits)
        .unwrap();

        for (buffer_size, check) in [
            (0usize, "zero is rejected" as &str),
            (63, "smaller than one snapshot is rejected"),
            (
                MAX_NATIVE_BUFFER_SIZE + 1,
                "above the native int range is rejected",
            ),
            (usize::MAX, "overflow is rejected"),
        ] {
            let error = NativeSettings {
                buffer_size: Some(buffer_size),
                ..Default::default()
            }
            .validate(&limits)
            .expect_err(check);
            assert!(
                matches!(
                    error,
                    Error::InvalidCaptureSetting {
                        field: "buffer_size",
                        ..
                    }
                ),
                "{check}: {error:?}"
            );
        }
    }

    #[test]
    fn realizations_echo_requests_and_keep_unknown_effective_unknown() {
        let mut realized = RealizedSettings::default();
        assert!(!realized.reported());
        assert!(realized.buffer_size.consistent_with(None));
        realized.buffer_size = Realized {
            requested: Some(1024),
            applied: Some(1024),
            effective: None,
        };
        assert!(realized.reported());
        assert!(realized.buffer_size.consistent_with(Some(1024)));
        // A backend echoing a different applied value fails the check, and an
        // effective value the backend could not query stays None — never a
        // fabricated default.
        realized.buffer_size.applied = Some(2048);
        assert!(!realized.buffer_size.consistent_with(Some(1024)));
        assert_eq!(realized.buffer_size.effective, None);
    }
}
