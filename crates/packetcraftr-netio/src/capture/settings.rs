// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Limits;
use crate::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampPrecision {
    #[default]
    Micro,
    Nano,
}

impl TimestampPrecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Nano => "nano",
        }
    }
}

impl std::fmt::Display for TimestampPrecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum TimestampSource {
    #[serde(rename = "host")]
    Host,
    #[serde(rename = "host_lowprec")]
    HostLowPrec,
    #[serde(rename = "host_hiprec")]
    HostHighPrec,
    #[serde(rename = "adapter")]
    Adapter,
}

impl TimestampSource {
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

impl std::fmt::Display for TimestampSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TimestampType {
    pub value: i32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub source: Option<TimestampSource>,
}

/// Real backends enumerate a handful of types; a larger answer is a broken backend.
pub const MAX_TIMESTAMP_TYPES: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeSettings {
    /// Kernel/driver capture-buffer size in bytes (`pcap_set_buffer_size`).
    pub buffer_size: Option<usize>,
    pub timestamp_source: Option<TimestampSource>,
    pub timestamp_precision: Option<TimestampPrecision>,
}

pub const MAX_NATIVE_BUFFER_SIZE: usize = i32::MAX as usize;

impl NativeSettings {
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

/// `effective = None` means unknown, not zero or default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Realized<T> {
    pub requested: Option<T>,
    pub applied: Option<T>,
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
    /// Backends must reject a confirmed effective mismatch before reporting a session.
    pub(crate) fn consistent_with(&self, request: Option<T>) -> bool {
        self.requested == request && self.applied == request
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RealizedSettings {
    pub buffer_size: Realized<usize>,
    pub timestamp_source: Realized<TimestampSource>,
    pub timestamp_precision: Realized<TimestampPrecision>,
}

impl RealizedSettings {
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
}
