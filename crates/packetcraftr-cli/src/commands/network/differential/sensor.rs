// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use packetcraftr::differential as lib;
use packetcraftr_core::error::{Classification, Kind};

use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;

pub(crate) struct SensorCapture {
    pub(crate) frames: u64,
    pub(crate) observations: Vec<lib::SensorObservation>,
}

pub(crate) fn read_sensor_capture(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limits: OfflineCaptureLimitsArgs,
) -> Result<SensorCapture, CliError> {
    let max_frames = limits.max_frames;
    let max_bytes = limits.max_bytes;
    let limits = limits.limits()?;
    let mut reader = crate::input::open_capture_file(&invocation.control, path, limits)?;
    let mut frames = 0_u64;
    let mut bytes = 0_u64;
    let mut observations = Vec::new();
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        frames = frames.checked_add(1).ok_or_else(|| {
            CliError::new(Kind::Internal, "sensor capture frame count overflowed")
        })?;
        bytes = bytes
            .checked_add(u64::try_from(frame.bytes().len()).unwrap_or(u64::MAX))
            .ok_or_else(|| CliError::new(Kind::Internal, "sensor capture byte count overflowed"))?;
        if frames > max_frames || bytes > max_bytes {
            return Err(CliError::from_classification(
                Classification::new(
                    packetcraftr_core::error::Code::CliCaptureLimit,
                    Kind::Usage,
                    Some("narrow the sensor capture or raise the capture limits"),
                ),
                format!("sensor capture exceeds its limits at {frames} frames and {bytes} bytes"),
                Vec::new(),
            ));
        }
        observations.extend(probes_in_frame(frame.bytes()));
    }
    Ok(SensorCapture {
        frames,
        observations,
    })
}

fn probes_in_frame(bytes: &[u8]) -> Vec<lib::SensorObservation> {
    let mut observations = Vec::new();
    let mut offset = 0_usize;
    while offset + 30 <= bytes.len() {
        let Some(found) = bytes[offset..]
            .windows(4)
            .position(|window| window == b"PCR1")
        else {
            break;
        };
        let start = offset + found;
        if start + 30 > bytes.len() {
            break;
        }
        let declared = usize::from(u16::from_be_bytes([bytes[start + 28], bytes[start + 29]]));
        // A probe always carries its trailing hash. Anything else moves the
        // scan one byte past this magic candidate.
        if declared < lib::canary::MIN_PAYLOAD_LEN || start + declared > bytes.len() {
            offset = start + 1;
            continue;
        }
        if let Some(probe) = lib::canary::parse_probe(&bytes[start..start + declared]) {
            observations.push(lib::SensorObservation {
                variant_index: probe.variant_index,
                attempt_seq: probe.attempt_seq,
                payload_sha256: lib::hex(&probe.payload_sha256),
            });
            offset = start + declared;
        } else {
            offset = start + 1;
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_exact_canary_probes_inside_a_frame() {
        let probe = lib::canary::build_probe(&[7_u8; lib::canary::TOKEN_LEN], 3, 9, 96);
        let mut frame = vec![1, 2, 3, 4];
        frame.extend_from_slice(&probe);
        frame.extend_from_slice(&[9, 9, 9]);
        let observations = probes_in_frame(&frame);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].variant_index, 3);
        assert_eq!(observations[0].attempt_seq, 9);
        assert_eq!(
            observations[0].payload_sha256,
            lib::hex(&lib::canary::payload_sha256(&probe))
        );
    }

    #[test]
    fn truncated_or_tampered_probes_are_not_observations() {
        let probe = lib::canary::build_probe(&[7_u8; lib::canary::TOKEN_LEN], 1, 2, 96);
        assert!(probes_in_frame(&probe[..probe.len() - 1]).is_empty());
        let mut tampered = probe.clone();
        tampered[40] ^= 0xFF;
        assert!(probes_in_frame(&tampered).is_empty());
    }
}
