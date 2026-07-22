// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native capture capability dispatch.

#![forbid(unsafe_code)]

use super::super::Error as LiveIoError;

#[cfg(feature = "native-layer2")]
pub(in crate::net) fn system_capture(
    _route: &super::super::route::PlannedRoute,
    limits: super::super::capture::CaptureQueueLimits,
) -> Result<Box<dyn super::super::capture::CaptureSession>, LiveIoError> {
    // Reject invalid bounds before opening a device or allocating native
    // resources. NativeCaptureSession validates again at its ownership seam.
    let _validated_limits = limits.validate()?;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        super::validate_current_interface_identity(&_route.route.interface)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let parts = super::pcap_backend::open_capture(&_route.route.interface, _validated_limits)?;
        #[cfg(windows)]
        let parts = super::npcap::open_capture(&_route.route.interface, _validated_limits)?;
        Ok(Box::new(super::live_capture::NativeCaptureSession::spawn(
            parts,
            _validated_limits,
        )?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(super::unsupported_live_io(
            "native Layer 2 capture is unsupported on this target",
        ))
    }
}

#[cfg(not(feature = "native-layer2"))]
pub(in crate::net) fn system_capture(
    _route: &super::super::route::PlannedRoute,
    _limits: super::super::capture::CaptureQueueLimits,
) -> Result<Box<dyn super::super::capture::CaptureSession>, LiveIoError> {
    Err(super::unsupported_live_io(
        "enable the native-layer2 feature for native packet capture",
    ))
}
