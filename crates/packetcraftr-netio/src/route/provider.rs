// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use thiserror::Error;

use packetcraftr_core::budget::{Cancelled, Deadline, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind};

use crate::interface::Id as InterfaceId;

use super::models::{Decision, Provider};

/// Native route/interface errors, retaining typed
/// [`SystemFault`](crate::SystemFault) sources through rendering.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum SystemError {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    /// The caller's deadline expired before the native lookup answered.
    #[error("live operation deadline expired while {operation}")]
    DeadlineExceeded { operation: &'static str },
    #[error("native route selection is unavailable: {message}")]
    Unsupported { message: String },
    #[error("no route to {destination} was found")]
    RouteNotFound { destination: IpAddr },
    #[error("interface {name} (index {index}) was not found")]
    InterfaceNotFound { name: String, index: u32 },
    #[error(
        "interface preference {requested} (index {requested_index}) resolved to {actual} (index {actual_index})"
    )]
    InterfaceMismatch {
        requested: String,
        requested_index: u32,
        actual: String,
        actual_index: u32,
    },
    #[error(
        "preferred source {preferred_source} has a different address family than destination {destination}"
    )]
    SourceFamilyMismatch {
        preferred_source: IpAddr,
        destination: IpAddr,
    },
    #[error("preferred source {preferred_source} is not assigned to interface {interface}")]
    SourceUnavailable {
        preferred_source: IpAddr,
        interface: String,
    },
    #[error("native route response was invalid: {message}")]
    InvalidResponse { message: String },
    #[error("native operation {operation} failed: {message}")]
    OperatingSystem {
        operation: &'static str,
        message: String,
        #[source]
        source: Option<crate::SystemFault>,
    },
}

impl SystemError {
    /// The failure a backend reports when its caller's deadline stopped it
    /// while `operation` was in progress.
    pub(crate) fn interrupted(interrupted: Interrupted, operation: &'static str) -> Self {
        match interrupted {
            Interrupted::Cancelled(cancelled) => cancelled.into(),
            _ => Self::DeadlineExceeded { operation },
        }
    }
}

/// Route provider backed by the adapter selected for the current target and
/// the explicit `native-route` feature. Every backend bounds its native query
/// by the caller's deadline; none has a timeout of its own.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Error = SystemError;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        validate_preferred_source_family(destination, preferred_source)?;
        admit(deadline, "looking up a route")?;
        crate::platform::route(destination, interface_hint, preferred_source, deadline)
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
        deadline: &Deadline,
    ) -> Result<Option<Decision>, Self::Error> {
        admit(deadline, "looking up an interface route")?;
        crate::platform::interface_route(interface, deadline).map(Some)
    }
}

/// Refuses a lookup whose caller is already cancelled or out of time, before
/// any backend is asked.
fn admit(deadline: &Deadline, operation: &'static str) -> Result<(), SystemError> {
    crate::deadline::remaining(deadline)
        .map(drop)
        .map_err(|interrupted| SystemError::interrupted(interrupted, operation))
}

/// Rejects a preferred source of the wrong address family before any backend
/// sees it; the backends verify only what the operating system answers.
fn validate_preferred_source_family(
    destination: IpAddr,
    preferred_source: Option<IpAddr>,
) -> Result<(), SystemError> {
    if let Some(source) = preferred_source
        && source.is_ipv4() != destination.is_ipv4()
    {
        return Err(SystemError::SourceFamilyMismatch {
            preferred_source: source,
            destination,
        });
    }
    Ok(())
}

impl Classified for SystemError {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::DeadlineExceeded { operation } => {
                crate::Error::DeadlineExceeded { operation }.classification()
            }
            Self::Unsupported { .. } => Classification::new(
                "capability.route",
                Kind::Capability,
                Some(
                    "enable the native-route capability on a supported target or inject a route provider",
                ),
            ),
            Self::RouteNotFound { .. } => Classification::new(
                "io.route_not_found",
                Kind::Io,
                Some(
                    "add or select a route for the destination; PacketcraftR will not fall back to another link mode",
                ),
            ),
            Self::InterfaceNotFound { .. } => Classification::new(
                "io.interface_not_found",
                Kind::Io,
                Some("select an existing interface using its current name and index"),
            ),
            Self::InterfaceMismatch { .. }
            | Self::SourceFamilyMismatch { .. }
            | Self::SourceUnavailable { .. } => Classification::new(
                "io.route_selection",
                Kind::Io,
                Some(
                    "choose an interface-owned source and interface compatible with the destination family",
                ),
            ),
            Self::InvalidResponse { .. } => Classification::new(
                "internal.route_response",
                Kind::Internal,
                Some("report the invalid native route response; do not use it for transmission"),
            ),
            Self::OperatingSystem { .. } => Classification::new(
                "io.route",
                Kind::Io,
                Some(
                    "inspect the operating-system route diagnostic and current network configuration",
                ),
            ),
        }
    }
}

#[cfg(all(test, not(native_route)))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "fixture0".to_owned(),
            index: 7,
        }
    }

    #[test]
    fn portable_system_provider_fails_closed_for_both_lookup_contracts() {
        let provider = SystemProvider;
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let deadline = Deadline::new(std::time::Duration::from_secs(5));

        let route = provider
            .lookup_with_preferences(
                destination,
                Some(&interface()),
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
                &deadline,
            )
            .expect_err("portable build has no native route provider");
        let interface = provider
            .lookup_interface(&interface(), &deadline)
            .expect_err("portable build has no native interface route provider");

        for (error, capability) in [
            (route, "route selection"),
            (interface, "interface selection"),
        ] {
            assert!(matches!(
                error,
                SystemError::Unsupported { ref message }
                    if message.contains("enable the native-route feature")
                        && message.contains(capability)
            ));
            let classification = error.classification();
            assert_eq!(classification.code, "capability.route");
            assert_eq!(classification.kind, Kind::Capability);
        }
    }
}

#[cfg(test)]
mod family_tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    use packetcraftr_core::budget::Cancellation;

    use super::*;

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "fixture0".to_owned(),
            index: 7,
        }
    }

    #[test]
    fn a_preferred_source_of_the_other_family_is_rejected_before_the_kernel_is_asked() {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let preferred_source = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let error = SystemProvider
            .lookup_with_preferences(
                destination,
                None,
                Some(preferred_source),
                &Deadline::new(Duration::from_secs(5)),
            )
            .expect_err("mixed address families");

        assert!(matches!(
            error,
            SystemError::SourceFamilyMismatch {
                preferred_source: rejected,
                destination: requested,
            } if rejected == preferred_source && requested == destination
        ));
        assert_eq!(error.classification().code, "io.route_selection");
    }

    #[test]
    fn a_spent_or_cancelled_caller_is_refused_before_any_backend_is_asked() {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let frozen = Instant::now();
        let spent = Deadline::with_time_source(Duration::ZERO, move || frozen);
        for error in [
            SystemProvider
                .lookup_with_preferences(destination, None, None, &spent)
                .expect_err("spent deadline"),
            SystemProvider
                .lookup_interface(&interface(), &spent)
                .expect_err("spent deadline"),
        ] {
            assert!(matches!(error, SystemError::DeadlineExceeded { .. }));
            let classification = error.classification();
            assert_eq!(classification.code, "io.deadline_exceeded");
            assert_eq!(classification.kind, Kind::Io);
        }

        let signal = Cancellation::default();
        signal.cancel();
        let cancelled = Deadline::new(Duration::from_secs(5)).with_cancellation(Some(signal));
        let error = SystemProvider
            .lookup_with_preferences(destination, None, None, &cancelled)
            .expect_err("cancelled caller");
        assert!(matches!(error, SystemError::Cancelled(_)));
    }
}
