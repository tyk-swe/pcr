// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Kind};

use crate::interface::Id as InterfaceId;

use super::models::{Decision, Provider};

/// Errors emitted by the current target's passive route/interface adapter.
///
/// A native refusal is retained as a [`SystemFault`](crate::SystemFault)
/// rather than formatted into `message`, so the operating-system diagnostic
/// survives to the render boundary. That source is not comparable, so these
/// failures are matched on rather than equated.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum SystemError {
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

/// Route provider backed by the adapter selected for the current target and
/// the explicit `native-route` feature.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Error = SystemError;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        crate::platform::system_route(destination, interface_hint, preferred_source)
    }

    fn lookup_interface(&self, interface: &InterfaceId) -> Result<Option<Decision>, Self::Error> {
        crate::platform::system_interface_route(interface).map(Some)
    }

    fn classify_error(&self, error: &Self::Error) -> Classification {
        error.classification()
    }
}

impl Classified for SystemError {
    fn classification(&self) -> Classification {
        match self {
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

#[cfg(all(test, not(feature = "native-route")))]
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

        let route = provider
            .lookup_with_preferences(
                destination,
                Some(&interface()),
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
            )
            .expect_err("portable build has no native route provider");
        let interface = provider
            .lookup_interface(&interface())
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
            let classification = provider.classify_error(&error);
            assert_eq!(classification.code, "capability.route");
            assert_eq!(classification.kind, Kind::Capability);
        }
    }
}
