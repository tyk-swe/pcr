// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod error;
mod models;
#[cfg(native_route)]
pub(crate) mod normalize;

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;

use crate::interface::Id as InterfaceId;

pub use error::Error;
pub use models::{Decision, Scope, SelectionReason};

/// Passive route and interface lookups.
pub trait Provider: Send + Sync {
    type Error: Classified + Send + Sync + 'static;

    /// `preferred_source` constrains interface selection but never rewrites packet source.
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error>;

    /// Passively selects an interface for destination-free packets.
    fn lookup_interface(
        &self,
        _interface: &InterfaceId,
        _deadline: &Deadline,
    ) -> Result<Option<Decision>, Self::Error> {
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Error = Error;

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

fn admit(deadline: &Deadline, operation: &'static str) -> Result<(), Error> {
    crate::deadline::remaining(deadline)
        .map(drop)
        .map_err(|interrupted| Error::interrupted(interrupted, operation))
}

fn validate_preferred_source_family(
    destination: IpAddr,
    preferred_source: Option<IpAddr>,
) -> Result<(), Error> {
    if let Some(source) = preferred_source
        && source.is_ipv4() != destination.is_ipv4()
    {
        return Err(Error::SourceFamilyMismatch {
            preferred_source: source,
            destination,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    use packetcraftr_core::budget::Cancellation;
    use packetcraftr_core::error::Kind;

    use super::*;
    use crate::test_support::interface_id;

    fn interface() -> InterfaceId {
        interface_id("fixture0", 7)
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
            Error::SourceFamilyMismatch {
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
            assert!(matches!(error, Error::DeadlineExceeded { .. }));
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
        assert!(matches!(error, Error::Cancelled(_)));
    }
}
