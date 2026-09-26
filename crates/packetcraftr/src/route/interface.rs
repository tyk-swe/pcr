// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, PoisonError};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::interface::{self, Id as InterfaceId};

use super::Error;

/// The interface a route must leave through.
///
/// A name or index selector is resolved through the client's interface
/// provider only after the operation is admitted, so a refused operation
/// never enumerates interfaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Interface {
    /// An identity an interface provider already confirmed.
    Id(InterfaceId),
    /// The interface with this name.
    Name(String),
    /// The interface with this index.
    Index(NonZeroU32),
}

impl Interface {
    /// Whether `id` is the interface this selector names: an index selector
    /// ignores the name, and a name selector ignores the index.
    #[must_use]
    pub fn matches(&self, id: &InterfaceId) -> bool {
        match self {
            Self::Id(selected) => selected == id,
            Self::Name(name) => id.name == *name,
            Self::Index(index) => id.index == index.get(),
        }
    }

    /// The confirmed identity, or `None` for a selector not yet resolved.
    pub(crate) fn id(&self) -> Option<&InterfaceId> {
        match self {
            Self::Id(id) => Some(id),
            Self::Name(_) | Self::Index(_) => None,
        }
    }
}

impl From<InterfaceId> for Interface {
    fn from(id: InterfaceId) -> Self {
        Self::Id(id)
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(InterfaceId { name, .. }) | Self::Name(name) => formatter.write_str(name),
            Self::Index(index) => write!(formatter, "{index}"),
        }
    }
}

/// The last selector a client resolved and the identity it resolved to.
///
/// Every operation of one client (and each operation-local view of it)
/// shares it, so a workflow that prepares many packets enumerates interfaces
/// once. A failed lookup is not remembered.
#[derive(Clone, Debug, Default)]
pub(crate) struct Resolved(Arc<Mutex<Option<(Interface, InterfaceId)>>>);

impl Resolved {
    /// Resolves `selector` through `provider` under `deadline`, unless it is
    /// already an identity or was the last selector resolved.
    pub(crate) fn resolve<N: interface::Provider + ?Sized>(
        &self,
        selector: &Interface,
        provider: &N,
        deadline: &Deadline,
    ) -> Result<InterfaceId, Error> {
        if let Some(id) = selector.id() {
            return Ok(id.clone());
        }
        let cached = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((resolved, id)) = cached.as_ref()
            && resolved == selector
        {
            return Ok(id.clone());
        }
        drop(cached);
        let id = provider
            .interfaces(deadline)?
            .into_iter()
            .map(|info| info.id)
            .find(|id| selector.matches(id))
            .ok_or_else(|| Error::UnknownInterface {
                selector: selector.to_string(),
            })?;
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((selector.clone(), id.clone()));
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use packetcraftr_core::error::Classified;
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::interface::{Flags, Info};
    use packetcraftr_netio::link::Capability;

    use super::*;

    #[derive(Default)]
    struct Flaky {
        calls: AtomicUsize,
    }

    impl interface::Provider for Flaky {
        fn interfaces(&self, _deadline: &Deadline) -> Result<Vec<Info>, interface::Error> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(interface::Error::DeadlineExceeded {
                    operation: "enumerating interfaces",
                });
            }
            Ok(vec![Info {
                id: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 9,
                },
                description: None,
                mac_address: None,
                addresses: Vec::new(),
                flags: Flags::default(),
                mtu: None,
                capability: Capability::Layer2AndLayer3,
                link_type: LinkType::ETHERNET,
            }])
        }
    }

    fn live() -> Deadline {
        Deadline::new(std::time::Duration::from_secs(5))
    }

    #[test]
    fn a_failed_lookup_is_retried_and_a_resolved_one_is_remembered() {
        let provider = Flaky::default();
        let resolved = Resolved::default();
        let selector = Interface::Name("fixture0".to_owned());

        let error = resolved
            .resolve(&selector, &provider, &live())
            .expect_err("the first enumeration fails");
        assert_eq!(error.classification().code, "io.deadline_exceeded");

        for _ in 0..2 {
            let id = resolved
                .resolve(&selector, &provider, &live())
                .expect("the second enumeration succeeds");
            assert_eq!(id.index, 9);
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);

        let by_index = Interface::Index(NonZeroU32::new(9).unwrap());
        assert_eq!(
            resolved
                .resolve(&by_index, &provider, &live())
                .unwrap()
                .name,
            "fixture0"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn an_unmatched_selector_is_an_unavailable_device() {
        let provider = Flaky {
            calls: AtomicUsize::new(1),
        };
        let error = Resolved::default()
            .resolve(&Interface::Name("missing0".to_owned()), &provider, &live())
            .expect_err("nothing matches");
        assert_eq!(error.classification().code, "io.device");
        assert!(error.to_string().contains("missing0"), "{error}");
    }

    #[test]
    fn an_identity_needs_no_enumeration_and_selectors_match_their_half() {
        let provider = Flaky::default();
        let id = InterfaceId {
            name: "eth0".to_owned(),
            index: 7,
        };
        assert_eq!(
            Resolved::default()
                .resolve(&Interface::Id(id.clone()), &provider, &live())
                .unwrap(),
            id
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(Interface::Index(NonZeroU32::new(7).unwrap()).matches(&id));
        assert!(Interface::Name("eth0".to_owned()).matches(&id));
        assert!(!Interface::Name("eth1".to_owned()).matches(&id));
        assert_eq!(
            Interface::Index(NonZeroU32::new(7).unwrap()).to_string(),
            "7"
        );
    }
}
