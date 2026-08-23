// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use packetcraftr_netio::interface::Id as InterfaceId;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum LookupKey {
    LookupWithPreferences {
        destination: IpAddr,
        interface_hint: Option<InterfaceId>,
        preferred_source: Option<IpAddr>,
    },
    Interface {
        interface: InterfaceId,
    },
}

/// Memoizes passive route decisions for one exchange without retaining an
/// operating-system route snapshot beyond that operation.
pub(super) struct CachedProvider<'a, R> {
    inner: &'a R,
    decisions: Mutex<HashMap<LookupKey, Option<packetcraftr_netio::route::Decision>>>,
}

impl<'a, R: packetcraftr_netio::route::Provider> CachedProvider<'a, R> {
    pub(super) fn new(inner: &'a R) -> Self {
        Self {
            inner,
            decisions: Mutex::new(HashMap::new()),
        }
    }

    fn get_or_lookup(
        &self,
        key: LookupKey,
        lookup: impl FnOnce() -> Result<Option<packetcraftr_netio::route::Decision>, R::Error>,
    ) -> Result<Option<packetcraftr_netio::route::Decision>, R::Error> {
        let cached = self
            .decisions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .cloned();
        if let Some(decision) = cached {
            return Ok(decision);
        }

        let decision = lookup()?;
        self.decisions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, decision.clone());
        Ok(decision)
    }
}

impl<R: packetcraftr_netio::route::Provider> packetcraftr_netio::route::Provider
    for CachedProvider<'_, R>
{
    type Error = R::Error;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<packetcraftr_netio::route::Decision, Self::Error> {
        let key = LookupKey::LookupWithPreferences {
            destination,
            interface_hint: interface_hint.cloned(),
            preferred_source,
        };
        Ok(self
            .get_or_lookup(key, || {
                self.inner
                    .lookup_with_preferences(destination, interface_hint, preferred_source)
                    .map(Some)
            })?
            .expect("route provider lookup always returns a decision"))
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
    ) -> Result<Option<packetcraftr_netio::route::Decision>, Self::Error> {
        let key = LookupKey::Interface {
            interface: interface.clone(),
        };
        self.get_or_lookup(key, || self.inner.lookup_interface(interface))
    }

    fn classify_error(&self, error: &Self::Error) -> packetcraftr_core::error::Classification {
        self.inner.classify_error(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use packetcraftr_core::error::Classification;
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::link::{Capability, MacAddress};
    use packetcraftr_netio::route::{Provider, Scope, SelectionReason};

    #[derive(Clone, Copy, Debug)]
    struct FixtureError;

    impl fmt::Display for FixtureError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fixture route error")
        }
    }

    impl std::error::Error for FixtureError {}

    struct CountingProvider {
        lookups: AtomicUsize,
        interfaces: AtomicUsize,
        fail: AtomicBool,
        interface_result: Option<packetcraftr_netio::route::Decision>,
    }

    impl CountingProvider {
        fn new(interface_result: Option<packetcraftr_netio::route::Decision>) -> Self {
            Self {
                lookups: AtomicUsize::new(0),
                interfaces: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                interface_result,
            }
        }
    }

    impl packetcraftr_netio::route::Provider for CountingProvider {
        type Error = FixtureError;

        fn lookup_with_preferences(
            &self,
            destination: IpAddr,
            interface_hint: Option<&InterfaceId>,
            preferred_source: Option<IpAddr>,
        ) -> Result<packetcraftr_netio::route::Decision, Self::Error> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(FixtureError);
            }
            let mut decision = decision();
            decision.next_hop = Some(destination);
            decision.interface = interface_hint.cloned().unwrap_or_else(interface);
            decision.preferred_source = preferred_source;
            Ok(decision)
        }

        fn lookup_interface(
            &self,
            _interface: &InterfaceId,
        ) -> Result<Option<packetcraftr_netio::route::Decision>, Self::Error> {
            self.interfaces.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                Err(FixtureError)
            } else {
                Ok(self.interface_result.clone())
            }
        }

        fn classify_error(&self, _error: &Self::Error) -> Classification {
            Classification::new("capability.fixture", None)
        }
    }

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "fixture0".to_owned(),
            index: 5,
        }
    }

    fn decision() -> packetcraftr_netio::route::Decision {
        packetcraftr_netio::route::Decision {
            interface: interface(),
            source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 1_500,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }
    }

    #[test]
    fn identical_route_arguments_are_memoized_but_distinct_keys_are_not() {
        let provider = CountingProvider::new(Some(decision()));
        let cache = CachedProvider::new(&provider);
        let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let first = cache
            .lookup_with_preferences(destination, None, None)
            .expect("first lookup");
        let second = cache
            .lookup_with_preferences(destination, None, None)
            .expect("cached lookup");
        assert_eq!(first, second);
        assert_eq!(provider.lookups.load(Ordering::SeqCst), 1);

        cache
            .lookup_with_preferences(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), None, None)
            .expect("distinct destination");
        cache
            .lookup_with_preferences(destination, Some(&interface()), None)
            .expect("distinct interface hint");
        cache
            .lookup_with_preferences(
                destination,
                None,
                Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
            )
            .expect("distinct source preference");
        assert_eq!(provider.lookups.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn interface_decisions_cache_both_some_and_none_results() {
        let provider = CountingProvider::new(Some(decision()));
        let cache = CachedProvider::new(&provider);
        assert_eq!(
            cache.lookup_interface(&interface()).expect("first lookup"),
            Some(decision())
        );
        assert_eq!(
            cache.lookup_interface(&interface()).expect("cached lookup"),
            Some(decision())
        );
        assert_eq!(provider.interfaces.load(Ordering::SeqCst), 1);

        let none_provider = CountingProvider::new(None);
        let none_cache = CachedProvider::new(&none_provider);
        assert_eq!(
            none_cache.lookup_interface(&interface()).expect("none"),
            None
        );
        assert_eq!(
            none_cache
                .lookup_interface(&interface())
                .expect("cached none"),
            None
        );
        assert_eq!(none_provider.interfaces.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn provider_errors_are_not_cached_and_classification_is_delegated() {
        let provider = CountingProvider::new(None);
        provider.fail.store(true, Ordering::SeqCst);
        let cache = CachedProvider::new(&provider);
        let destination = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(
            cache
                .lookup_with_preferences(destination, None, None)
                .is_err()
        );
        assert!(
            cache
                .lookup_with_preferences(destination, None, None)
                .is_err()
        );
        assert_eq!(provider.lookups.load(Ordering::SeqCst), 2);
        assert_eq!(
            cache.classify_error(&FixtureError),
            Classification::new("capability.fixture", None)
        );
    }

    #[test]
    fn poisoned_cache_mutex_recovers_without_bypassing_lookup() {
        let provider = CountingProvider::new(Some(decision()));
        let cache = CachedProvider::new(&provider);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.decisions.lock().expect("initial cache lock");
            panic!("poison fixture cache");
        }));

        assert_eq!(
            cache
                .lookup_interface(&interface())
                .expect("recovered lookup"),
            Some(decision())
        );
        assert_eq!(provider.interfaces.load(Ordering::SeqCst), 1);
    }
}
