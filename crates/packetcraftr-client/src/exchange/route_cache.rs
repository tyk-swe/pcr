// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use packetcraftr_net::route::{InterfaceId, RouteDecision, RouteProvider};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ExchangeRouteLookupKey {
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
pub(crate) struct ExchangeRouteProvider<'a, R> {
    inner: &'a R,
    decisions: Mutex<HashMap<ExchangeRouteLookupKey, Option<RouteDecision>>>,
}

impl<'a, R: RouteProvider> ExchangeRouteProvider<'a, R> {
    pub(crate) fn new(inner: &'a R) -> Self {
        Self {
            inner,
            decisions: Mutex::new(HashMap::new()),
        }
    }

    fn get_or_lookup(
        &self,
        key: ExchangeRouteLookupKey,
        lookup: impl FnOnce() -> Result<Option<RouteDecision>, R::Error>,
    ) -> Result<Option<RouteDecision>, R::Error> {
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

impl<R: RouteProvider> RouteProvider for ExchangeRouteProvider<'_, R> {
    type Error = R::Error;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        let key = ExchangeRouteLookupKey::LookupWithPreferences {
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
    ) -> Result<Option<RouteDecision>, Self::Error> {
        let key = ExchangeRouteLookupKey::Interface {
            interface: interface.clone(),
        };
        self.get_or_lookup(key, || self.inner.lookup_interface(interface))
    }

    fn classify_error(&self, error: &Self::Error) -> packetcraftr_core::error::Classification {
        self.inner.classify_error(error)
    }
}
