// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;

use super::binding::{ChildBinding, Discriminator, FilterFieldBinding, ReverseBinding};
use super::builder::Builder;
use crate::codec::LayerCodec;

use crate::matcher::ResponseMatcher;

#[derive(Clone, Default)]
pub struct Registry {
    pub(super) codecs: BTreeMap<crate::layer::Id, Arc<dyn LayerCodec>>,
    pub(super) builtin_codecs: BTreeSet<crate::layer::Id>,
    pub(super) aliases: HashMap<String, crate::layer::Id>,
    pub(super) roots: HashMap<u32, crate::layer::Id>,
    pub(super) bindings: HashMap<crate::layer::Id, HashMap<Discriminator, Vec<ChildBinding>>>,
    pub(super) reverse_bindings:
        HashMap<crate::layer::Id, HashMap<crate::layer::Id, Vec<ReverseBinding>>>,
    pub(super) matchers: BTreeMap<crate::layer::Id, Arc<dyn ResponseMatcher>>,
    pub(super) schemas: BTreeMap<crate::layer::Id, &'static crate::layer::Schema>,
    pub(super) filter_fields: BTreeMap<String, FilterFieldBinding>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Registry")
            .field("protocols", &self.codecs.keys().collect::<Vec<_>>())
            .field("link_types", &self.roots)
            .field(
                "binding_count",
                &self.bindings.values().map(HashMap::len).sum::<usize>(),
            )
            .finish()
    }
}

impl Registry {
    pub fn builder() -> Builder {
        Builder::new()
    }

    pub fn codec<Q>(&self, protocol: &Q) -> Option<&Arc<dyn LayerCodec>>
    where
        crate::layer::Id: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.codecs.get(protocol)
    }

    pub fn codec_named(&self, name: &str) -> Option<&Arc<dyn LayerCodec>> {
        let normalized = name.trim().to_ascii_lowercase();
        let protocol = self.aliases.get(&normalized)?;
        self.codecs.get(protocol)
    }

    pub fn is_builtin_codec<Q>(&self, protocol: &Q) -> bool
    where
        crate::layer::Id: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.builtin_codecs.contains(protocol)
    }

    pub fn protocol_named(&self, name: &str) -> Option<&crate::layer::Id> {
        self.aliases.get(&name.trim().to_ascii_lowercase())
    }

    pub fn root_for_link_type(&self, link_type: u32) -> Option<&crate::layer::Id> {
        self.roots.get(&link_type)
    }

    /// All registered numeric capture roots. Iterator order is unspecified.
    pub fn link_type_roots(&self) -> impl ExactSizeIterator<Item = (u32, &crate::layer::Id)> {
        self.roots
            .iter()
            .map(|(link_type, protocol)| (*link_type, protocol))
    }

    pub fn child_for<Q>(
        &self,
        parent: &Q,
        discriminator: Discriminator,
    ) -> Option<&crate::layer::Id>
    where
        crate::layer::Id: std::borrow::Borrow<Q>,
        Q: Eq + std::hash::Hash + ?Sized,
    {
        self.bindings
            .get(parent)?
            .get(&discriminator)
            .and_then(|bindings| bindings.first())
            .map(|binding| &binding.child)
    }

    pub fn discriminator_for<P, C>(&self, parent: &P, child: &C) -> Option<Discriminator>
    where
        crate::layer::Id: std::borrow::Borrow<P> + std::borrow::Borrow<C>,
        P: Eq + std::hash::Hash + ?Sized,
        C: Eq + std::hash::Hash + ?Sized,
    {
        self.reverse_bindings
            .get(parent)?
            .get(child)
            .and_then(|bindings| bindings.first())
            .map(|binding| binding.discriminator)
    }

    pub fn matcher<Q>(&self, protocol: &Q) -> Option<&Arc<dyn ResponseMatcher>>
    where
        crate::layer::Id: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.matchers.get(protocol)
    }

    pub fn protocols(&self) -> impl ExactSizeIterator<Item = &crate::layer::Id> {
        self.codecs.keys()
    }

    /// The reflective schema of a registered protocol.
    ///
    /// Schemas are captured once, when the registry is built, through each
    /// codec's schema-publication hook. Decode-only codecs may publish a
    /// schema even when they cannot construct a layer.
    pub fn schema<Q>(&self, protocol: &Q) -> Option<&'static crate::layer::Schema>
    where
        crate::layer::Id: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.schemas.get(protocol).copied()
    }

    /// Resolves a registered display-filter path. Lookup is case-insensitive.
    pub fn filter_field(&self, path: &str) -> Option<&FilterFieldBinding> {
        self.filter_fields.get(&path.trim().to_ascii_lowercase())
    }

    /// Every registered display-filter path, in lexicographic order.
    pub fn filter_fields(&self) -> impl ExactSizeIterator<Item = (&str, &FilterFieldBinding)> {
        self.filter_fields
            .iter()
            .map(|(path, binding)| (path.as_str(), binding))
    }
}
