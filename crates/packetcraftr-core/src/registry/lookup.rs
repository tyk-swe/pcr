// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

use super::binding::{ChildBinding, Discriminator, FilterFieldBinding, ReverseBinding};
use super::builder::Builder;
use crate::codec::LayerCodec;

use crate::matcher::ResponseMatcher;

#[derive(Clone, Default)]
pub struct Registry {
    pub(super) codecs: BTreeMap<crate::layer::Id, Arc<dyn LayerCodec>>,
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

    /// The codec registered under a canonical protocol name.
    pub fn codec(&self, protocol: &str) -> Option<&Arc<dyn LayerCodec>> {
        self.codecs.get(protocol)
    }

    /// The codec a canonical name or alias resolves to, ignoring case.
    pub fn codec_named(&self, name: &str) -> Option<&Arc<dyn LayerCodec>> {
        self.codecs.get(&self.protocol_named(name)?)
    }

    /// Resolves a canonical name or alias to its protocol, ignoring case.
    pub fn protocol_named(&self, name: &str) -> Option<crate::layer::Id> {
        self.aliases.get(&name.trim().to_ascii_lowercase()).copied()
    }

    pub fn root_for_link_type(&self, link_type: u32) -> Option<crate::layer::Id> {
        self.roots.get(&link_type).copied()
    }

    /// The winning child that `discriminator` selects under `parent`.
    pub fn child_for(
        &self,
        parent: &str,
        discriminator: Discriminator,
    ) -> Option<crate::layer::Id> {
        self.bindings
            .get(parent)?
            .get(&discriminator)
            .and_then(|bindings| bindings.first())
            .map(|binding| binding.child)
    }

    /// The discriminator under which `parent` selects `child`.
    pub fn discriminator_for(&self, parent: &str, child: &str) -> Option<Discriminator> {
        self.reverse_bindings
            .get(parent)?
            .get(child)
            .and_then(|bindings| bindings.first())
            .map(|binding| binding.discriminator)
    }

    /// Every parent binding that selects `child`, as `(parent, discriminator)`
    /// pairs sorted by parent then discriminator.
    ///
    /// This is the reverse of [`Self::child_for`] over the whole registry, and
    /// answers the question a protocol reference cannot otherwise answer:
    /// which ports or EtherTypes reach this protocol. Only winning bindings
    /// appear; a binding another child outranks is not listed.
    pub fn parent_bindings(&self, child: &str) -> Vec<(crate::layer::Id, Discriminator)> {
        let mut bindings: Vec<_> = self
            .reverse_bindings
            .iter()
            .filter_map(|(parent, children)| Some((parent, children.get(child)?)))
            .flat_map(|(parent, entries)| {
                entries
                    .iter()
                    .map(move |entry| (*parent, entry.discriminator))
            })
            .collect();
        bindings
            .sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        bindings.dedup();
        bindings
    }

    pub fn matcher(&self, protocol: &str) -> Option<&Arc<dyn ResponseMatcher>> {
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
    pub fn schema(&self, protocol: &str) -> Option<&'static crate::layer::Schema> {
        self.schemas.get(protocol).copied()
    }

    /// Resolves a registered display-filter path. Lookup is case-insensitive.
    pub fn filter_field(&self, path: &str) -> Option<&FilterFieldBinding> {
        self.filter_fields.get(&path.trim().to_ascii_lowercase())
    }
}
