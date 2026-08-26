// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::binding::{ChildBinding, Discriminator, FilterFieldBinding};
use super::error::Error;
use crate::codec::LayerCodec;

use crate::matcher::ResponseMatcher;

#[derive(Default)]
pub struct Builder {
    pub(super) codecs: BTreeMap<crate::layer::Id, Arc<dyn LayerCodec>>,
    pub(super) aliases: HashMap<String, crate::layer::Id>,
    pub(super) roots: HashMap<u32, crate::layer::Id>,
    pub(super) bindings: HashMap<crate::layer::Id, HashMap<Discriminator, Vec<ChildBinding>>>,
    pub(super) matchers: BTreeMap<crate::layer::Id, Arc<dyn ResponseMatcher>>,
    pub(super) filter_fields: BTreeMap<String, FilterFieldBinding>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_codec<C>(&mut self, codec: C) -> Result<&mut Self, Error>
    where
        C: LayerCodec + 'static,
    {
        let aliases = codec.aliases();
        self.register_codec_with_aliases(Arc::new(codec), aliases)
    }

    /// Registers a codec under an explicit alias list instead of the one the
    /// codec advertises. The built-in registry uses it; it carries no other
    /// distinction.
    pub fn register_builtin_codec<C>(
        &mut self,
        codec: C,
        aliases: &'static [&'static str],
    ) -> Result<&mut Self, Error>
    where
        C: LayerCodec + 'static,
    {
        self.register_codec_with_aliases(Arc::new(codec), aliases)
    }

    pub(super) fn register_codec_with_aliases(
        &mut self,
        codec: Arc<dyn LayerCodec>,
        advertised_aliases: &[&str],
    ) -> Result<&mut Self, Error> {
        let protocol = codec.protocol_id();
        if self.codecs.contains_key(&protocol) {
            return Err(Error::DuplicateProtocol { protocol });
        }
        let mut aliases = Vec::new();
        for alias in std::iter::once(protocol.as_str()).chain(advertised_aliases.iter().copied()) {
            let alias = alias.trim().to_ascii_lowercase();
            if !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
        for alias in &aliases {
            if let Some(existing) = self.aliases.get(alias) {
                return Err(Error::DuplicateAlias {
                    alias: alias.clone(),
                    existing: existing.clone(),
                });
            }
        }
        for alias in aliases {
            self.aliases.insert(alias, protocol.clone());
        }
        self.codecs.insert(protocol, codec);
        Ok(self)
    }

    pub fn bind_link_type(
        &mut self,
        link_type: u32,
        root: impl Into<crate::layer::Id>,
    ) -> Result<&mut Self, Error> {
        if self.roots.contains_key(&link_type) {
            return Err(Error::DuplicateLinkType { link_type });
        }
        self.roots.insert(link_type, root.into());
        Ok(self)
    }

    pub fn bind(
        &mut self,
        parent: impl Into<crate::layer::Id>,
        discriminator: u64,
        child: impl Into<crate::layer::Id>,
        priority: i32,
    ) -> Result<&mut Self, Error> {
        let parent = parent.into();
        let child = child.into();
        let entries = self
            .bindings
            .entry(parent.clone())
            .or_default()
            .entry(Discriminator(discriminator))
            .or_default();
        if entries.iter().any(|entry| {
            (entry.priority == priority && entry.child != child)
                || (entry.child == child && entry.priority != priority)
        }) {
            return Err(Error::BindingConflict {
                parent,
                discriminator,
                priority,
            });
        }
        if !entries.iter().any(|entry| entry.child == child) {
            entries.push(ChildBinding { child, priority });
        }
        Ok(self)
    }

    pub fn register_matcher<M>(
        &mut self,
        protocol: impl Into<crate::layer::Id>,
        matcher: M,
    ) -> Result<&mut Self, Error>
    where
        M: ResponseMatcher + 'static,
    {
        let protocol = protocol.into();
        if self.matchers.contains_key(&protocol) {
            return Err(Error::DuplicateMatcher { protocol });
        }
        self.matchers.insert(protocol, Arc::new(matcher));
        Ok(self)
    }

    /// Publishes an additional display-filter spelling for a protocol field.
    ///
    /// Canonical `<protocol>.<field>` paths always resolve without a binding;
    /// this registers the conventional operator-facing names on top of them.
    /// Paths are matched case-insensitively and every path is unique across the
    /// registry, so one spelling can never resolve to two protocols.
    pub fn bind_filter_field(
        &mut self,
        path: &'static str,
        binding: FilterFieldBinding,
    ) -> Result<&mut Self, Error> {
        let normalized = path.trim().to_ascii_lowercase();
        if let Some(existing) = self.filter_fields.get(&normalized) {
            return Err(Error::DuplicateFilterField {
                path: normalized,
                existing: existing.protocol().clone(),
            });
        }
        // Reject structural binding defects at registration.
        let invalid = |reason: String| Error::InvalidFilterField {
            path: normalized.clone(),
            reason,
        };
        if binding.fields().is_empty() {
            return Err(invalid("it names no reflective field".to_owned()));
        }
        if let FilterFieldBinding::Bits { mask, shift, .. } = &binding {
            if *mask == 0 {
                return Err(invalid("its bit mask selects no bits".to_owned()));
            }
            if *shift >= u64::BITS {
                return Err(invalid(format!(
                    "its bit shift {shift} is not below {}",
                    u64::BITS
                )));
            }
            // Shifting past every selected bit would create a non-matching binding.
            if mask >> shift == 0 {
                return Err(invalid(format!(
                    "its bit shift {shift} discards every bit selected by mask {mask:#x}"
                )));
            }
        }
        self.filter_fields.insert(normalized, binding);
        Ok(self)
    }
}
