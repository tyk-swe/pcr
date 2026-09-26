// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use super::binding::{ChildBinding, Discriminator, FilterFieldBinding};
use super::error::Error;
use crate::codec::LayerCodec;
use crate::frame::LinkType;

use crate::matcher::ResponseMatcher;

#[derive(Default)]
pub struct Builder {
    pub(super) codecs: BTreeMap<crate::layer::Id, Arc<dyn LayerCodec>>,
    pub(super) aliases: HashMap<String, crate::layer::Id>,
    pub(super) roots: HashMap<LinkType, crate::layer::Id>,
    pub(super) bindings: HashMap<crate::layer::Id, HashMap<Discriminator, Vec<ChildBinding>>>,
    pub(super) matchers: BTreeMap<crate::layer::Id, Arc<dyn ResponseMatcher>>,
    pub(super) trailing_padding: BTreeSet<crate::layer::Id>,
    pub(super) filter_fields: BTreeMap<String, FilterFieldBinding>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a codec with its canonical name and caller-owned aliases.
    /// Codecs do not advertise aliases; built-ins use
    /// [`crate::protocol::BuiltinProtocol::aliases`].
    pub fn register_codec<C>(&mut self, codec: C, aliases: &[&str]) -> Result<&mut Self, Error>
    where
        C: LayerCodec + 'static,
    {
        let codec: Arc<dyn LayerCodec> = Arc::new(codec);
        let protocol = *codec.protocol_id();
        if self.codecs.contains_key(&protocol) {
            return Err(Error::DuplicateProtocol { protocol });
        }
        let mut resolvable: Vec<String> = Vec::new();
        for alias in std::iter::once(protocol.as_str()).chain(aliases.iter().copied()) {
            let alias = alias.trim().to_ascii_lowercase();
            if !resolvable.contains(&alias) {
                resolvable.push(alias);
            }
        }
        for alias in &resolvable {
            if let Some(existing) = self.aliases.get(alias) {
                return Err(Error::DuplicateAlias {
                    alias: alias.clone(),
                    existing: *existing,
                });
            }
        }
        for alias in resolvable {
            self.aliases.insert(alias, protocol);
        }
        self.codecs.insert(protocol, codec);
        Ok(self)
    }

    /// Records that frames of a link protocol may carry trailing padding after
    /// the payload its network layer declares, as Ethernet does to reach its
    /// minimum frame size.
    ///
    /// Decoding a link scope rooted at `protocol` preserves bytes past the
    /// network layer's declared length as link [`Padding`](crate::layer::Padding),
    /// and building accepts link padding inside it. Call it when registering
    /// the protocol's codec; [`Self::build`] rejects an unregistered protocol.
    pub fn allow_trailing_padding(&mut self, protocol: impl Into<crate::layer::Id>) -> &mut Self {
        self.trailing_padding.insert(protocol.into());
        self
    }

    pub fn bind_link_type(
        &mut self,
        link_type: LinkType,
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
        discriminator: impl Into<Discriminator>,
        child: impl Into<crate::layer::Id>,
        priority: i32,
    ) -> Result<&mut Self, Error> {
        let parent = parent.into();
        let child = child.into();
        let discriminator = discriminator.into();
        let entries = self
            .bindings
            .entry(parent)
            .or_default()
            .entry(discriminator)
            .or_default();
        if entries.iter().any(|entry| {
            (entry.priority == priority && entry.child != child)
                || (entry.child == child && entry.priority != priority)
        }) {
            return Err(Error::BindingConflict {
                parent,
                discriminator: discriminator.0,
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

    /// Registers an additional case-insensitive, registry-unique filter path.
    /// Canonical `<protocol>.<field>` paths already resolve without
    /// registration.
    pub fn bind_filter_field(
        &mut self,
        path: &'static str,
        binding: FilterFieldBinding,
    ) -> Result<&mut Self, Error> {
        let normalized = path.trim().to_ascii_lowercase();
        if let Some(existing) = self.filter_fields.get(&normalized) {
            return Err(Error::DuplicateFilterField {
                path: normalized,
                existing: *existing.protocol(),
            });
        }
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
