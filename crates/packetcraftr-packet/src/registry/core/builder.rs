// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use super::super::super::codec::LayerCodec;
use super::super::super::layer::ProtocolId;
use super::super::super::matcher::ResponseMatcher;
use super::binding::{ChildBinding, Discriminator, FilterFieldBinding};
use super::error::RegistryError;
use super::module::ProtocolModule;

#[derive(Default)]
pub struct RegistryBuilder {
    pub(super) codecs: BTreeMap<ProtocolId, Arc<dyn LayerCodec>>,
    pub(super) builtin_codecs: BTreeSet<ProtocolId>,
    pub(super) aliases: HashMap<String, ProtocolId>,
    pub(super) roots: HashMap<u32, ProtocolId>,
    pub(super) bindings: HashMap<ProtocolId, HashMap<Discriminator, Vec<ChildBinding>>>,
    pub(super) matchers: BTreeMap<ProtocolId, Arc<dyn ResponseMatcher>>,
    pub(super) filter_fields: BTreeMap<String, FilterFieldBinding>,
}

impl RegistryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_codec<C>(&mut self, codec: C) -> Result<&mut Self, RegistryError>
    where
        C: LayerCodec + 'static,
    {
        let aliases = codec.aliases();
        self.register_codec_with_origin(Arc::new(codec), false, aliases)
    }

    pub fn register_builtin_codec<C>(
        &mut self,
        codec: C,
        aliases: &'static [&'static str],
    ) -> Result<&mut Self, RegistryError>
    where
        C: LayerCodec + 'static,
    {
        self.register_codec_with_origin(Arc::new(codec), true, aliases)
    }

    pub(super) fn register_codec_with_origin(
        &mut self,
        codec: Arc<dyn LayerCodec>,
        builtin: bool,
        advertised_aliases: &[&str],
    ) -> Result<&mut Self, RegistryError> {
        let protocol = codec.protocol_id();
        if self.codecs.contains_key(&protocol) {
            return Err(RegistryError::DuplicateProtocol { protocol });
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
                return Err(RegistryError::DuplicateAlias {
                    alias: alias.clone(),
                    existing: existing.clone(),
                });
            }
        }
        for alias in aliases {
            self.aliases.insert(alias, protocol.clone());
        }
        if builtin {
            self.builtin_codecs.insert(protocol.clone());
        }
        self.codecs.insert(protocol, codec);
        Ok(self)
    }

    pub fn bind_link_type(
        &mut self,
        link_type: u32,
        root: impl Into<ProtocolId>,
    ) -> Result<&mut Self, RegistryError> {
        if self.roots.contains_key(&link_type) {
            return Err(RegistryError::DuplicateLinkType { link_type });
        }
        self.roots.insert(link_type, root.into());
        Ok(self)
    }

    pub fn bind(
        &mut self,
        parent: impl Into<ProtocolId>,
        discriminator: u64,
        child: impl Into<ProtocolId>,
        priority: i32,
    ) -> Result<&mut Self, RegistryError> {
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
            return Err(RegistryError::BindingConflict {
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
        protocol: impl Into<ProtocolId>,
        matcher: M,
    ) -> Result<&mut Self, RegistryError>
    where
        M: ResponseMatcher + 'static,
    {
        let protocol = protocol.into();
        if self.matchers.contains_key(&protocol) {
            return Err(RegistryError::DuplicateMatcher { protocol });
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
    ) -> Result<&mut Self, RegistryError> {
        let normalized = path.trim().to_ascii_lowercase();
        if let Some(existing) = self.filter_fields.get(&normalized) {
            return Err(RegistryError::DuplicateFilterField {
                path: normalized,
                existing: existing.protocol().clone(),
            });
        }
        // Structural defects need no registry context, so reject them at the
        // call site rather than deferring to `build`.
        let invalid = |reason: String| RegistryError::InvalidFilterField {
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
            // The extraction is `(value & mask) >> shift`, so a shift past the
            // mask's highest selected bit yields zero for every packet. Such a
            // binding would build cleanly and then silently never match.
            if mask >> shift == 0 {
                return Err(invalid(format!(
                    "its bit shift {shift} discards every bit selected by mask {mask:#x}"
                )));
            }
        }
        self.filter_fields.insert(normalized, binding);
        Ok(self)
    }

    pub fn module<M>(&mut self, module: &M) -> Result<&mut Self, RegistryError>
    where
        M: ProtocolModule,
    {
        module.register(self)?;
        Ok(self)
    }
}
