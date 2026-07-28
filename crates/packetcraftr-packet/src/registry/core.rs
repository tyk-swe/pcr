// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use super::super::codec::LayerCodec;
use super::super::field::{FieldKind, FieldValue};
use super::super::layer::{LayerSchema, ProtocolId};
use super::super::matcher::ResponseMatcher;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Discriminator(pub u64);

/// How one display-filter path resolves onto reflective layer fields.
///
/// Canonical `<protocol>.<field>` paths need no binding: the filter compiler
/// resolves them directly against [`ProtocolRegistry::schema`]. Bindings exist
/// so a protocol can additionally publish the conventional spellings operators
/// already type, and so a packed field can be addressed one flag at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterFieldBinding {
    /// An alternate spelling of one reflective field.
    Direct {
        protocol: ProtocolId,
        field: &'static str,
    },
    /// One sub-value of a packed unsigned field, such as a single TCP flag.
    ///
    /// The field value is masked and then shifted right, so a single flag bit
    /// compares against `0` and `1` rather than its raw positional weight.
    Bits {
        protocol: ProtocolId,
        field: &'static str,
        mask: u64,
        shift: u32,
    },
    /// Several reflective fields addressed by one path, such as a port that
    /// may appear as either endpoint. A comparison holds when **any** listed
    /// field satisfies it.
    Either {
        protocol: ProtocolId,
        fields: &'static [&'static str],
    },
}

impl FilterFieldBinding {
    /// The protocol whose layers this path reads.
    pub fn protocol(&self) -> &ProtocolId {
        match self {
            Self::Direct { protocol, .. }
            | Self::Bits { protocol, .. }
            | Self::Either { protocol, .. } => protocol,
        }
    }

    /// Every reflective field name this path may read.
    pub fn fields(&self) -> &[&'static str] {
        match self {
            Self::Direct { field, .. } | Self::Bits { field, .. } => std::slice::from_ref(field),
            Self::Either { fields, .. } => fields,
        }
    }
}

/// A compile-time Rust extension module.
pub trait ProtocolModule {
    fn register(&self, builder: &mut RegistryBuilder) -> Result<(), RegistryError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    #[error("protocol codec {protocol} is already registered")]
    DuplicateProtocol { protocol: ProtocolId },
    #[error("protocol alias {alias} is already registered for {existing}")]
    DuplicateAlias { alias: String, existing: ProtocolId },
    #[error("link type {link_type} already has a root binding")]
    DuplicateLinkType { link_type: u32 },
    #[error(
        "binding conflict for parent {parent}, discriminator {discriminator}, priority {priority}"
    )]
    BindingConflict {
        parent: ProtocolId,
        discriminator: u64,
        priority: i32,
    },
    #[error("response matcher for {protocol} is already registered")]
    DuplicateMatcher { protocol: ProtocolId },
    #[error("binding references unregistered protocol {protocol}")]
    UnknownProtocol { protocol: ProtocolId },
    #[error("filter field path {path} is already registered for {existing}")]
    DuplicateFilterField { path: String, existing: ProtocolId },
    #[error("filter field path {path} names field {field}, absent from layer {protocol}")]
    UnknownFilterField {
        path: String,
        protocol: ProtocolId,
        field: String,
    },
    #[error("filter field path {path} is not usable: {reason}")]
    InvalidFilterField { path: String, reason: String },
}

#[derive(Clone, Debug)]
struct ChildBinding {
    child: ProtocolId,
    priority: i32,
}

#[derive(Clone, Copy, Debug)]
struct ReverseBinding {
    discriminator: Discriminator,
    priority: i32,
}

#[derive(Clone, Default)]
pub struct ProtocolRegistry {
    codecs: BTreeMap<ProtocolId, Arc<dyn LayerCodec>>,
    builtin_codecs: BTreeSet<ProtocolId>,
    aliases: HashMap<String, ProtocolId>,
    roots: HashMap<u32, ProtocolId>,
    bindings: HashMap<ProtocolId, HashMap<Discriminator, Vec<ChildBinding>>>,
    reverse_bindings: HashMap<ProtocolId, HashMap<ProtocolId, Vec<ReverseBinding>>>,
    matchers: BTreeMap<ProtocolId, Arc<dyn ResponseMatcher>>,
    schemas: BTreeMap<ProtocolId, &'static LayerSchema>,
    filter_fields: BTreeMap<String, FilterFieldBinding>,
}

impl fmt::Debug for ProtocolRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolRegistry")
            .field("protocols", &self.codecs.keys().collect::<Vec<_>>())
            .field("link_types", &self.roots)
            .field(
                "binding_count",
                &self.bindings.values().map(HashMap::len).sum::<usize>(),
            )
            .finish()
    }
}

impl ProtocolRegistry {
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::new()
    }

    pub fn codec<Q>(&self, protocol: &Q) -> Option<&Arc<dyn LayerCodec>>
    where
        ProtocolId: std::borrow::Borrow<Q>,
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
        ProtocolId: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.builtin_codecs.contains(protocol)
    }

    pub fn protocol_named(&self, name: &str) -> Option<&ProtocolId> {
        self.aliases.get(&name.trim().to_ascii_lowercase())
    }

    pub fn root_for_link_type(&self, link_type: u32) -> Option<&ProtocolId> {
        self.roots.get(&link_type)
    }

    /// All registered numeric capture roots. Iterator order is unspecified.
    pub fn link_type_roots(&self) -> impl ExactSizeIterator<Item = (u32, &ProtocolId)> {
        self.roots
            .iter()
            .map(|(link_type, protocol)| (*link_type, protocol))
    }

    pub fn child_for<Q>(&self, parent: &Q, discriminator: Discriminator) -> Option<&ProtocolId>
    where
        ProtocolId: std::borrow::Borrow<Q>,
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
        ProtocolId: std::borrow::Borrow<P> + std::borrow::Borrow<C>,
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
        ProtocolId: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.matchers.get(protocol)
    }

    /// Protocols with registered request/response matchers.
    pub fn matcher_protocols(&self) -> impl ExactSizeIterator<Item = &ProtocolId> {
        self.matchers.keys()
    }

    pub fn protocols(&self) -> impl ExactSizeIterator<Item = &ProtocolId> {
        self.codecs.keys()
    }

    /// The reflective schema of a registered protocol.
    ///
    /// Schemas are captured once, when the registry is built, from a default
    /// layer produced by each codec. A decode-only codec cannot construct one,
    /// so it reports [`None`]; its decoded layers still carry their own schema.
    pub fn schema<Q>(&self, protocol: &Q) -> Option<&'static LayerSchema>
    where
        ProtocolId: std::borrow::Borrow<Q>,
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

#[derive(Default)]
pub struct RegistryBuilder {
    codecs: BTreeMap<ProtocolId, Arc<dyn LayerCodec>>,
    builtin_codecs: BTreeSet<ProtocolId>,
    aliases: HashMap<String, ProtocolId>,
    roots: HashMap<u32, ProtocolId>,
    bindings: HashMap<ProtocolId, HashMap<Discriminator, Vec<ChildBinding>>>,
    matchers: BTreeMap<ProtocolId, Arc<dyn ResponseMatcher>>,
    filter_fields: BTreeMap<String, FilterFieldBinding>,
}

impl RegistryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_codec<C>(&mut self, codec: C) -> Result<&mut Self, RegistryError>
    where
        C: LayerCodec + 'static,
    {
        self.register_codec_with_origin(Arc::new(codec), false)
    }

    pub fn register_builtin_codec<C>(&mut self, codec: C) -> Result<&mut Self, RegistryError>
    where
        C: LayerCodec + 'static,
    {
        self.register_codec_with_origin(Arc::new(codec), true)
    }

    fn register_codec_with_origin(
        &mut self,
        codec: Arc<dyn LayerCodec>,
        builtin: bool,
    ) -> Result<&mut Self, RegistryError> {
        let protocol = codec.protocol_id();
        if self.codecs.contains_key(&protocol) {
            return Err(RegistryError::DuplicateProtocol { protocol });
        }
        let mut aliases = Vec::new();
        for alias in std::iter::once(protocol.as_str()).chain(codec.aliases().iter().copied()) {
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

    pub fn build(mut self) -> Result<ProtocolRegistry, RegistryError> {
        for protocol in self.roots.values() {
            if !self.codecs.contains_key(protocol) {
                return Err(RegistryError::UnknownProtocol {
                    protocol: protocol.clone(),
                });
            }
        }
        let mut reverse_bindings: HashMap<ProtocolId, HashMap<ProtocolId, Vec<ReverseBinding>>> =
            HashMap::new();
        for (parent, discriminators) in &mut self.bindings {
            if !self.codecs.contains_key(parent) {
                return Err(RegistryError::UnknownProtocol {
                    protocol: parent.clone(),
                });
            }
            for (discriminator, entries) in discriminators {
                entries.sort_by(|left, right| {
                    right
                        .priority
                        .cmp(&left.priority)
                        .then_with(|| left.child.cmp(&right.child))
                });
                for entry in entries.iter() {
                    if !self.codecs.contains_key(&entry.child) {
                        return Err(RegistryError::UnknownProtocol {
                            protocol: entry.child.clone(),
                        });
                    }
                }
                entries.truncate(1);
                let winner = entries.first().expect("bindings are never empty");
                reverse_bindings
                    .entry(parent.clone())
                    .or_default()
                    .entry(winner.child.clone())
                    .or_default()
                    .push(ReverseBinding {
                        discriminator: *discriminator,
                        priority: winner.priority,
                    });
            }
        }
        for children in reverse_bindings.values_mut() {
            for entries in children.values_mut() {
                entries.sort_by(|left, right| {
                    right
                        .priority
                        .cmp(&left.priority)
                        .then_with(|| left.discriminator.cmp(&right.discriminator))
                });
            }
        }
        for protocol in self.matchers.keys() {
            if !self.codecs.contains_key(protocol) {
                return Err(RegistryError::UnknownProtocol {
                    protocol: protocol.clone(),
                });
            }
        }
        // Capture each protocol's reflective schema once, from a default layer.
        // Filter compilation and protocol discovery both need field metadata
        // without constructing a throwaway layer per lookup. A decode-only
        // codec cannot build one and is simply absent from the map.
        let defaults = BTreeMap::<String, FieldValue>::new();
        let mut schemas = BTreeMap::new();
        for (protocol, codec) in &self.codecs {
            if let Ok(layer) = codec.make_layer(&defaults) {
                schemas.insert(protocol.clone(), layer.schema());
            }
        }
        for (path, binding) in &self.filter_fields {
            validate_filter_field(path, binding, &self.codecs, &schemas)?;
            reject_canonical_filter_path(path, &self.aliases, &schemas)?;
        }
        Ok(ProtocolRegistry {
            codecs: self.codecs,
            builtin_codecs: self.builtin_codecs,
            aliases: self.aliases,
            roots: self.roots,
            bindings: self.bindings,
            reverse_bindings,
            matchers: self.matchers,
            schemas,
            filter_fields: self.filter_fields,
        })
    }
}

/// Rejects a filter binding whose path is already a canonical
/// `<protocol-or-alias>.<field>` spelling.
///
/// Canonical paths resolve straight through the cached schemas, so a binding
/// that reuses one would give the same text two different meanings depending
/// on which lookup a caller reached for. Only the final `.` is split, so a
/// nested spelling such as `tcp.flags.syn` is compared as the prefix
/// `tcp.flags`, which is not an alias and therefore never collides.
fn reject_canonical_filter_path(
    path: &str,
    aliases: &HashMap<String, ProtocolId>,
    schemas: &BTreeMap<ProtocolId, &'static LayerSchema>,
) -> Result<(), RegistryError> {
    let Some((prefix, field)) = path.rsplit_once('.') else {
        return Ok(());
    };
    let Some(protocol) = aliases.get(prefix) else {
        return Ok(());
    };
    let Some(schema) = schemas.get(protocol) else {
        return Ok(());
    };
    if schema
        .fields
        .iter()
        .any(|declared| declared.name.eq_ignore_ascii_case(field))
    {
        return Err(RegistryError::DuplicateFilterField {
            path: path.to_owned(),
            existing: protocol.clone(),
        });
    }
    Ok(())
}

/// Rejects a filter binding that names an unregistered protocol, a field the
/// protocol does not expose, or a bit selection that cannot address anything.
///
/// Validating here means a mistyped built-in catalog entry fails when the
/// registry is built rather than silently never matching a packet.
fn validate_filter_field(
    path: &str,
    binding: &FilterFieldBinding,
    codecs: &BTreeMap<ProtocolId, Arc<dyn LayerCodec>>,
    schemas: &BTreeMap<ProtocolId, &'static LayerSchema>,
) -> Result<(), RegistryError> {
    let protocol = binding.protocol();
    if !codecs.contains_key(protocol) {
        return Err(RegistryError::UnknownProtocol {
            protocol: protocol.clone(),
        });
    }
    // A decode-only codec has no default layer and therefore no cached schema.
    // Its field names cannot be checked here; leave them to the compiler.
    let Some(schema) = schemas.get(protocol) else {
        return Ok(());
    };
    for field in binding.fields() {
        let Some(declared) = schema.fields.iter().find(|entry| entry.name == *field) else {
            return Err(RegistryError::UnknownFilterField {
                path: path.to_owned(),
                protocol: protocol.clone(),
                field: (*field).to_owned(),
            });
        };
        if matches!(binding, FilterFieldBinding::Bits { .. })
            && declared.kind != FieldKind::Unsigned
        {
            return Err(RegistryError::InvalidFilterField {
                path: path.to_owned(),
                reason: format!(
                    "field {field} on layer {protocol} is not unsigned, so it has no bits to select"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_filter_field_paths_are_rejected_case_insensitively() {
        let mut builder = RegistryBuilder::new();
        builder
            .bind_filter_field(
                "ip.src",
                FilterFieldBinding::Direct {
                    protocol: ProtocolId::new("ipv4"),
                    field: "source",
                },
            )
            .unwrap();
        assert!(matches!(
            builder.bind_filter_field(
                "IP.SRC",
                FilterFieldBinding::Direct {
                    protocol: ProtocolId::new("ipv6"),
                    field: "source",
                },
            ),
            Err(RegistryError::DuplicateFilterField { .. })
        ));
    }

    #[test]
    fn a_filter_field_binding_on_an_unregistered_protocol_fails_the_build() {
        let mut builder = RegistryBuilder::new();
        builder
            .bind_filter_field(
                "ip.src",
                FilterFieldBinding::Direct {
                    protocol: ProtocolId::new("ipv4"),
                    field: "source",
                },
            )
            .unwrap();
        assert!(matches!(
            builder.build(),
            Err(RegistryError::UnknownProtocol { .. })
        ));
    }

    #[test]
    fn a_bit_selection_that_addresses_nothing_is_rejected_at_the_call_site() {
        let mut builder = RegistryBuilder::new();
        let empty_mask = builder.bind_filter_field(
            "tcp.flags.syn",
            FilterFieldBinding::Bits {
                protocol: ProtocolId::new("tcp"),
                field: "flags",
                mask: 0,
                shift: 1,
            },
        );
        assert!(matches!(
            empty_mask,
            Err(RegistryError::InvalidFilterField { .. })
        ));

        let wide_shift = builder.bind_filter_field(
            "tcp.flags.fin",
            FilterFieldBinding::Bits {
                protocol: ProtocolId::new("tcp"),
                field: "flags",
                mask: 1,
                shift: u64::BITS,
            },
        );
        assert!(matches!(
            wide_shift,
            Err(RegistryError::InvalidFilterField { .. })
        ));

        // A shift past the mask's highest bit is in range but still extracts
        // nothing, so it must not build either.
        let shifted_past_mask = builder.bind_filter_field(
            "tcp.flags.rst",
            FilterFieldBinding::Bits {
                protocol: ProtocolId::new("tcp"),
                field: "flags",
                mask: 0x02,
                shift: 2,
            },
        );
        assert!(matches!(
            shifted_past_mask,
            Err(RegistryError::InvalidFilterField { .. })
        ));

        // The correct pairing for the same bit must still be accepted.
        builder
            .bind_filter_field(
                "tcp.flags.syn",
                FilterFieldBinding::Bits {
                    protocol: ProtocolId::new("tcp"),
                    field: "flags",
                    mask: 0x02,
                    shift: 1,
                },
            )
            .unwrap();
    }

    #[test]
    fn an_either_binding_without_fields_is_rejected() {
        let mut builder = RegistryBuilder::new();
        assert!(matches!(
            builder.bind_filter_field(
                "tcp.port",
                FilterFieldBinding::Either {
                    protocol: ProtocolId::new("tcp"),
                    fields: &[],
                },
            ),
            Err(RegistryError::InvalidFilterField { .. })
        ));
    }

    #[test]
    fn rebinding_a_child_is_idempotent_only_at_the_same_priority() {
        let mut builder = RegistryBuilder::new();
        builder.bind("parent", 1, "child", 10).unwrap();
        builder.bind("parent", 1, "child", 10).unwrap();
        assert!(matches!(
            builder.bind("parent", 1, "child", 20),
            Err(RegistryError::BindingConflict {
                discriminator: 1,
                priority: 20,
                ..
            })
        ));
    }
}
