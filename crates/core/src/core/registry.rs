// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use thiserror::Error;

use super::build::{BuildContext, BuildMode};
use super::diagnostic::Diagnostic;
use super::layer::{FieldError, Layer, ProtocolId};
use super::layout::FieldLayout;
use super::packet::Packet;
use super::value::FieldValue;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Discriminator(pub u64);

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodecError {
    #[error("codec expected layer {expected}, got {actual}")]
    WrongLayer {
        expected: ProtocolId,
        actual: ProtocolId,
    },
    #[error("truncated {protocol} layer: need at least {needed} bytes, got {available}")]
    Truncated {
        protocol: ProtocolId,
        needed: usize,
        available: usize,
    },
    #[error("invalid {protocol} layer: {message}")]
    Invalid {
        protocol: ProtocolId,
        message: String,
    },
    #[error("unsupported {protocol} construct: {message}")]
    Unsupported {
        protocol: ProtocolId,
        message: String,
    },
    #[error("packet length arithmetic overflow while processing {protocol}")]
    LengthOverflow { protocol: ProtocolId },
    #[error(transparent)]
    Field(#[from] FieldError),
}

pub struct LayerEncodeContext<'a> {
    pub packet: &'a Packet,
    pub index: usize,
    pub build_context: &'a BuildContext,
    pub mode: BuildMode,
    pub registry: &'a ProtocolRegistry,
    pub child: Option<&'a dyn Layer>,
    /// Maximum additional bytes this layer may contribute without exceeding
    /// the operation's configured packet-size limit. External codecs should
    /// check this before allocating output buffers.
    pub remaining_packet_bytes: usize,
}

pub struct EncodedLayer {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub materialized: Box<dyn Layer>,
    pub fields: Vec<FieldLayout>,
    pub diagnostics: Vec<Diagnostic>,
}

impl EncodedLayer {
    pub fn header(prefix: Vec<u8>, materialized: Box<dyn Layer>) -> Self {
        Self {
            prefix,
            suffix: Vec::new(),
            materialized,
            fields: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

pub struct LayerDecodeContext<'a> {
    pub registry: &'a ProtocolRegistry,
    pub layer_index: usize,
    pub absolute_offset: usize,
    pub verify_checksums: bool,
    /// Whether bytes outside an IP-declared length may be link-layer padding.
    pub allow_trailing_padding: bool,
    /// Network pseudo-header context established by an enclosing IP codec.
    pub network: Option<NetworkEnvelope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEnvelope {
    pub source: IpAddr,
    pub destination: IpAddr,
}

pub struct DecodedLayerValue {
    pub layer: Box<dyn Layer>,
    pub consumed: usize,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub next: Vec<Discriminator>,
    pub fields: Vec<FieldLayout>,
    pub diagnostics: Vec<Diagnostic>,
    pub stop: bool,
    /// New pseudo-header context to carry into child decoders.
    pub network: Option<NetworkEnvelope>,
}

impl DecodedLayerValue {
    pub fn terminal(layer: Box<dyn Layer>, consumed: usize) -> Self {
        Self {
            layer,
            consumed,
            payload_offset: consumed,
            payload_len: 0,
            next: Vec::new(),
            fields: Vec::new(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        }
    }
}

/// Encoder, bounded decoder, and expression factory for one protocol.
pub trait LayerCodec: Send + Sync + fmt::Debug {
    fn protocol_id(&self) -> ProtocolId;

    /// Whether a decoded layer protocol is a valid result for this codec.
    /// Most codecs return their own protocol. A decode-only multiplexing root
    /// may explicitly admit the concrete protocols it selects.
    fn accepts_decoded_protocol(&self, protocol: &ProtocolId) -> bool {
        *protocol == self.protocol_id()
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError>;

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError>;

    /// Constructs one layer from caller-supplied reflective fields.
    ///
    /// Implementations may fill omitted fields with defaults. The returned
    /// layer must satisfy [`Layer::validate_required_fields`]; the public
    /// expression/document paths and the builder enforce that invariant.
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchResult {
    pub matched: bool,
    pub confidence: u8,
    pub reason: Option<String>,
}

impl MatchResult {
    pub fn no_match() -> Self {
        Self {
            matched: false,
            confidence: 0,
            reason: None,
        }
    }

    pub fn matched(confidence: u8, reason: impl Into<String>) -> Self {
        Self {
            matched: true,
            confidence,
            reason: Some(reason.into()),
        }
    }
}

pub trait ResponseMatcher: Send + Sync + fmt::Debug {
    fn matches(&self, request: &Packet, response: &Packet) -> MatchResult;
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
}

#[derive(Clone, Debug)]
struct Binding {
    child: ProtocolId,
    priority: i32,
}

#[derive(Clone, Default)]
pub struct ProtocolRegistry {
    codecs: BTreeMap<ProtocolId, Arc<dyn LayerCodec>>,
    aliases: HashMap<String, ProtocolId>,
    roots: HashMap<u32, ProtocolId>,
    bindings: HashMap<(ProtocolId, Discriminator), Vec<Binding>>,
    reverse_bindings: HashMap<(ProtocolId, ProtocolId), Vec<(Discriminator, i32)>>,
    matchers: BTreeMap<ProtocolId, Arc<dyn ResponseMatcher>>,
}

impl fmt::Debug for ProtocolRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolRegistry")
            .field("protocols", &self.codecs.keys().collect::<Vec<_>>())
            .field("link_types", &self.roots)
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

impl ProtocolRegistry {
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::new()
    }

    pub fn codec(&self, protocol: &ProtocolId) -> Option<&Arc<dyn LayerCodec>> {
        self.codecs.get(protocol)
    }

    pub fn codec_named(&self, name: &str) -> Option<&Arc<dyn LayerCodec>> {
        let normalized = name.trim().to_ascii_lowercase();
        let protocol = self.aliases.get(&normalized)?;
        self.codecs.get(protocol)
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

    pub fn child_for(
        &self,
        parent: &ProtocolId,
        discriminator: Discriminator,
    ) -> Option<&ProtocolId> {
        self.bindings
            .get(&(parent.clone(), discriminator))
            .and_then(|bindings| bindings.first())
            .map(|binding| &binding.child)
    }

    pub fn discriminator_for(
        &self,
        parent: &ProtocolId,
        child: &ProtocolId,
    ) -> Option<Discriminator> {
        self.reverse_bindings
            .get(&(parent.clone(), child.clone()))
            .and_then(|bindings| bindings.first())
            .map(|binding| binding.0)
    }

    pub fn matcher(&self, protocol: &ProtocolId) -> Option<&Arc<dyn ResponseMatcher>> {
        self.matchers.get(protocol)
    }

    /// Protocols with registered request/response matchers.
    pub fn matcher_protocols(&self) -> impl ExactSizeIterator<Item = &ProtocolId> {
        self.matchers.keys()
    }

    pub fn protocols(&self) -> impl ExactSizeIterator<Item = &ProtocolId> {
        self.codecs.keys()
    }
}

#[derive(Default)]
pub struct RegistryBuilder {
    codecs: BTreeMap<ProtocolId, Arc<dyn LayerCodec>>,
    aliases: HashMap<String, ProtocolId>,
    roots: HashMap<u32, ProtocolId>,
    bindings: HashMap<(ProtocolId, Discriminator), Vec<Binding>>,
    matchers: BTreeMap<ProtocolId, Arc<dyn ResponseMatcher>>,
}

impl RegistryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_codec<C>(&mut self, codec: C) -> Result<&mut Self, RegistryError>
    where
        C: LayerCodec + 'static,
    {
        self.register_codec_arc(Arc::new(codec))
    }

    pub fn register_codec_arc(
        &mut self,
        codec: Arc<dyn LayerCodec>,
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
            .entry((parent.clone(), Discriminator(discriminator)))
            .or_default();
        if entries
            .iter()
            .any(|entry| entry.priority == priority && entry.child != child)
        {
            return Err(RegistryError::BindingConflict {
                parent,
                discriminator,
                priority,
            });
        }
        if !entries.iter().any(|entry| entry.child == child) {
            entries.push(Binding { child, priority });
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
        let mut reverse_bindings: HashMap<(ProtocolId, ProtocolId), Vec<(Discriminator, i32)>> =
            HashMap::new();
        for ((parent, discriminator), entries) in &mut self.bindings {
            if !self.codecs.contains_key(parent) {
                return Err(RegistryError::UnknownProtocol {
                    protocol: parent.clone(),
                });
            }
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
                reverse_bindings
                    .entry((parent.clone(), entry.child.clone()))
                    .or_default()
                    .push((*discriminator, entry.priority));
            }
        }
        for entries in reverse_bindings.values_mut() {
            entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        }
        for protocol in self.matchers.keys() {
            if !self.codecs.contains_key(protocol) {
                return Err(RegistryError::UnknownProtocol {
                    protocol: protocol.clone(),
                });
            }
        }
        Ok(ProtocolRegistry {
            codecs: self.codecs,
            aliases: self.aliases,
            roots: self.roots,
            bindings: self.bindings,
            reverse_bindings,
            matchers: self.matchers,
        })
    }
}
