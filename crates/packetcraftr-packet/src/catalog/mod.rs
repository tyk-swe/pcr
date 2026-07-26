// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Immutable provenance-aware protocol catalogs.

mod operation;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use packetcraftr_model::{CatalogHash, ProtocolId, ProviderId, RegistrationOrigin};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::codec::Discriminator;
use crate::layer::{LayerSchema, SchemaError};
use crate::provider::{ProtocolProvider, ProviderError, ProviderProtocolKey};
use crate::semantics::BuiltinProtocol;

pub use operation::{ProtocolCatalogOperation, ProtocolOperationError};

pub const MAX_CATALOG_PROVIDERS: usize = 256;
pub const MAX_CATALOG_PROTOCOLS: usize = 4_096;
pub const MAX_CATALOG_ALIASES: usize = 65_536;
pub const MAX_CATALOG_CAPTURE_ROOTS: usize = 4_096;
pub const MAX_CATALOG_BINDINGS: usize = 65_536;
pub const MAX_PARENT_DECODE_BINDINGS: usize = 4_096;
pub const MAX_CATALOG_FALLBACKS: usize = 4_096;
pub const MAX_ACCEPTED_DECODE_PROTOCOLS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingDirection {
    DecodeOnly,
    Canonical,
}

#[derive(Clone, Debug)]
pub struct ProtocolRegistration {
    pub protocol: ProtocolId,
    pub schema: Arc<LayerSchema>,
    pub provider: ProviderId,
    pub provider_key: ProviderProtocolKey,
    pub accepted_decoded_protocols: Arc<[ProtocolId]>,
    pub matcher: bool,
    pub origin: RegistrationOrigin,
}

impl ProtocolRegistration {
    pub fn new(
        schema: Arc<LayerSchema>,
        provider: ProviderId,
        provider_key: ProviderProtocolKey,
        origin: RegistrationOrigin,
    ) -> Self {
        Self {
            protocol: schema.protocol.clone(),
            schema,
            provider,
            provider_key,
            accepted_decoded_protocols: Arc::from([]),
            matcher: false,
            origin,
        }
    }

    #[must_use]
    pub fn accepts_decoded(mut self, protocols: impl IntoIterator<Item = ProtocolId>) -> Self {
        let mut protocols = protocols.into_iter().collect::<Vec<_>>();
        protocols.sort();
        protocols.dedup();
        self.accepted_decoded_protocols = protocols.into();
        self
    }

    #[must_use]
    pub const fn with_matcher(mut self, matcher: bool) -> Self {
        self.matcher = matcher;
        self
    }

    pub fn accepts_decoded_protocol(&self, protocol: &ProtocolId) -> bool {
        crate::invariant::decoded_protocol_is_accepted(
            &self.protocol,
            &self.accepted_decoded_protocols,
            protocol,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaptureRootRegistration {
    pub link_type: u32,
    pub protocol: ProtocolId,
    pub origin: RegistrationOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolBindingRegistration {
    pub parent: ProtocolId,
    pub discriminator: Discriminator,
    pub child: ProtocolId,
    pub direction: BindingDirection,
    pub origin: RegistrationOrigin,
}

impl ProtocolBindingRegistration {
    pub fn canonical(
        parent: ProtocolId,
        discriminator: u64,
        child: ProtocolId,
        origin: RegistrationOrigin,
    ) -> Self {
        Self {
            parent,
            discriminator: Discriminator(discriminator),
            child,
            direction: BindingDirection::Canonical,
            origin,
        }
    }

    pub fn decode_only(
        parent: ProtocolId,
        discriminator: u64,
        child: ProtocolId,
        origin: RegistrationOrigin,
    ) -> Self {
        Self {
            parent,
            discriminator: Discriminator(discriminator),
            child,
            direction: BindingDirection::DecodeOnly,
            origin,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FallbackBindingRegistration {
    pub parent: ProtocolId,
    pub child: ProtocolId,
    pub origin: RegistrationOrigin,
}

#[derive(Default)]
pub struct ProtocolRegistrationSet {
    providers: Vec<Arc<dyn ProtocolProvider>>,
    protocols: Vec<ProtocolRegistration>,
    roots: Vec<CaptureRootRegistration>,
    bindings: Vec<ProtocolBindingRegistration>,
    fallbacks: Vec<FallbackBindingRegistration>,
}

impl fmt::Debug for ProtocolRegistrationSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolRegistrationSet")
            .field(
                "providers",
                &self
                    .providers
                    .iter()
                    .map(|provider| provider.provider_id())
                    .collect::<Vec<_>>(),
            )
            .field("protocols", &self.protocols)
            .field("roots", &self.roots)
            .field("bindings", &self.bindings)
            .field("fallbacks", &self.fallbacks)
            .finish()
    }
}

impl ProtocolRegistrationSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_provider(&mut self, provider: Arc<dyn ProtocolProvider>) -> &mut Self {
        self.providers.push(provider);
        self
    }

    pub fn register_protocol(&mut self, registration: ProtocolRegistration) -> &mut Self {
        self.protocols.push(registration);
        self
    }

    pub fn capture_root(
        &mut self,
        link_type: u32,
        protocol: ProtocolId,
        origin: RegistrationOrigin,
    ) -> &mut Self {
        self.roots.push(CaptureRootRegistration {
            link_type,
            protocol,
            origin,
        });
        self
    }

    pub fn binding(&mut self, registration: ProtocolBindingRegistration) -> &mut Self {
        self.bindings.push(registration);
        self
    }

    pub fn fallback(
        &mut self,
        parent: ProtocolId,
        child: ProtocolId,
        origin: RegistrationOrigin,
    ) -> &mut Self {
        self.fallbacks.push(FallbackBindingRegistration {
            parent,
            child,
            origin,
        });
        self
    }

    pub fn extend(&mut self, mut other: Self) -> &mut Self {
        self.providers.append(&mut other.providers);
        self.protocols.append(&mut other.protocols);
        self.roots.append(&mut other.roots);
        self.bindings.append(&mut other.bindings);
        self.fallbacks.append(&mut other.fallbacks);
        self
    }
}

/// Trusted compile-time Rust registration module.
pub trait NativeProtocolModule {
    fn registrations(&self) -> Result<ProtocolRegistrationSet, CatalogError>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SelectionKey {
    Protocol(ProtocolId),
    Alias(String),
    CaptureRoot(u32),
    DecodeBinding(ProtocolId, Discriminator),
    Fallback(ProtocolId),
}

/// Exact-origin selections made by the host for otherwise conflicting input.
#[derive(Clone, Debug, Default)]
pub struct ProtocolCatalogPolicy {
    selections: BTreeMap<SelectionKey, RegistrationOrigin>,
}

impl ProtocolCatalogPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn select_protocol(
        &mut self,
        protocol: ProtocolId,
        origin: RegistrationOrigin,
    ) -> &mut Self {
        self.selections
            .insert(SelectionKey::Protocol(protocol), origin);
        self
    }

    pub fn select_alias(
        &mut self,
        alias: impl AsRef<str>,
        origin: RegistrationOrigin,
    ) -> Result<&mut Self, CatalogError> {
        let alias = normalize_alias(alias.as_ref())?;
        self.selections.insert(SelectionKey::Alias(alias), origin);
        Ok(self)
    }

    pub fn select_capture_root(&mut self, link_type: u32, origin: RegistrationOrigin) -> &mut Self {
        self.selections
            .insert(SelectionKey::CaptureRoot(link_type), origin);
        self
    }

    pub fn select_decode_binding(
        &mut self,
        parent: ProtocolId,
        discriminator: u64,
        origin: RegistrationOrigin,
    ) -> &mut Self {
        self.selections.insert(
            SelectionKey::DecodeBinding(parent, Discriminator(discriminator)),
            origin,
        );
        self
    }

    pub fn select_fallback(&mut self, parent: ProtocolId, origin: RegistrationOrigin) -> &mut Self {
        self.selections
            .insert(SelectionKey::Fallback(parent), origin);
        self
    }

    fn selection(&self, key: &SelectionKey) -> Option<&RegistrationOrigin> {
        self.selections.get(key)
    }
}

pub struct ProtocolCatalogBuilder {
    registration_sets: Vec<ProtocolRegistrationSet>,
    policy: ProtocolCatalogPolicy,
    generation: u64,
}

impl Default for ProtocolCatalogBuilder {
    fn default() -> Self {
        Self {
            registration_sets: Vec::new(),
            policy: ProtocolCatalogPolicy::default(),
            generation: 1,
        }
    }
}

impl ProtocolCatalogBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn registration_set(&mut self, set: ProtocolRegistrationSet) -> &mut Self {
        self.registration_sets.push(set);
        self
    }

    pub fn native_module<M>(&mut self, module: &M) -> Result<&mut Self, CatalogError>
    where
        M: NativeProtocolModule,
    {
        self.registration_sets.push(module.registrations()?);
        Ok(self)
    }

    pub fn policy(&mut self, policy: ProtocolCatalogPolicy) -> &mut Self {
        self.policy = policy;
        self
    }

    pub fn generation(&mut self, generation: u64) -> &mut Self {
        self.generation = generation;
        self
    }

    pub fn build(self) -> Result<ProtocolCatalogSnapshot, CatalogError> {
        let mut providers = BTreeMap::<ProviderId, Arc<dyn ProtocolProvider>>::new();
        let mut registrations = Vec::new();
        let mut roots = Vec::new();
        let mut bindings = Vec::new();
        let mut fallbacks = Vec::new();
        for set in self.registration_sets {
            for provider in set.providers {
                let id = provider.provider_id().clone();
                if let RegistrationOrigin::Native {
                    provider: origin_provider,
                } = provider.origin()
                    && origin_provider != &id
                {
                    return Err(CatalogError::ProviderIdentityMismatch {
                        provider: id,
                        origin_provider: origin_provider.clone(),
                    });
                }
                if providers.insert(id.clone(), provider).is_some() {
                    return Err(CatalogError::DuplicateProvider { provider: id });
                }
            }
            registrations.extend(set.protocols);
            roots.extend(set.roots);
            bindings.extend(set.bindings);
            fallbacks.extend(set.fallbacks);
        }
        enforce_limit("providers", providers.len(), MAX_CATALOG_PROVIDERS)?;
        enforce_limit(
            "protocol registrations",
            registrations.len(),
            MAX_CATALOG_PROTOCOLS,
        )?;
        enforce_limit("capture roots", roots.len(), MAX_CATALOG_CAPTURE_ROOTS)?;
        enforce_limit("decode bindings", bindings.len(), MAX_CATALOG_BINDINGS)?;
        enforce_limit("fallback bindings", fallbacks.len(), MAX_CATALOG_FALLBACKS)?;

        registrations.sort_by(protocol_registration_order);
        let mut grouped_protocols = BTreeMap::<ProtocolId, Vec<ProtocolRegistration>>::new();
        for mut registration in registrations {
            if registration.protocol != registration.schema.protocol {
                return Err(CatalogError::SchemaProtocolMismatch {
                    registration: registration.protocol,
                    schema: registration.schema.protocol.clone(),
                });
            }
            let mut accepted = registration.accepted_decoded_protocols.to_vec();
            accepted.sort();
            accepted.dedup();
            registration.accepted_decoded_protocols = accepted.into();
            enforce_limit(
                "accepted decoded protocols",
                registration.accepted_decoded_protocols.len(),
                MAX_ACCEPTED_DECODE_PROTOCOLS,
            )?;
            if registration.protocol.is_packetcraftr_namespace()
                && registration.origin != RegistrationOrigin::Builtin
            {
                return Err(CatalogError::ReservedProtocol {
                    protocol: registration.protocol,
                    origin: registration.origin,
                });
            }
            let Some(provider) = providers.get(&registration.provider) else {
                return Err(CatalogError::UnknownProvider {
                    provider: registration.provider,
                    protocol: registration.protocol,
                });
            };
            if provider.origin() != &registration.origin {
                return Err(CatalogError::ProviderOriginMismatch {
                    provider: registration.provider,
                    protocol: registration.protocol,
                });
            }
            grouped_protocols
                .entry(registration.protocol.clone())
                .or_default()
                .push(registration);
        }

        let mut selected_protocols = BTreeMap::new();
        for (protocol, candidates) in grouped_protocols {
            let selected = select_protocol_candidate(&self.policy, &protocol, candidates)?;
            selected_protocols.insert(protocol, selected);
        }
        for registration in selected_protocols.values() {
            for accepted in registration.accepted_decoded_protocols.iter() {
                require_protocol(&selected_protocols, "accepted decoded protocol", accepted)?;
            }
        }
        let selected_provider_ids = selected_protocols
            .values()
            .map(|registration| registration.provider.clone())
            .collect::<BTreeSet<_>>();
        providers.retain(|provider, _| selected_provider_ids.contains(provider));

        let builtin_ids = selected_protocols
            .values()
            .filter(|registration| registration.origin == RegistrationOrigin::Builtin)
            .map(|registration| registration.protocol.clone())
            .collect::<BTreeSet<_>>();

        let aliases = select_aliases(&self.policy, &selected_protocols, &builtin_ids)?;
        enforce_limit("catalog aliases", aliases.len(), MAX_CATALOG_ALIASES)?;
        let roots = select_roots(&self.policy, roots, &selected_protocols)?;
        let (decode_bindings, reverse_bindings, binding_registrations) =
            select_bindings(&self.policy, bindings, &selected_protocols)?;
        let fallbacks = select_fallbacks(&self.policy, fallbacks, &selected_protocols)?;

        let catalog_hash = hash_catalog(
            &selected_protocols,
            &aliases,
            &roots,
            &binding_registrations,
            &fallbacks,
        );
        Ok(ProtocolCatalogSnapshot {
            generation: self.generation,
            catalog_hash,
            protocols: selected_protocols,
            providers,
            aliases,
            roots,
            decode_bindings,
            reverse_bindings,
            binding_registrations,
            fallbacks,
        })
    }
}

pub struct ProtocolCatalogSnapshot {
    generation: u64,
    catalog_hash: CatalogHash,
    protocols: BTreeMap<ProtocolId, ProtocolRegistration>,
    providers: BTreeMap<ProviderId, Arc<dyn ProtocolProvider>>,
    aliases: BTreeMap<String, ProtocolId>,
    roots: BTreeMap<u32, CaptureRootRegistration>,
    decode_bindings: BTreeMap<ProtocolId, BTreeMap<Discriminator, ProtocolId>>,
    reverse_bindings: BTreeMap<(ProtocolId, ProtocolId), Discriminator>,
    binding_registrations: BTreeMap<(ProtocolId, Discriminator), ProtocolBindingRegistration>,
    fallbacks: BTreeMap<ProtocolId, FallbackBindingRegistration>,
}

impl fmt::Debug for ProtocolCatalogSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolCatalogSnapshot")
            .field("generation", &self.generation)
            .field("catalog_hash", &self.catalog_hash)
            .field("protocols", &self.protocols.keys().collect::<Vec<_>>())
            .field("providers", &self.providers.keys().collect::<Vec<_>>())
            .field("roots", &self.roots)
            .field(
                "binding_count",
                &self
                    .decode_bindings
                    .values()
                    .map(BTreeMap::len)
                    .sum::<usize>(),
            )
            .finish()
    }
}

impl ProtocolCatalogSnapshot {
    pub fn builder() -> ProtocolCatalogBuilder {
        ProtocolCatalogBuilder::new()
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn catalog_hash(&self) -> CatalogHash {
        self.catalog_hash
    }

    pub fn descriptor(&self, protocol: &ProtocolId) -> Option<&ProtocolRegistration> {
        self.protocols.get(protocol)
    }

    pub fn descriptor_named(&self, name: &str) -> Option<&ProtocolRegistration> {
        let protocol = self.protocol_named(name)?;
        self.protocols.get(protocol)
    }

    pub fn schema(&self, protocol: &ProtocolId) -> Option<&Arc<LayerSchema>> {
        self.protocols
            .get(protocol)
            .map(|registration| &registration.schema)
    }

    pub fn protocol_named(&self, name: &str) -> Option<&ProtocolId> {
        let normalized = normalize_alias(name).ok()?;
        self.aliases.get(&normalized)
    }

    pub fn root_for_link_type(&self, link_type: u32) -> Option<&ProtocolId> {
        self.capture_root_registration(link_type)
            .map(|registration| &registration.protocol)
    }

    pub fn capture_root_registration(&self, link_type: u32) -> Option<&CaptureRootRegistration> {
        self.roots.get(&link_type)
    }

    pub fn link_type_roots(&self) -> impl ExactSizeIterator<Item = (u32, &ProtocolId)> {
        self.roots
            .iter()
            .map(|(link_type, registration)| (*link_type, &registration.protocol))
    }

    pub fn child_for(
        &self,
        parent: &ProtocolId,
        discriminator: Discriminator,
    ) -> Option<&ProtocolId> {
        self.decode_bindings.get(parent)?.get(&discriminator)
    }

    pub fn binding_registration(
        &self,
        parent: &ProtocolId,
        discriminator: Discriminator,
    ) -> Option<&ProtocolBindingRegistration> {
        self.binding_registrations
            .get(&(parent.clone(), discriminator))
    }

    pub fn fallback_child_for(&self, parent: &ProtocolId) -> Option<&ProtocolId> {
        self.fallback_registration(parent)
            .map(|registration| &registration.child)
    }

    pub fn fallback_registration(
        &self,
        parent: &ProtocolId,
    ) -> Option<&FallbackBindingRegistration> {
        self.fallbacks.get(parent)
    }

    pub fn discriminator_for(
        &self,
        parent: &ProtocolId,
        child: &ProtocolId,
    ) -> Option<Discriminator> {
        self.reverse_bindings
            .get(&(parent.clone(), child.clone()))
            .copied()
    }

    pub fn protocols(&self) -> impl ExactSizeIterator<Item = (&ProtocolId, &ProtocolRegistration)> {
        self.protocols.iter()
    }

    pub fn matcher_protocols(&self) -> impl Iterator<Item = &ProtocolId> {
        self.protocols
            .values()
            .filter(|registration| registration.matcher)
            .map(|registration| &registration.protocol)
    }

    pub fn is_builtin_protocol(&self, protocol: &ProtocolId) -> bool {
        self.protocols
            .get(protocol)
            .is_some_and(|registration| registration.origin == RegistrationOrigin::Builtin)
    }

    pub fn operation(self: &Arc<Self>) -> ProtocolCatalogOperation {
        ProtocolCatalogOperation::new(Arc::clone(self))
    }

    pub(crate) fn provider(&self, provider: &ProviderId) -> Option<&Arc<dyn ProtocolProvider>> {
        self.providers.get(provider)
    }

    pub(crate) fn parent_bindings(
        &self,
        parent: &ProtocolId,
    ) -> Option<&BTreeMap<Discriminator, ProtocolId>> {
        self.decode_bindings.get(parent)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CatalogError {
    #[error(transparent)]
    Schema(#[from] SchemaError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("provider {provider} is registered more than once")]
    DuplicateProvider { provider: ProviderId },
    #[error(
        "native provider {provider} declares a different provider identity {origin_provider} in its origin"
    )]
    ProviderIdentityMismatch {
        provider: ProviderId,
        origin_provider: ProviderId,
    },
    #[error("protocol {registration} schema identifies {schema}")]
    SchemaProtocolMismatch {
        registration: ProtocolId,
        schema: ProtocolId,
    },
    #[error("protocol {protocol} references unknown provider {provider}")]
    UnknownProvider {
        provider: ProviderId,
        protocol: ProtocolId,
    },
    #[error("provider {provider} origin differs from protocol {protocol} origin")]
    ProviderOriginMismatch {
        provider: ProviderId,
        protocol: ProtocolId,
    },
    #[error("origin {origin:?} cannot register reserved protocol {protocol}")]
    ReservedProtocol {
        protocol: ProtocolId,
        origin: RegistrationOrigin,
    },
    #[error("built-in protocol identity {protocol} requires an exact host origin selection")]
    ProtectedProtocol { protocol: ProtocolId },
    #[error(
        "protocol {protocol} has conflicting registrations; explicit origin selection is required"
    )]
    ProtocolConflict { protocol: ProtocolId },
    #[error(
        "selection for {resource} names {origin:?}, but it does not select exactly one candidate"
    )]
    InvalidSelection {
        resource: String,
        origin: RegistrationOrigin,
    },
    #[error("alias {alias} is claimed by both {first} and {second}")]
    AliasConflict {
        alias: String,
        first: ProtocolId,
        second: ProtocolId,
    },
    #[error("capture root {link_type} has conflicting protocol registrations")]
    CaptureRootConflict { link_type: u32 },
    #[error("binding ({parent}, {discriminator}) has conflicting children")]
    DecodeBindingConflict {
        parent: ProtocolId,
        discriminator: u64,
    },
    #[error("canonical reverse binding ({parent}, {child}) has more than one discriminator")]
    CanonicalBindingConflict {
        parent: ProtocolId,
        child: ProtocolId,
    },
    #[error("fallback binding for {parent} has conflicting children")]
    FallbackConflict { parent: ProtocolId },
    #[error("{resource} references unregistered protocol {protocol}")]
    UnknownProtocol {
        resource: &'static str,
        protocol: ProtocolId,
    },
    #[error("catalog alias {alias:?} is invalid")]
    InvalidAlias { alias: String },
    #[error("catalog {resource} count {actual} exceeds limit {limit}")]
    ResourceLimit {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
}

fn protocol_registration_order(
    left: &ProtocolRegistration,
    right: &ProtocolRegistration,
) -> std::cmp::Ordering {
    left.protocol
        .cmp(&right.protocol)
        .then_with(|| left.origin.cmp(&right.origin))
        .then_with(|| left.provider.cmp(&right.provider))
        .then_with(|| left.provider_key.cmp(&right.provider_key))
        .then_with(|| left.schema.schema_hash.cmp(&right.schema.schema_hash))
}

fn select_protocol_candidate(
    policy: &ProtocolCatalogPolicy,
    protocol: &ProtocolId,
    mut candidates: Vec<ProtocolRegistration>,
) -> Result<ProtocolRegistration, CatalogError> {
    if candidates.len() == 1 {
        let candidate = candidates.pop().expect("one candidate");
        if BuiltinProtocol::from_id(protocol).is_some()
            && candidate.origin != RegistrationOrigin::Builtin
        {
            let key = SelectionKey::Protocol(protocol.clone());
            if policy.selection(&key) != Some(&candidate.origin) {
                return Err(CatalogError::ProtectedProtocol {
                    protocol: protocol.clone(),
                });
            }
        }
        return Ok(candidate);
    }
    let key = SelectionKey::Protocol(protocol.clone());
    if let Some(origin) = policy.selection(&key) {
        return select_exact_origin(
            candidates,
            origin,
            format!("protocol {protocol}"),
            |candidate| &candidate.origin,
        );
    }
    select_single_builtin(candidates, |candidate| &candidate.origin).ok_or_else(|| {
        CatalogError::ProtocolConflict {
            protocol: protocol.clone(),
        }
    })
}

fn select_aliases(
    policy: &ProtocolCatalogPolicy,
    protocols: &BTreeMap<ProtocolId, ProtocolRegistration>,
    builtin_ids: &BTreeSet<ProtocolId>,
) -> Result<BTreeMap<String, ProtocolId>, CatalogError> {
    let mut candidates = BTreeMap::<String, Vec<(&ProtocolId, &RegistrationOrigin)>>::new();
    for registration in protocols.values() {
        candidates
            .entry(normalize_alias(registration.protocol.as_str())?)
            .or_default()
            .push((&registration.protocol, &registration.origin));
        for alias in registration.schema.aliases.iter() {
            candidates
                .entry(alias.to_string())
                .or_default()
                .push((&registration.protocol, &registration.origin));
        }
    }
    let mut aliases = BTreeMap::new();
    for (alias, mut claims) in candidates {
        claims.sort();
        claims.dedup();
        let selected = if claims.len() == 1 {
            claims[0]
        } else {
            let key = SelectionKey::Alias(alias.clone());
            if let Some(origin) = policy.selection(&key) {
                let selected = claims
                    .iter()
                    .filter(|(_, candidate_origin)| *candidate_origin == origin)
                    .copied()
                    .collect::<Vec<_>>();
                if selected.len() != 1 {
                    return Err(CatalogError::InvalidSelection {
                        resource: format!("alias {alias}"),
                        origin: origin.clone(),
                    });
                }
                selected[0]
            } else if let [selected] = claims
                .iter()
                .filter(|(_, origin)| **origin == RegistrationOrigin::Builtin)
                .copied()
                .collect::<Vec<_>>()
                .as_slice()
            {
                *selected
            } else {
                return Err(CatalogError::AliasConflict {
                    alias,
                    first: claims[0].0.clone(),
                    second: claims[1].0.clone(),
                });
            }
        };
        if builtin_ids.contains(selected.0) && selected.1 != &RegistrationOrigin::Builtin {
            return Err(CatalogError::AliasConflict {
                alias,
                first: selected.0.clone(),
                second: selected.0.clone(),
            });
        }
        aliases.insert(alias, selected.0.clone());
    }
    Ok(aliases)
}

fn select_roots(
    policy: &ProtocolCatalogPolicy,
    mut roots: Vec<CaptureRootRegistration>,
    protocols: &BTreeMap<ProtocolId, ProtocolRegistration>,
) -> Result<BTreeMap<u32, CaptureRootRegistration>, CatalogError> {
    roots.sort();
    let mut grouped = BTreeMap::<u32, Vec<CaptureRootRegistration>>::new();
    for root in roots {
        require_protocol(protocols, "capture root", &root.protocol)?;
        grouped.entry(root.link_type).or_default().push(root);
    }
    let mut selected = BTreeMap::new();
    for (link_type, candidates) in grouped {
        let root = if candidates.len() == 1 {
            candidates.into_iter().next().expect("one root")
        } else if let Some(origin) = policy.selection(&SelectionKey::CaptureRoot(link_type)) {
            select_exact_origin(
                candidates,
                origin,
                format!("capture root {link_type}"),
                |candidate| &candidate.origin,
            )?
        } else if let Some(root) = select_single_builtin(candidates, |candidate| &candidate.origin)
        {
            root
        } else {
            return Err(CatalogError::CaptureRootConflict { link_type });
        };
        selected.insert(link_type, root);
    }
    Ok(selected)
}

type DecodeBindings = BTreeMap<ProtocolId, BTreeMap<Discriminator, ProtocolId>>;
type ReverseBindings = BTreeMap<(ProtocolId, ProtocolId), Discriminator>;
type BindingRegistrations = BTreeMap<(ProtocolId, Discriminator), ProtocolBindingRegistration>;

fn select_bindings(
    policy: &ProtocolCatalogPolicy,
    mut bindings: Vec<ProtocolBindingRegistration>,
    protocols: &BTreeMap<ProtocolId, ProtocolRegistration>,
) -> Result<(DecodeBindings, ReverseBindings, BindingRegistrations), CatalogError> {
    bindings.sort();
    let mut grouped =
        BTreeMap::<(ProtocolId, Discriminator), Vec<ProtocolBindingRegistration>>::new();
    for binding in bindings {
        require_protocol(protocols, "protocol binding parent", &binding.parent)?;
        require_protocol(protocols, "protocol binding child", &binding.child)?;
        grouped
            .entry((binding.parent.clone(), binding.discriminator))
            .or_default()
            .push(binding);
    }
    let mut selected = Vec::new();
    for ((parent, discriminator), candidates) in grouped {
        let binding = if candidates.len() == 1 {
            candidates.into_iter().next().expect("one binding")
        } else if let Some(origin) =
            policy.selection(&SelectionKey::DecodeBinding(parent.clone(), discriminator))
        {
            select_exact_origin(
                candidates,
                origin,
                format!("binding ({parent}, {})", discriminator.0),
                |candidate| &candidate.origin,
            )?
        } else if let Some(binding) =
            select_single_builtin(candidates, |candidate| &candidate.origin)
        {
            binding
        } else {
            return Err(CatalogError::DecodeBindingConflict {
                parent,
                discriminator: discriminator.0,
            });
        };
        selected.push(binding);
    }
    selected.sort();

    let mut decode = BTreeMap::<ProtocolId, BTreeMap<Discriminator, ProtocolId>>::new();
    let mut reverse = BTreeMap::new();
    let mut registrations = BTreeMap::new();
    for binding in selected {
        let parent_bindings = decode.entry(binding.parent.clone()).or_default();
        if parent_bindings.len() >= MAX_PARENT_DECODE_BINDINGS {
            return Err(CatalogError::ResourceLimit {
                resource: "decode bindings for one parent",
                actual: parent_bindings.len() + 1,
                limit: MAX_PARENT_DECODE_BINDINGS,
            });
        }
        parent_bindings.insert(binding.discriminator, binding.child.clone());
        registrations.insert(
            (binding.parent.clone(), binding.discriminator),
            binding.clone(),
        );
        if binding.direction == BindingDirection::Canonical
            && reverse
                .insert(
                    (binding.parent.clone(), binding.child.clone()),
                    binding.discriminator,
                )
                .is_some()
        {
            return Err(CatalogError::CanonicalBindingConflict {
                parent: binding.parent,
                child: binding.child,
            });
        }
    }
    Ok((decode, reverse, registrations))
}

fn select_fallbacks(
    policy: &ProtocolCatalogPolicy,
    mut fallbacks: Vec<FallbackBindingRegistration>,
    protocols: &BTreeMap<ProtocolId, ProtocolRegistration>,
) -> Result<BTreeMap<ProtocolId, FallbackBindingRegistration>, CatalogError> {
    fallbacks.sort();
    let mut grouped = BTreeMap::<ProtocolId, Vec<FallbackBindingRegistration>>::new();
    for fallback in fallbacks {
        require_protocol(protocols, "fallback parent", &fallback.parent)?;
        require_protocol(protocols, "fallback child", &fallback.child)?;
        grouped
            .entry(fallback.parent.clone())
            .or_default()
            .push(fallback);
    }
    let mut selected = BTreeMap::new();
    for (parent, candidates) in grouped {
        let fallback = if candidates.len() == 1 {
            candidates.into_iter().next().expect("one fallback")
        } else if let Some(origin) = policy.selection(&SelectionKey::Fallback(parent.clone())) {
            select_exact_origin(
                candidates,
                origin,
                format!("fallback {parent}"),
                |candidate| &candidate.origin,
            )?
        } else if let Some(fallback) =
            select_single_builtin(candidates, |candidate| &candidate.origin)
        {
            fallback
        } else {
            return Err(CatalogError::FallbackConflict { parent });
        };
        selected.insert(parent, fallback);
    }
    Ok(selected)
}

fn select_exact_origin<T>(
    candidates: Vec<T>,
    origin: &RegistrationOrigin,
    resource: String,
    candidate_origin: impl Fn(&T) -> &RegistrationOrigin,
) -> Result<T, CatalogError> {
    let mut selected = candidates
        .into_iter()
        .filter(|candidate| candidate_origin(candidate) == origin)
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(CatalogError::InvalidSelection {
            resource,
            origin: origin.clone(),
        });
    }
    Ok(selected.pop().expect("one selected candidate"))
}

fn select_single_builtin<T>(
    candidates: Vec<T>,
    candidate_origin: impl Fn(&T) -> &RegistrationOrigin,
) -> Option<T> {
    let mut builtins = candidates
        .into_iter()
        .filter(|candidate| candidate_origin(candidate) == &RegistrationOrigin::Builtin);
    let selected = builtins.next()?;
    builtins.next().is_none().then_some(selected)
}

fn require_protocol(
    protocols: &BTreeMap<ProtocolId, ProtocolRegistration>,
    resource: &'static str,
    protocol: &ProtocolId,
) -> Result<(), CatalogError> {
    if protocols.contains_key(protocol) {
        Ok(())
    } else {
        Err(CatalogError::UnknownProtocol {
            resource,
            protocol: protocol.clone(),
        })
    }
}

fn enforce_limit(resource: &'static str, actual: usize, limit: usize) -> Result<(), CatalogError> {
    if actual <= limit {
        Ok(())
    } else {
        Err(CatalogError::ResourceLimit {
            resource,
            actual,
            limit,
        })
    }
}

fn normalize_alias(alias: &str) -> Result<String, CatalogError> {
    let alias = alias.trim().to_ascii_lowercase();
    ProtocolId::new(&alias).map_err(|_| CatalogError::InvalidAlias {
        alias: alias.clone(),
    })?;
    Ok(alias)
}

fn hash_catalog(
    protocols: &BTreeMap<ProtocolId, ProtocolRegistration>,
    aliases: &BTreeMap<String, ProtocolId>,
    roots: &BTreeMap<u32, CaptureRootRegistration>,
    bindings: &BindingRegistrations,
    fallbacks: &BTreeMap<ProtocolId, FallbackBindingRegistration>,
) -> CatalogHash {
    let mut hash = Sha256::new();
    hash.update(b"packetcraftr-protocol-catalog-v1");
    hash_len(&mut hash, protocols.len());
    for registration in protocols.values() {
        hash_text(&mut hash, registration.protocol.as_str());
        hash_text(&mut hash, registration.schema.schema_hash.as_str());
        hash_text(&mut hash, registration.provider.as_str());
        hash_text(&mut hash, registration.provider_key.as_str());
        hash_origin(&mut hash, &registration.origin);
        hash.update([u8::from(registration.matcher)]);
        hash_len(&mut hash, registration.accepted_decoded_protocols.len());
        for accepted in registration.accepted_decoded_protocols.iter() {
            hash_text(&mut hash, accepted.as_str());
        }
    }
    hash_len(&mut hash, aliases.len());
    for (alias, protocol) in aliases {
        hash_text(&mut hash, alias);
        hash_text(&mut hash, protocol.as_str());
    }
    hash_len(&mut hash, roots.len());
    for (link_type, registration) in roots {
        hash.update(link_type.to_be_bytes());
        hash_text(&mut hash, registration.protocol.as_str());
        hash_origin(&mut hash, &registration.origin);
    }
    hash_len(&mut hash, bindings.len());
    for ((parent, discriminator), registration) in bindings {
        hash_text(&mut hash, parent.as_str());
        hash.update(discriminator.0.to_be_bytes());
        hash_text(&mut hash, registration.child.as_str());
        hash.update([match registration.direction {
            BindingDirection::DecodeOnly => 0,
            BindingDirection::Canonical => 1,
        }]);
        hash_origin(&mut hash, &registration.origin);
    }
    hash_len(&mut hash, fallbacks.len());
    for (parent, registration) in fallbacks {
        hash_text(&mut hash, parent.as_str());
        hash_text(&mut hash, registration.child.as_str());
        hash_origin(&mut hash, &registration.origin);
    }
    CatalogHash::from_bytes(hash.finalize().into())
}

fn hash_origin(hash: &mut Sha256, origin: &RegistrationOrigin) {
    match origin {
        RegistrationOrigin::Builtin => hash.update([0]),
        RegistrationOrigin::Native { provider } => {
            hash.update([1]);
            hash_text(hash, provider.as_str());
        }
        RegistrationOrigin::Wasm {
            package,
            package_digest,
            component,
            component_digest,
            extension,
        } => {
            hash.update([2]);
            hash_text(hash, package.as_str());
            hash_text(hash, package_digest.as_str());
            hash_text(hash, component.as_str());
            hash_text(hash, component_digest.as_str());
            hash_text(hash, extension.as_str());
        }
    }
}

fn hash_text(hash: &mut Sha256, value: &str) {
    hash_len(hash, value.len());
    hash.update(value.as_bytes());
}

fn hash_len(hash: &mut Sha256, value: usize) {
    hash.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}
