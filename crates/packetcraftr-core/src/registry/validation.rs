// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::binding::{FilterFieldBinding, ReverseBinding};

use super::error::Error;

use crate::codec::LayerCodec;
use crate::field::FieldKind;

impl super::builder::Builder {
    /// Finalizes the registry, resolving every binding it was given.
    ///
    /// # Panics
    ///
    /// Panics only if the builder corrupts a binding table; registration errors return
    /// [`Error`](crate::registry::Error).
    pub fn build(mut self) -> Result<super::lookup::Registry, Error> {
        for protocol in self.roots.values() {
            if !self.codecs.contains_key(protocol) {
                return Err(Error::UnknownProtocol {
                    protocol: protocol.clone(),
                });
            }
        }
        let mut reverse_bindings: HashMap<
            crate::layer::Id,
            HashMap<crate::layer::Id, Vec<ReverseBinding>>,
        > = HashMap::new();
        for (parent, discriminators) in &mut self.bindings {
            if !self.codecs.contains_key(parent) {
                return Err(Error::UnknownProtocol {
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
                        return Err(Error::UnknownProtocol {
                            protocol: entry.child.clone(),
                        });
                    }
                }
                entries.truncate(1);
                let Some(winner) = entries.first() else {
                    continue;
                };
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
                return Err(Error::UnknownProtocol {
                    protocol: protocol.clone(),
                });
            }
        }
        // Collect schemas once; codecs can use a default factory or publish a static schema.
        let mut schemas = BTreeMap::new();
        for (protocol, codec) in &self.codecs {
            if let Some(schema) = codec.published_schema() {
                schemas.insert(protocol.clone(), schema);
            }
        }
        for (path, binding) in &self.filter_fields {
            validate_filter_field(path, binding, &self.codecs, &schemas)?;
            reject_canonical_filter_path(path, &self.aliases, &schemas)?;
        }
        Ok(super::lookup::Registry {
            codecs: self.codecs,
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
    aliases: &HashMap<String, crate::layer::Id>,
    schemas: &BTreeMap<crate::layer::Id, &'static crate::layer::Schema>,
) -> Result<(), Error> {
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
        return Err(Error::DuplicateFilterField {
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
    codecs: &BTreeMap<crate::layer::Id, Arc<dyn LayerCodec>>,
    schemas: &BTreeMap<crate::layer::Id, &'static crate::layer::Schema>,
) -> Result<(), Error> {
    let protocol = binding.protocol();
    if !codecs.contains_key(protocol) {
        return Err(Error::UnknownProtocol {
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
            return Err(Error::UnknownFilterField {
                path: path.to_owned(),
                protocol: protocol.clone(),
                field: (*field).to_owned(),
            });
        };
        if matches!(binding, FilterFieldBinding::Bits { .. })
            && declared.kind != FieldKind::Unsigned
        {
            return Err(Error::InvalidFilterField {
                path: path.to_owned(),
                reason: format!(
                    "field {field} on layer {protocol} is not unsigned, so it has no bits to select"
                ),
            });
        }
    }
    Ok(())
}
