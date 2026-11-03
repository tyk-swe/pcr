// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, LazyLock};

use crate::protocol::BuiltinProtocol;

use super::bindings;

fn register_catalog(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    for protocol in BuiltinProtocol::ALL {
        protocol.register(builder)?;
    }
    Ok(())
}

pub fn registry() -> Arc<crate::registry::Registry> {
    static REGISTRY: LazyLock<Arc<crate::registry::Registry>> = LazyLock::new(|| {
        Arc::new(registry_with(|_builder| Ok(())).expect("built-in catalog must register"))
    });
    Arc::clone(&REGISTRY)
}

/// Build the default registry, then let the caller add bindings before it is
/// frozen.
/// ```
/// use packetcraftr_core::protocol::builtin;
///
/// let registry = builtin::registry_with(|builder| {
///     builder.bind("tcp", 4433, "tls", packetcraftr_core::registry::Priority::Primary)?;
///     Ok(())
/// })
/// .expect("extra binding is valid");
/// assert_eq!(
///     registry
///         .child_for("tcp", packetcraftr_core::registry::Discriminator(4433))
///         .map(|protocol| protocol.as_str()),
///     Some("tls")
/// );
/// ```
pub fn registry_with<F>(extra: F) -> Result<crate::registry::Registry, crate::registry::Error>
where
    F: FnOnce(&mut crate::registry::Builder) -> Result<(), crate::registry::Error>,
{
    let mut builder = crate::registry::Builder::default();
    register_catalog(&mut builder)?;
    bindings::register(&mut builder)?;
    extra(&mut builder)?;
    builder.build()
}

/// Build the default registry with extra TCP ports dissected as TLS.
/// ```
/// use packetcraftr_core::protocol::builtin;
///
/// let registry = builtin::registry_with_tls_ports(&[4433]).expect("extra TLS port");
/// assert_eq!(
///     registry
///         .child_for("tcp", packetcraftr_core::registry::Discriminator(4433))
///         .map(|protocol| protocol.as_str()),
///     Some("tls")
/// );
/// ```
pub fn registry_with_tls_ports(
    ports: &[u16],
) -> Result<crate::registry::Registry, crate::registry::Error> {
    registry_with(|builder| bindings::bind_tls_ports(builder, ports))
}
