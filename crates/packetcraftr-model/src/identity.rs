// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable, bounded identities shared by catalog and extension boundaries.

use std::borrow::Borrow;
use std::fmt;
use std::sync::Arc;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Maximum serialized bytes accepted by textual external identities.
pub const MAX_IDENTITY_BYTES: usize = 128;
/// Serialized bytes in a canonical `sha256:<hex>` content digest.
pub const SHA256_CONTENT_DIGEST_BYTES: usize = 71;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("{kind} identity is empty")]
    Empty { kind: &'static str },
    #[error("{kind} identity has {actual} bytes, exceeding limit {limit}")]
    TooLong {
        kind: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("{kind} identity {value:?} is malformed")]
    Malformed { kind: &'static str, value: String },
    #[error("content digest must use canonical sha256:<64 lowercase hex digits> form")]
    InvalidContentDigest,
}

fn validate_text_identity(kind: &'static str, value: &str) -> Result<(), IdentityError> {
    if value.is_empty() || value.trim().is_empty() {
        return Err(IdentityError::Empty { kind });
    }
    if value.len() > MAX_IDENTITY_BYTES {
        return Err(IdentityError::TooLong {
            kind,
            actual: value.len(),
            limit: MAX_IDENTITY_BYTES,
        });
    }
    let bytes = value.as_bytes();
    let valid_edge = |byte: u8| byte.is_ascii_alphanumeric();
    if !value.is_ascii()
        || !valid_edge(bytes[0])
        || !valid_edge(bytes[bytes.len() - 1])
        || !bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
    {
        return Err(IdentityError::Malformed {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

macro_rules! textual_identity {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("A validated, bounded ", $kind, " identity.")]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Validates untrusted identity text.
            pub fn new(value: impl AsRef<str>) -> Result<Self, IdentityError> {
                Self::try_from(value.as_ref())
            }

            /// Constructs a first-party identity embedded in the program.
            ///
            /// This deliberately panics for an invalid literal so mistakes are
            /// caught at initialization rather than propagated as runtime data.
            pub fn from_static(value: &'static str) -> Self {
                validate_text_identity($kind, value)
                    .unwrap_or_else(|error| panic!("invalid built-in {} identity: {error}", $kind));
                Self(Arc::from(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdentityError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                validate_text_identity($kind, value)?;
                Ok(Self(Arc::from(value)))
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentityError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                validate_text_identity($kind, &value)?;
                Ok(Self(Arc::from(value)))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(D::Error::custom)
            }
        }
    };
}

textual_identity!(ProtocolId, "protocol");
textual_identity!(FieldId, "field");
textual_identity!(ProviderId, "provider");
textual_identity!(PackageId, "package");
textual_identity!(ComponentId, "component");
textual_identity!(ExtensionId, "extension");

impl ProtocolId {
    /// Whether this name is reserved for first-party PacketcraftR protocols.
    pub fn is_packetcraftr_namespace(&self) -> bool {
        self.as_str() == "packetcraftr" || self.as_str().starts_with("packetcraftr.")
    }
}

/// An exact digest for installed package or component content.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentDigest(Arc<str>);

impl ContentDigest {
    pub fn new(value: impl AsRef<str>) -> Result<Self, IdentityError> {
        Self::try_from(value.as_ref())
    }

    pub fn from_sha256(bytes: [u8; 32]) -> Self {
        let mut value = String::with_capacity(SHA256_CONTENT_DIGEST_BYTES);
        value.push_str("sha256:");
        push_hex(&mut value, &bytes);
        Self(Arc::from(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn sha256_bytes(&self) -> [u8; 32] {
        let hex = &self.as_str().as_bytes()[7..];
        let mut output = [0_u8; 32];
        for (index, pair) in hex.chunks_exact(2).enumerate() {
            output[index] = (hex_nibble(pair[0]).expect("validated digest") << 4)
                | hex_nibble(pair[1]).expect("validated digest");
        }
        output
    }
}

impl TryFrom<&str> for ContentDigest {
    type Error = IdentityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(IdentityError::InvalidContentDigest);
        };
        if value.len() != SHA256_CONTENT_DIGEST_BYTES
            || hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IdentityError::InvalidContentDigest);
        }
        Ok(Self(Arc::from(value)))
    }
}

impl TryFrom<String> for ContentDigest {
    type Error = IdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl AsRef<str> for ContentDigest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ContentDigest {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ContentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(D::Error::custom)
    }
}

/// Deterministic identity of one canonical protocol-catalog snapshot.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogHash([u8; 32]);

impl CatalogHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        push_hex(&mut output, &self.0);
        output
    }
}

impl fmt::Debug for CatalogHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CatalogHash")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for CatalogHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for CatalogHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CatalogHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "catalog hash must contain 64 lowercase hexadecimal digits",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0]).expect("validated hash") << 4)
                | hex_nibble(pair[1]).expect("validated hash");
        }
        Ok(Self(bytes))
    }
}

/// Source identity attached to every selected catalog registration.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegistrationOrigin {
    Builtin,
    Native {
        provider: ProviderId,
    },
    Wasm {
        package: PackageId,
        package_digest: ContentDigest,
        component: ComponentId,
        component_digest: ContentDigest,
        extension: ExtensionId,
    },
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textual_identities_validate_and_serialize_transparently() {
        let id = ProtocolId::from_static("vendor.example/foo-v1");
        assert_eq!(
            <ProtocolId as Borrow<str>>::borrow(&id),
            "vendor.example/foo-v1"
        );
        assert_eq!(id.to_string(), "vendor.example/foo-v1");
        assert_eq!(
            serde_json::from_str::<ProtocolId>("\"vendor.example/foo-v1\"").unwrap(),
            id
        );
        for invalid in ["", " ", ".bad", "bad.", "bad value", "bad\u{2603}"] {
            assert!(ProtocolId::new(invalid).is_err(), "{invalid:?}");
        }
        assert!(ProtocolId::new("x".repeat(MAX_IDENTITY_BYTES + 1)).is_err());
    }

    #[test]
    fn digests_and_catalog_hashes_have_canonical_bounded_forms() {
        let bytes = [0xab; 32];
        let digest = ContentDigest::from_sha256(bytes);
        assert_eq!(digest.sha256_bytes(), bytes);
        assert_eq!(digest.as_str().len(), SHA256_CONTENT_DIGEST_BYTES);
        assert_eq!(ContentDigest::new(digest.as_str()).unwrap(), digest);
        assert!(ContentDigest::new("sha256:ABC").is_err());

        let hash = CatalogHash::from_bytes(bytes);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(serde_json::from_str::<CatalogHash>(&json).unwrap(), hash);
    }

    #[test]
    fn registration_origins_are_runtime_neutral_and_exact_digest_bound() {
        let origin = RegistrationOrigin::Wasm {
            package: PackageId::new("example.packet").unwrap(),
            package_digest: ContentDigest::from_sha256([1; 32]),
            component: ComponentId::new("codec").unwrap(),
            component_digest: ContentDigest::from_sha256([2; 32]),
            extension: ExtensionId::new("example.packet.codec").unwrap(),
        };
        let json = serde_json::to_string(&origin).unwrap();
        assert_eq!(
            serde_json::from_str::<RegistrationOrigin>(&json).unwrap(),
            origin
        );
    }
}
