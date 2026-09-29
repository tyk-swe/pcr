// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};
pub const MAX_CERTIFICATES: usize = 32;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Certificate {
    pub der: Bytes,
    pub sha256: String,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Complete,
    Encrypted,
    #[default]
    Incomplete,
    Malformed,
    Limit,
    NotObserved,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CertificateCollection {
    pub status: CertificateStatus,
    pub entries: Vec<Certificate>,
}
pub(super) fn parse(body: &[u8]) -> CertificateCollection {
    let mut collection = CertificateCollection::default();
    let Some(total) = length(body) else {
        collection.status = CertificateStatus::Malformed;
        return collection;
    };
    if total != body.len() - 3 {
        collection.status = CertificateStatus::Malformed;
        return collection;
    }
    let mut offset = 3;
    while offset < body.len() {
        if collection.entries.len() == MAX_CERTIFICATES {
            collection.status = CertificateStatus::Limit;
            return collection;
        }
        let Some(size) = length(&body[offset..]) else {
            collection.status = CertificateStatus::Malformed;
            return collection;
        };
        offset += 3;
        let Some(der) = body
            .get(offset..offset.saturating_add(size))
            .filter(|bytes| !bytes.is_empty())
        else {
            collection.status = CertificateStatus::Malformed;
            return collection;
        };
        let digest = Sha256::digest(der);
        let sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        collection.entries.push(Certificate {
            der: Bytes::copy_from_slice(der),
            sha256,
        });
        offset += size;
    }
    collection.status = CertificateStatus::Complete;
    collection
}
fn length(bytes: &[u8]) -> Option<usize> {
    let bytes = bytes.get(..3)?;
    Some((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_der_hash_and_malformed_list_lengths() {
        let chain = parse(&[0, 0, 6, 0, 0, 3, 1, 2, 3]);
        assert_eq!(chain.status, CertificateStatus::Complete);
        assert_eq!(chain.entries[0].der.as_ref(), [1, 2, 3]);
        assert_eq!(
            chain.entries[0].sha256,
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
        );
        assert_eq!(
            parse(&[0, 0, 7, 0, 0, 3, 1, 2, 3]).status,
            CertificateStatus::Malformed
        );
        assert_eq!(
            parse(&[0, 0, 3, 0, 0, 0]).status,
            CertificateStatus::Malformed
        );
    }
}
