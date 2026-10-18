// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Trust decisions remain separate from passive handshake observations.
use super::{Evidence, ServerName};
use rustls::{
    RootCertStore,
    client::{verify_server_cert_signed_by_trust_anchor, verify_server_name},
    pki_types::{CertificateDer, UnixTime, pem::PemObject},
    server::ParsedCertificate,
};

#[derive(Clone, Debug)]
pub struct TrustStore(RootCertStore);
impl Default for TrustStore {
    fn default() -> Self {
        Self(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
    }
}
impl TrustStore {
    /// Replaces the bundled roots. Empty, malformed, oversized, or non-certificate PEM is rejected.
    pub fn from_pem(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err("CA file must contain 1..1048576 bytes".into());
        }
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(bytes) {
            roots
                .add(cert.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        }
        if roots.is_empty() {
            return Err("CA file contains no certificates".into());
        }
        Ok(Self(roots))
    }
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Check {
    pub valid: Option<bool>,
    pub reason: Option<String>,
}
impl Check {
    fn result(result: Result<(), rustls::Error>) -> Self {
        match result {
            Ok(()) => Self {
                valid: Some(true),
                reason: None,
            },
            Err(e) => Self {
                valid: Some(false),
                reason: Some(e.to_string()),
            },
        }
    }
    fn unavailable(reason: &str) -> Self {
        Self {
            valid: None,
            reason: Some(reason.into()),
        }
    }
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Verification {
    pub chain: Check,
    pub name: Check,
}
impl Verification {
    pub fn valid(&self) -> bool {
        self.chain.valid == Some(true) && self.name.valid == Some(true)
    }
}

/// Evaluates the retained chain at the current time; no revocation fetching or network I/O.
/// Callers must gate all application writes on `valid()` when authenticating TLS.
pub fn verify(evidence: &Evidence, name: &ServerName, roots: &TrustStore) -> Verification {
    let unavailable = |reason| Verification {
        chain: Check::unavailable(reason),
        name: Check::unavailable(reason),
    };
    if evidence.certificates_truncated {
        return unavailable("certificate evidence truncated");
    }
    let Some(leaf) = evidence.certificates.first() else {
        return unavailable("no certificate presented");
    };
    let der = CertificateDer::from(leaf.as_ref());
    let cert = match ParsedCertificate::try_from(&der) {
        Ok(cert) => cert,
        Err(e) => {
            return Verification {
                chain: Check::result(Err(e.clone())),
                name: Check::result(Err(e)),
            };
        }
    };
    let intermediates: Vec<_> = evidence
        .certificates
        .iter()
        .skip(1)
        .map(|c| CertificateDer::from(c.as_ref()))
        .collect();
    let provider = rustls::crypto::ring::default_provider();
    let chain = Check::result(verify_server_cert_signed_by_trust_anchor(
        &cert,
        &roots.0,
        &intermediates,
        UnixTime::now(),
        provider.signature_verification_algorithms.all,
    ));
    let name = match name.clone().into_rustls() {
        Ok(name) => Check::result(verify_server_name(&cert, &name)),
        Err(e) => Check {
            valid: Some(false),
            reason: Some(e.to_string()),
        },
    };
    Verification { chain, name }
}
