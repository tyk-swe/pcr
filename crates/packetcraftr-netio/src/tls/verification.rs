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
        // Certificate-only iterators skip other PEM sections. Reject them first,
        // including unknown labels, rather than silently accepting a mixed bundle.
        for line in bytes.split(|byte| *byte == b'\n' || *byte == b'\r') {
            let line = line.trim_ascii();
            if (line.windows(11).any(|window| window == b"-----BEGIN ")
                && line != b"-----BEGIN CERTIFICATE-----")
                || (line.windows(9).any(|window| window == b"-----END ")
                    && line != b"-----END CERTIFICATE-----")
            {
                return Err("CA file contains a non-certificate PEM section".into());
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn unauthenticated_evidence_never_verifies() {
        let name = ServerName::Declared("example.test".into());
        let roots = TrustStore::default();

        let missing = verify(&Evidence::default(), &name, &roots);
        assert!(!missing.valid());
        assert_eq!(missing.chain.valid, None);

        let truncated = verify(
            &Evidence {
                certificates_truncated: true,
                ..Evidence::default()
            },
            &name,
            &roots,
        );
        assert!(!truncated.valid());
        assert_eq!(truncated.chain.valid, None);

        let garbage = verify(
            &Evidence {
                certificates: vec![Bytes::from_static(b"not a certificate")],
                ..Evidence::default()
            },
            &name,
            &roots,
        );
        assert!(!garbage.valid());
        assert_eq!(garbage.chain.valid, Some(false));

        let untrusted_der = CertificateDer::pem_slice_iter(include_bytes!("test-ca.pem"))
            .next()
            .expect("fixture holds a certificate")
            .expect("fixture certificate parses");
        let untrusted = verify(
            &Evidence {
                certificates: vec![Bytes::copy_from_slice(untrusted_der.as_ref())],
                ..Evidence::default()
            },
            &name,
            &roots,
        );
        assert!(!untrusted.valid());
        assert_eq!(untrusted.chain.valid, Some(false));
    }

    #[test]
    fn ca_bundles_reject_every_other_pem_section() {
        let certificate = include_bytes!("test-ca.pem");
        assert!(TrustStore::from_pem(certificate).is_ok());
        for label in ["PRIVATE KEY", "PUBLIC KEY", "UNKNOWN"] {
            let section = format!("-----BEGIN {label}-----\nAQ==\n-----END {label}-----\n");
            assert!(TrustStore::from_pem(section.as_bytes()).is_err());
            let mut mixed = certificate.to_vec();
            mixed.extend(section.as_bytes());
            assert!(
                TrustStore::from_pem(&mixed)
                    .unwrap_err()
                    .contains("non-certificate")
            );
        }
    }
}
