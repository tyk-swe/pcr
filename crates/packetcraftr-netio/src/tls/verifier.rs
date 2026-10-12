// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use super::Limits;

#[derive(Debug, Default)]
pub(super) struct Certificates {
    pub(super) chain: Vec<Bytes>,
    pub(super) truncated: bool,
}

#[derive(Debug)]
pub(super) struct ObservationVerifier {
    provider: Arc<CryptoProvider>,
    certificates: Arc<Mutex<Certificates>>,
    limits: Limits,
}

impl ObservationVerifier {
    pub(super) fn new(
        provider: Arc<CryptoProvider>,
        certificates: Arc<Mutex<Certificates>>,
        limits: Limits,
    ) -> Self {
        Self {
            provider,
            certificates,
            limits,
        }
    }
}

impl ServerCertVerifier for ObservationVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut evidence = self
            .certificates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        evidence.chain.clear();
        evidence.truncated = false;
        let mut retained = 0;
        for certificate in std::iter::once(end_entity).chain(intermediates) {
            if evidence.chain.len() == self.limits.max_certificates
                || certificate.len() > self.limits.max_certificate_bytes - retained
            {
                evidence.truncated = true;
                break;
            }
            retained += certificate.len();
            evidence
                .chain
                .push(Bytes::copy_from_slice(certificate.as_ref()));
        }
        // This acknowledges receipt only. No issuer, time, or hostname trust
        // decision is made; the signed handshake is verified below.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
