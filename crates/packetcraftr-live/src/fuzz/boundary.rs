// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_packet::build::{Builder, Options as BuildOptions, Result as BuiltPacket};
use packetcraftr_packet::registry::Registry;
use packetcraftr_packet::{Packet, diagnostic::Diagnostic};

use crate::BoundaryError;
use crate::exchange::{ExchangeResult, MatchedResponse, UndecodedCapture, UnsolicitedResponse};
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization,
};
use crate::send::SentPacket;

#[derive(Clone, Debug)]
struct AuthorizedBuild {
    bytes: Bytes,
    registry: Arc<Registry>,
    options: BuildOptions,
}

#[derive(Clone, Debug)]
pub struct FuzzExecutionCase {
    index: u64,
    seed: u64,
    packet: Packet,
    authorized_build: Option<AuthorizedBuild>,
}

impl FuzzExecutionCase {
    #[cfg(test)]
    pub(crate) fn new(index: u64, seed: u64, packet: Packet) -> Self {
        Self {
            index,
            seed,
            packet,
            authorized_build: None,
        }
    }

    pub(crate) fn from_prepared(
        index: u64,
        seed: u64,
        built: BuiltPacket,
        registry: Arc<Registry>,
        options: BuildOptions,
    ) -> Self {
        Self {
            index,
            seed,
            packet: built.packet.clone(),
            authorized_build: Some(AuthorizedBuild {
                bytes: built.bytes,
                registry,
                options,
            }),
        }
    }

    pub fn index(&self) -> u64 {
        self.index
    }
    pub fn seed(&self) -> u64 {
        self.seed
    }
    pub fn packet(&self) -> &Packet {
        &self.packet
    }
}

#[derive(Clone, Debug)]
pub struct FuzzCaseExecution {
    case_index: u64,
    seed: u64,
    pub(crate) sent: SentPacket,
    pub(crate) responses: Vec<MatchedResponse>,
    pub(crate) unmatched: Vec<UnsolicitedResponse>,
    pub(crate) undecoded: Vec<UndecodedCapture>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: crate::Stats,
}

impl FuzzCaseExecution {
    /// A successful fuzz result can only be made from an opaque exchange
    /// receipt whose authorized semantic packet is exactly this case.
    pub fn from_exchange(
        case: &FuzzExecutionCase,
        exchange: &ExchangeResult,
    ) -> Result<Self, BoundaryError> {
        if exchange.sent().len() != 1 {
            return Err(BoundaryError::internal_execution(
                "fuzz exchange returned more than one sent receipt",
                "internal.fuzz_execution",
                "discard evidence that is not bound to exactly one prepared case",
            ));
        }
        let Some(sent) = exchange.sent().first().cloned() else {
            return Err(BoundaryError::internal_execution(
                "fuzz exchange did not produce a sent receipt",
                "internal.fuzz_execution",
                "discard incomplete trusted exchange evidence",
            ));
        };
        case.validate_receipt(&sent)?;
        Ok(Self {
            case_index: case.index,
            seed: case.seed,
            sent,
            responses: exchange.responses().to_vec(),
            unmatched: exchange.unsolicited().to_vec(),
            undecoded: exchange.undecoded().to_vec(),
            diagnostics: exchange.diagnostics().to_vec(),
            stats: exchange.stats().clone(),
        })
    }

    pub fn sent(&self) -> &SentPacket {
        &self.sent
    }
    pub fn case_index(&self) -> u64 {
        self.case_index
    }
    pub fn seed(&self) -> u64 {
        self.seed
    }
    pub fn responses(&self) -> &[MatchedResponse] {
        &self.responses
    }
    pub fn unmatched(&self) -> &[UnsolicitedResponse] {
        &self.unmatched
    }
    pub fn undecoded(&self) -> &[UndecodedCapture] {
        &self.undecoded
    }
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    pub fn stats(&self) -> &crate::Stats {
        &self.stats
    }
}

impl FuzzExecutionCase {
    fn validate_receipt(&self, sent: &SentPacket) -> Result<(), BoundaryError> {
        let Some(authorized_build) = &self.authorized_build else {
            if !sent.packet().structurally_eq(&self.packet) {
                return Err(BoundaryError::execution_validation(
                    "fuzz executor returned a build for a different authorized case",
                    "fuzz.executor",
                    "bind each result to the prepared case packet and seed",
                ));
            }
            return Ok(());
        };

        let mut materialized_packet = self.packet.clone();
        materialize_network_fields(&mut materialized_packet, &sent.route().plan)
            .map_err(|source| self.materialization_error(source.to_string()))?;
        materialize_link_structure(&mut materialized_packet, &sent.route().plan)
            .map_err(|source| self.materialization_error(source.to_string()))?;
        let preliminary_packet = materialized_packet.clone();
        let link_changed = materialize_link_fields(&mut materialized_packet, sent.route())
            .map_err(|source| self.materialization_error(source.to_string()))?;

        if !materialized_packet.structurally_eq(&self.packet) {
            let builder = Builder::new(Arc::clone(&authorized_build.registry));
            let context = build_context(&sent.route().plan);
            let mut preliminary = builder
                .build(
                    preliminary_packet,
                    context.clone(),
                    authorized_build.options.clone(),
                )
                .map_err(|source| self.materialization_error(source.to_string()))?;
            let preliminary_len = preliminary.bytes.len();
            let expected = if link_changed {
                if patch_builtin_ethernet(
                    &authorized_build.registry,
                    &mut preliminary,
                    &materialized_packet,
                ) {
                    preliminary
                } else {
                    builder
                        .build(
                            materialized_packet,
                            context,
                            authorized_build.options.clone(),
                        )
                        .map_err(|source| self.materialization_error(source.to_string()))?
                }
            } else {
                preliminary
            };
            require_fixed_width_link_materialization(preliminary_len, expected.bytes.len())
                .map_err(|source| self.materialization_error(source.to_string()))?;
            if !expected.packet.structurally_eq(sent.packet())
                || expected.bytes != *sent.wire_bytes()
            {
                return Err(self.substituted_build_error());
            }
        } else if authorized_build.bytes != *sent.wire_bytes()
            || !sent.packet().structurally_eq(&self.packet)
        {
            return Err(self.substituted_build_error());
        }
        Ok(())
    }

    fn substituted_build_error(&self) -> BoundaryError {
        BoundaryError::execution_validation(
            "fuzz executor returned bytes different from the authorized prepared build",
            "fuzz.executor",
            "retain exact prepared bytes or the bytes produced by the modeled route/link materialization",
        )
    }

    fn materialization_error(&self, message: String) -> BoundaryError {
        BoundaryError::execution_validation(
            format!("authorized fuzz build materialization failed: {message}"),
            "fuzz.executor",
            "reject evidence when the authorized route/link transformation cannot be reproduced",
        )
    }

    #[cfg(test)]
    pub(crate) fn validate_receipt_for_test(&self, sent: &SentPacket) -> Result<(), BoundaryError> {
        self.validate_receipt(sent)
    }
}

pub trait FuzzAuthorizer {
    /// Authorize the complete packet set, optional route destination, and
    /// conservative maximum wire-byte budget before route or capture effects.
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        destination: Option<IpAddr>,
        maximum_wire_bytes: u64,
        requires_malformed_live: bool,
    ) -> std::result::Result<(), crate::BoundaryError>;
}

pub trait FuzzExecutor {
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> std::result::Result<FuzzCaseExecution, crate::BoundaryError>;
}
