// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use packetcraftr_core::build::Builder;
use packetcraftr_core::codec::Addresses;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::registry::Registry;
use sha2::{Digest, Sha256};

use super::Request;
use super::canary;
use super::catalog::{AttemptShape, build_attempt, catalog};
use super::error::Error;
use super::report::hex;
use crate::policy::{DeclaredPackets, Operation, PermissiveLive, Policy, WireLimits};

const ETHERNET_OVERHEAD: u64 = 14;

#[derive(Clone, Debug)]
pub struct PlanRow {
    pub variant_index: usize,
    pub id: &'static str,
    pub hypothesis: &'static str,
    pub packets_per_attempt: usize,
}

#[derive(Clone, Debug)]
pub struct PlanSummary {
    pub digest: String,
    pub rows: Vec<PlanRow>,
    pub total_packets: u64,
    pub total_wire_bytes: u64,
}

#[derive(Clone, Debug)]
pub(super) struct AttemptPlan {
    pub variant_index: usize,
    pub attempt_seq: u32,
    pub packets: Vec<Packet>,
    pub payload_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(super) struct Prepared {
    pub summary: PlanSummary,
    pub attempts: Vec<AttemptPlan>,
}

fn digest(request: &Request, total_packets: u64, total_wire_bytes: u64) -> String {
    let variants = catalog()
        .iter()
        .map(|variant| variant.id)
        .collect::<Vec<_>>()
        .join(",");
    let canonical = format!(
        "packetcraftr.differential.plan/v1\n\
         target={}\nresponder_port={}\nsource_port={}\nspoof_source={}\n\
         token={}\nrepeats={}\npayload_len={}\ntimeout_ms={}\n\
         variants={}\npackets={}\nwire_bytes={}\n",
        request.target,
        request.responder_port,
        request.source_port,
        request
            .spoof_source
            .map_or_else(|| "-".to_owned(), |source| source.to_string()),
        hex(&request.token),
        request.repeats,
        request.payload_len,
        request.timeout.as_millis(),
        variants,
        total_packets,
        total_wire_bytes,
    );
    hex(&Sha256::digest(canonical.as_bytes()))
}

pub(super) fn prepare(registry: &Arc<Registry>, request: &Request) -> Result<Prepared, Error> {
    let shape = AttemptShape {
        target: request.target,
        source: request.spoof_source.unwrap_or(Ipv4Addr::UNSPECIFIED),
        source_port: request.source_port,
        destination_port: request.responder_port,
    };
    let builder = Builder::new(Arc::clone(registry));
    let mut attempts = Vec::new();
    let mut rows = Vec::new();
    let mut total_packets: u64 = 0;
    let mut total_wire_bytes: u64 = 0;
    let mut seq: u32 = 0;
    for (variant_index, variant) in catalog().iter().enumerate() {
        let mut packets_per_attempt = 0_usize;
        for repeat in 0..request.repeats {
            let _ = repeat;
            let payload = canary::build_probe(
                &request.token,
                u16::try_from(variant_index).unwrap_or(u16::MAX),
                seq,
                request.payload_len,
            );
            let payload_sha256 = canary::payload_sha256(&payload);
            let packets = build_attempt(&shape, variant, &payload, seq);
            packets_per_attempt = packets.len();
            for packet in &packets {
                let built = builder
                    .build(packet.clone(), Addresses::default(), Default::default())
                    .map_err(|source| Error::Build(BoundaryError::from_error(source)))?;
                total_packets = total_packets
                    .checked_add(1)
                    .ok_or(Error::StatisticsOverflow)?;
                total_wire_bytes = total_wire_bytes
                    .checked_add(built.bytes.len() as u64 + ETHERNET_OVERHEAD)
                    .ok_or(Error::StatisticsOverflow)?;
            }
            attempts.push(AttemptPlan {
                variant_index,
                attempt_seq: seq,
                packets,
                payload_sha256,
            });
            seq += 1;
        }
        rows.push(PlanRow {
            variant_index,
            id: variant.id,
            hypothesis: variant.hypothesis,
            packets_per_attempt,
        });
    }
    Ok(Prepared {
        summary: PlanSummary {
            digest: digest(request, total_packets, total_wire_bytes),
            rows,
            total_packets,
            total_wire_bytes,
        },
        attempts,
    })
}

pub(super) fn authorize(
    policy: &Policy,
    request: &Request,
    prepared: &Prepared,
) -> Result<(), Error> {
    let packets: Vec<&Packet> = prepared
        .attempts
        .iter()
        .flat_map(|attempt| attempt.packets.iter())
        .collect();
    policy
        .authorize(Operation::Declared(DeclaredPackets::new(
            WireLimits::new(
                prepared.summary.total_packets,
                prepared.summary.total_wire_bytes,
            ),
            &packets,
            Some(std::net::IpAddr::V4(request.target)),
            PermissiveLive::NotRequired,
        )))
        .map_err(|source| Error::Authorization(BoundaryError::from_error(source)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::protocol::builtin;

    fn request() -> Request {
        Request::new(Ipv4Addr::new(192, 0, 2, 10), 40101, [0x42; 16])
    }

    #[test]
    fn digest_is_stable_and_binds_the_token() {
        let registry = builtin::registry();
        let first = prepare(&registry, &request()).expect("plan prepares");
        let second = prepare(&registry, &request()).expect("plan prepares");
        assert_eq!(first.summary.digest, second.summary.digest);

        let mut other = request();
        other.token = [0x24; 16];
        let changed = prepare(&registry, &other).expect("plan prepares");
        assert_ne!(first.summary.digest, changed.summary.digest);
    }

    #[test]
    fn budgets_count_every_attempt_packet() {
        let registry = builtin::registry();
        let prepared = prepare(&registry, &request()).expect("plan prepares");
        let counted: usize = prepared
            .attempts
            .iter()
            .map(|attempt| attempt.packets.len())
            .sum();
        assert_eq!(prepared.summary.total_packets, counted as u64);
        assert_eq!(
            prepared.summary.total_packets,
            (catalog().len() * request().repeats as usize) as u64
        );
        assert!(prepared.summary.total_wire_bytes > prepared.summary.total_packets * 60);
    }

    #[test]
    fn public_target_is_denied_without_opt_in() {
        let registry = builtin::registry();
        let mut public = request();
        public.target = Ipv4Addr::new(8, 8, 8, 8);
        let prepared = prepare(&registry, &public).expect("plan prepares");
        let denied = authorize(&Policy::default(), &public, &prepared);
        assert!(matches!(denied, Err(Error::Authorization(_))));

        let allowed = Policy {
            allow_public_destinations: true,
            ..Policy::default()
        };
        authorize(&allowed, &public, &prepared).expect("opt-in authorizes");
    }
}
