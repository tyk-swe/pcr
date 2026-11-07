use super::crypto::Keys;
use super::ranges::{Ranges, StreamState};
use super::{Connection, Datagram, Diagnostic, Direction, EarlyData, Limits, Metrics};
use crate::analysis::{Endpoint, FlowKey};
use crate::protocol::application::quic::{Packet, PacketKind, Version};
use bytes::Bytes;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::SystemTime;

#[derive(Clone, Copy)]
pub(super) struct Observation<'a> {
    pub(super) direction: Direction,
    pub(super) number: u64,
    pub(super) timestamp: SystemTime,
    pub(super) flow: &'a FlowKey,
}
pub(super) struct Cid {
    pub(super) id: Vec<u8>,
    pub(super) owner: Direction,
    pub(super) sequence: Option<u64>,
    pub(super) token: Option<[u8; 16]>,
    pub(super) retired: bool,
}
pub(super) struct IssuedCid<'a> {
    pub(super) id: &'a [u8],
    pub(super) owner: Direction,
    pub(super) sequence: u64,
    pub(super) token: [u8; 16],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingReason {
    MissingSecrets,
    Authentication,
}
pub(super) struct Pending {
    pub(super) reason: PendingReason,
    pub(super) bytes: Bytes,
    pub(super) direction: Direction,
    pub(super) dcid_length: usize,
    pub(super) number: u64,
    pub(super) timestamp: SystemTime,
    pub(super) flow: FlowKey,
    pub(super) keylog_revision: u64,
}
#[derive(Default)]
pub(super) struct Protection {
    pub(super) initial: Option<Keys>,
    pub(super) previous_initial: Option<Keys>,
    pub(super) handshake: Option<Keys>,
    pub(super) early: Option<Keys>,
    pub(super) application: Option<Keys>,
    pub(super) previous: Option<Keys>,
    pub(super) key_phase: bool,
    pub(super) generation_start: Option<u64>,
    pub(super) largest: [Option<u64>; 3],
    pub(super) seen: [BTreeSet<u64>; 3],
    pub(super) sent: [BTreeMap<u64, SystemTime>; 3],
}
#[derive(Default)]
pub(super) struct CryptoStream {
    pub(super) ranges: Ranges,
    pub(super) consumed: u64,
}
pub(super) struct State {
    pub(super) report: Connection,
    pub(super) version: Version,
    pub(super) cids: Vec<Cid>,
    pub(super) original_dcid: Vec<u8>,
    pub(super) initial_dcid: Vec<u8>,
    pub(super) random: Option<[u8; 32]>,
    pub(super) protections: [Protection; 2],
    pub(super) crypto: [[CryptoStream; 3]; 2],
    pub(super) streams: BTreeMap<(u64, Direction, bool), StreamState>,
    pub(super) pending: VecDeque<Pending>,
    pub(super) challenges: BTreeMap<[u8; 8], (Direction, FlowKey)>,
    pub(super) last_time: SystemTime,
    pub(super) hello_time: Option<SystemTime>,
    pub(super) last_packet: Option<(Direction, PacketKind, u64)>,
    pub(super) key_revision: u64,
    pub(super) keys_changed: bool,
    pub(super) retry_seen: bool,
    pub(super) early_acceptance: Option<bool>,
    pub(super) source_frames: BTreeSet<u64>,
}
impl State {
    pub(super) fn new(
        index: u64,
        version: Version,
        input: &super::Datagram<'_>,
        packet: &Packet<'_>,
    ) -> Self {
        let flow = &input.flow.flow;
        let scope = input.scope.clone();
        let frame = input.number;
        let timestamp = input.timestamp;
        let dcid = packet.dcid;
        let scid = packet.scid;
        let report = Connection {
            connection: index,
            scope,
            version: version.wire(),
            client_endpoint: Endpoint {
                address: flow.source,
                port: flow.source_port,
            },
            server_endpoint: Endpoint {
                address: flow.destination,
                port: flow.destination_port,
            },
            first_frame: frame,
            last_frame: frame,
            connection_ids: Vec::new(),
            paths: vec![flow.clone()],
            sni: None,
            sni_is_outer: false,
            offered_alpn: Vec::new(),
            negotiated_alpn: None,
            cipher_suite: None,
            ja3: None,
            ja4: None,
            client_hello_frame: None,
            server_hello_frame: None,
            hello_elapsed_ms: None,
            client_finished_frame: None,
            server_finished_frame: None,
            handshake_done_frame: None,
            early_data: EarlyData::NotObserved,
            client_transport_parameters: Vec::new(),
            server_transport_parameters: Vec::new(),
            streams: Vec::new(),
            metrics: Metrics::default(),
            diagnostics: Vec::new(),
            diagnostics_omitted: 0,
            pending_packets: 0,
            closed: false,
            close_error: None,
            close_reason: None,
            stateless_reset: false,
            incomplete: false,
            end_reason: String::new(),
            source_frames: Vec::new(),
            source_frames_omitted: 0,
        };
        Self {
            report,
            version,
            cids: vec![
                Cid {
                    id: dcid.to_vec(),
                    owner: Direction::Server,
                    sequence: None,
                    token: None,
                    retired: false,
                },
                Cid {
                    id: scid.to_vec(),
                    owner: Direction::Client,
                    sequence: Some(0),
                    token: None,
                    retired: false,
                },
            ],
            original_dcid: dcid.to_vec(),
            initial_dcid: dcid.to_vec(),
            random: None,
            protections: std::array::from_fn(|_| Protection::default()),
            crypto: std::array::from_fn(|_| std::array::from_fn(|_| CryptoStream::default())),
            streams: BTreeMap::new(),
            pending: VecDeque::new(),
            challenges: BTreeMap::new(),
            last_time: timestamp,
            hello_time: None,
            last_packet: None,
            key_revision: 0,
            keys_changed: false,
            retry_seen: false,
            early_acceptance: None,
            source_frames: BTreeSet::new(),
        }
    }
    pub(super) fn record_datagram(&mut self, input: &Datagram<'_>, limits: &Limits) {
        self.report.last_frame = self.report.last_frame.max(input.number);
        self.last_time = self.last_time.max(input.timestamp);
        for &frame in input.source_frames {
            if self.source_frames.len() < limits.max_ranges {
                self.source_frames.insert(frame);
            } else if !self.source_frames.contains(&frame) {
                self.report.source_frames_omitted += 1;
                self.report.incomplete = true;
            }
        }
        if input.truncated {
            self.diagnostic(
                input.number,
                "capture_truncated",
                "UDP datagram is truncated in the capture",
                limits,
            );
        }
    }
    pub(super) fn issue_cid(
        &mut self,
        issued: IssuedCid<'_>,
        retire_before: u64,
        limits: &Limits,
    ) -> Result<(), super::Error> {
        if self.cids.iter().any(|cid| {
            cid.owner == issued.owner
                && ((cid.sequence == Some(issued.sequence)
                    && (cid.id != issued.id
                        || cid.token.is_some_and(|token| token != issued.token)))
                    || (cid.id == issued.id
                        && cid
                            .sequence
                            .is_some_and(|sequence| sequence != issued.sequence)))
        }) {
            return Err(super::Error::Invalid);
        }
        if let Some(cid) = self
            .cids
            .iter_mut()
            .find(|cid| cid.owner == issued.owner && cid.sequence == Some(issued.sequence))
        {
            cid.token = Some(issued.token);
        } else {
            if self.cids.len() >= limits.max_connection_ids {
                return Err(super::Error::Limit);
            }
            self.cids.push(Cid {
                id: issued.id.to_vec(),
                owner: issued.owner,
                sequence: Some(issued.sequence),
                token: Some(issued.token),
                retired: false,
            });
        }
        for cid in &mut self.cids {
            if cid.owner == issued.owner
                && cid
                    .sequence
                    .is_some_and(|sequence| sequence < retire_before)
            {
                cid.retired = true;
            }
        }
        Ok(())
    }
    pub(super) fn diagnostic(
        &mut self,
        frame: u64,
        code: &str,
        message: impl Into<String>,
        limits: &Limits,
    ) {
        self.report.incomplete = true;
        if self.report.diagnostics.len() >= limits.max_diagnostics {
            self.report.diagnostics_omitted += 1;
            return;
        }
        let mut message = message.into();
        if message.len() > 512 {
            let mut end = 512;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        self.report.diagnostics.push(Diagnostic {
            frame,
            code: code.to_owned(),
            message,
        });
    }
    pub(super) fn memory(&self) -> usize {
        8192 + self
            .pending
            .iter()
            .map(|p| 256 + p.bytes.len())
            .sum::<usize>()
            + self
                .streams
                .values()
                .map(|s| 256 + s.ranges.memory())
                .sum::<usize>()
            + self
                .crypto
                .iter()
                .flatten()
                .map(|c| 128 + c.ranges.memory())
                .sum::<usize>()
            + self
                .protections
                .iter()
                .map(|p| {
                    p.seen.iter().map(|s| s.len() * 64).sum::<usize>()
                        + p.sent.iter().map(|s| s.len() * 80).sum::<usize>()
                })
                .sum::<usize>()
            + self
                .cids
                .iter()
                .map(|c| 128 + c.id.capacity())
                .sum::<usize>()
            + self.report.paths.len() * 256
            + self.challenges.len() * 256
            + self.source_frames.len() * 64
            + self
                .report
                .diagnostics
                .iter()
                .map(|d| 128 + d.code.capacity() + d.message.capacity())
                .sum::<usize>()
            + self
                .report
                .offered_alpn
                .iter()
                .map(|s| s.capacity() + 32)
                .sum::<usize>()
            + self.report.sni.as_ref().map_or(0, String::capacity)
            + self
                .report
                .client_transport_parameters
                .iter()
                .chain(&self.report.server_transport_parameters)
                .map(|p| p.value_hex.capacity() + 64)
                .sum::<usize>()
    }
    pub(super) fn finish(mut self, reason: &str, limits: &Limits) -> Connection {
        self.report.end_reason = reason.to_owned();
        self.report.pending_packets = self.pending.len() as u64;
        if self
            .pending
            .iter()
            .any(|p| p.reason == PendingReason::MissingSecrets)
        {
            let code = if self.random.is_none() || self.report.cipher_suite.is_none() {
                "missing_context"
            } else {
                "missing_secrets"
            };
            self.diagnostic(self.report.last_frame, code, "Buffered packets need handshake context or traffic secrets that were not available", limits);
        }
        if self
            .pending
            .iter()
            .any(|p| p.reason == PendingReason::Authentication)
        {
            self.diagnostic(
                self.report.last_frame,
                "authentication_failed",
                "Buffered packets could not be authenticated with the available keys",
                limits,
            );
        }
        if !self.report.closed {
            self.report.incomplete = true;
        }
        self.report.connection_ids = self
            .cids
            .iter()
            .map(|c| super::keylog::hex(&c.id))
            .collect();
        self.report.source_frames = self.source_frames.into_iter().collect();
        self.report.streams = self
            .streams
            .into_iter()
            .map(|((id, direction, early), state)| state.finish(id, direction, early))
            .collect();
        if self
            .report
            .streams
            .iter()
            .any(|s| !s.complete || (s.early_data && self.report.early_data != EarlyData::Accepted))
        {
            self.report.incomplete = true;
        }
        self.report
    }
    pub(super) fn learn_cid(&mut self, id: &[u8], owner: Direction, limits: &Limits, frame: u64) {
        if self.cids.iter().any(|c| c.id == id && c.owner == owner) {
            return;
        }
        if self.cids.len() >= limits.max_connection_ids {
            self.diagnostic(
                frame,
                "connection_id_limit",
                "Connection ID tracking limit reached",
                limits,
            );
            return;
        }
        self.cids.push(Cid {
            id: id.to_vec(),
            owner,
            sequence: Some(0),
            token: None,
            retired: false,
        });
    }
}
