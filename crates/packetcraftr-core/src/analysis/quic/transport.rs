use super::crypto::{Opened, validate_retry};
use super::ranges::StreamState;
use super::state::{IssuedCid, Observation, State};
use super::{Direction, EarlyData, KeyLog, Limits};
use crate::protocol::application::{
    quic::{Error, Frame, Packet, PacketKind, parse_frames},
    tls,
};

impl State {
    pub(super) fn process(
        &mut self,
        packet: &Packet<'_>,
        observation: &Observation<'_>,
        log: &KeyLog,
        limits: &Limits,
        replay: bool,
    ) -> Result<bool, Error> {
        let Observation {
            direction,
            number,
            timestamp,
            ..
        } = *observation;
        if !replay {
            self.report.metrics.packets += 1;
            self.report.last_frame = self.report.last_frame.max(number);
            self.last_time = self.last_time.max(timestamp);
            match packet.kind {
                PacketKind::Initial => self.report.metrics.initial_packets += 1,
                PacketKind::Handshake => self.report.metrics.handshake_packets += 1,
                PacketKind::ZeroRtt => {
                    self.report.metrics.zero_rtt_packets += 1;
                    self.report.early_data = match self.early_acceptance {
                        Some(true) => EarlyData::Accepted,
                        Some(false) => EarlyData::Rejected,
                        None => EarlyData::Unknown,
                    };
                }
                PacketKind::OneRtt => self.report.metrics.one_rtt_packets += 1,
                _ => {}
            }
        }
        if packet.version != 0 && packet.version != self.version.wire() {
            self.diagnostic(number, "unsupported_version_transition", "Observed another long-header version on this connection; version changes within a connection are unsupported", limits);
            return Ok(true);
        }
        if packet.kind == PacketKind::Retry {
            if direction != Direction::Server || self.retry_seen {
                return Err(Error::Invalid);
            }
            validate_retry(self.version, &self.original_dcid, packet.bytes)?;
            self.retry_seen = true;
            self.report.metrics.retry_packets += 1;
            self.initial_dcid = packet.scid.to_vec();
            self.learn_cid(packet.scid, Direction::Server, limits, number);
            for p in &mut self.protections {
                p.previous_initial = p.initial.take();
            }
            return Ok(true);
        }
        if packet.kind == PacketKind::VersionNegotiation {
            self.diagnostic(
                number,
                "version_negotiation",
                "Observed an unauthenticated Version Negotiation packet",
                limits,
            );
            return Ok(true);
        }
        let Some(opened) = self.open(packet, direction, log)? else {
            return Ok(false);
        };
        self.accept(packet, observation, opened, limits)?;
        Ok(true)
    }
    fn accept(
        &mut self,
        packet: &Packet<'_>,
        observation: &Observation<'_>,
        opened: Opened,
        limits: &Limits,
    ) -> Result<(), Error> {
        let Observation {
            direction,
            number,
            timestamp,
            flow,
        } = *observation;
        self.report.metrics.decrypted_packets += 1;
        self.last_packet = Some((direction, packet.kind, opened.number));
        let space = packet.kind.space();
        let p = &mut self.protections[direction.index()];
        if p.seen[space].contains(&opened.number) {
            self.report.metrics.duplicate_packets += 1;
            return Ok(());
        }
        if let Some(largest) = p.largest[space] {
            if opened.number < largest {
                self.report.metrics.reordered_packets += 1;
            }
            if opened.number > largest.saturating_add(1) {
                self.report.metrics.observed_packet_gaps += opened.number - largest - 1;
            }
        }
        p.largest[space] = Some(p.largest[space].map_or(opened.number, |n| n.max(opened.number)));
        p.seen[space].insert(opened.number);
        if p.seen[space].len() > limits.max_ranges {
            p.seen[space].pop_first();
        }
        if !packet.scid.is_empty() || packet.kind == PacketKind::Initial {
            self.learn_cid(packet.scid, direction, limits, number);
        }
        let canonical = if direction == Direction::Client {
            flow.clone()
        } else {
            flow.reverse()
        };
        if !self.report.paths.contains(&canonical) {
            if self.report.paths.len() < limits.max_connection_ids {
                self.report.paths.push(canonical);
            } else {
                self.diagnostic(
                    number,
                    "path_limit",
                    "Connection path tracking limit reached",
                    limits,
                );
            }
        }
        let frames = parse_frames(&opened.plaintext, limits.max_ranges)?;
        let ack_eliciting = frames
            .iter()
            .any(|f| !matches!(f, Frame::Ack { .. } | Frame::Padding | Frame::Close { .. }));
        if ack_eliciting {
            let sent = &mut self.protections[direction.index()].sent[space];
            sent.insert(opened.number, timestamp);
            if sent.len() > limits.max_ranges {
                sent.pop_first();
            }
        }
        for frame in frames {
            if !allowed(&frame, packet.kind) {
                self.diagnostic(
                    number,
                    "invalid_frame_level",
                    "Frame is not permitted at this QUIC encryption level",
                    limits,
                );
                continue;
            }
            if let Err(error) = self.frame(frame, packet.kind, observation, limits) {
                let code = if error == Error::Limit {
                    "buffer_limit"
                } else {
                    "malformed_frame"
                };
                self.diagnostic(number, code, error.to_string(), limits);
            }
        }
        Ok(())
    }
    pub(super) fn accept_early_data(&mut self, limits: &Limits) -> Result<(), Error> {
        let early = self
            .streams
            .extract_if(.., |(_, _, early), _| *early)
            .collect::<Vec<_>>();
        let mut first_error = None;
        for ((id, direction, _), state) in early {
            let destination = self
                .streams
                .entry((id, direction, false))
                .or_insert_with(StreamState::new);
            destination.ranges.conflicting |= state.ranges.conflicting;
            for range in state.ranges.finish() {
                match destination.insert(range.offset, &range.data, false, limits) {
                    Ok(repeated) => self.report.metrics.repeated_stream_bytes += repeated,
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if let Some(size) = state.final_size
                && let Err(error) = destination.set_final(size)
            {
                first_error.get_or_insert(error);
            }
            destination.omitted_bytes = destination
                .omitted_bytes
                .saturating_add(state.omitted_bytes);
            destination.final_size_error |= state.final_size_error;
            if state.reset_error.is_some() {
                destination.reset_error = state.reset_error;
            }
        }
        first_error.map_or(Ok(()), Err)
    }
    fn frame(
        &mut self,
        frame: Frame<'_>,
        kind: PacketKind,
        observation: &Observation<'_>,
        limits: &Limits,
    ) -> Result<(), Error> {
        let Observation {
            direction,
            number,
            timestamp,
            flow,
        } = *observation;
        match frame {
            Frame::Crypto { offset, data } => {
                self.crypto_data(kind.space(), offset, data, observation, limits)?;
            }
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                validate_stream_sender(id, direction)?;
                let early = kind == PacketKind::ZeroRtt && self.early_acceptance != Some(true);
                let key = (id, direction, early);
                if !self.streams.contains_key(&key)
                    && self.streams.len() >= limits.max_streams_per_connection
                {
                    return Err(Error::Limit);
                }
                let stream = self.streams.entry(key).or_insert_with(StreamState::new);
                self.report.metrics.repeated_stream_bytes +=
                    stream.insert(offset, data, fin, limits)?;
            }
            Frame::ResetStream {
                id,
                error,
                final_size,
            } => {
                validate_stream_sender(id, direction)?;
                let key = (
                    id,
                    direction,
                    kind == PacketKind::ZeroRtt && self.early_acceptance != Some(true),
                );
                if !self.streams.contains_key(&key)
                    && self.streams.len() >= limits.max_streams_per_connection
                {
                    return Err(Error::Limit);
                }
                let stream = self.streams.entry(key).or_insert_with(StreamState::new);
                stream.set_final(final_size)?;
                stream.reset_error = Some(error);
            }
            Frame::Ack { ranges, .. } => {
                let sent = &mut self.protections[direction.reverse().index()].sent[kind.space()];
                for range in ranges {
                    let observed: Vec<_> = sent
                        .range(range.first..=range.last)
                        .map(|(&n, &t)| (n, t))
                        .collect();
                    for (n, t) in observed {
                        sent.remove(&n);
                        if let Ok(elapsed) = timestamp.duration_since(t) {
                            let ms = elapsed.as_secs_f64() * 1000.0;
                            self.report.metrics.ack_samples += 1;
                            self.report.metrics.min_ack_elapsed_ms = Some(
                                self.report
                                    .metrics
                                    .min_ack_elapsed_ms
                                    .map_or(ms, |old| old.min(ms)),
                            );
                        }
                    }
                }
            }
            Frame::NewConnectionId {
                sequence,
                retire_before,
                id,
                reset_token,
            } => {
                self.issue_cid(
                    IssuedCid {
                        id,
                        owner: direction,
                        sequence,
                        token: reset_token.try_into().map_err(|_| Error::Invalid)?,
                    },
                    retire_before,
                    limits,
                )?;
            }
            Frame::RetireConnectionId(sequence) => {
                self.retire_cid(direction.reverse(), sequence, limits)?;
            }
            Frame::PathChallenge(data) => {
                self.report.metrics.path_challenges += 1;
                if self.challenges.len() >= limits.max_connection_ids {
                    return Err(Error::Limit);
                }
                self.challenges.insert(
                    data.try_into().map_err(|_| Error::Invalid)?,
                    (direction, flow.clone()),
                );
            }
            Frame::PathResponse(data) => {
                let token: [u8; 8] = data.try_into().map_err(|_| Error::Invalid)?;
                if self.challenges.get(&token).is_some_and(|(sent, path)| {
                    *sent == direction.reverse() && path.reverse() == *flow
                }) {
                    self.challenges.remove(&token);
                    self.report.metrics.validated_paths += 1;
                }
            }
            Frame::Close { error, reason, .. } => {
                self.report.closed = true;
                self.report.close_error = Some(error);
                self.report.close_reason =
                    Some(tls::escape_wire_bytes(&reason[..reason.len().min(128)]));
            }
            Frame::HandshakeDone => {
                if direction != Direction::Server {
                    return Err(Error::Invalid);
                }
                self.report.handshake_done_frame = Some(number);
            }
            Frame::Datagram(data) => {
                self.report.metrics.datagrams += 1;
                self.report.metrics.datagram_bytes += data.len() as u64;
            }
            Frame::Limit { kind: 20..=23, .. } => self.report.metrics.flow_control_blocks += 1,
            _ => {}
        }
        Ok(())
    }
}
fn validate_stream_sender(id: u64, direction: Direction) -> Result<(), Error> {
    if id & 2 != 0 && (id & 1 == 0) != (direction == Direction::Client) {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn allowed(frame: &Frame<'_>, kind: PacketKind) -> bool {
    match frame {
        Frame::Padding | Frame::Ping => true,
        Frame::Ack { .. } | Frame::Crypto { .. } => kind != PacketKind::ZeroRtt,
        Frame::Close { application, .. } => {
            !*application || matches!(kind, PacketKind::ZeroRtt | PacketKind::OneRtt)
        }
        Frame::NewToken(_) | Frame::PathResponse(_) | Frame::HandshakeDone => {
            kind == PacketKind::OneRtt
        }
        _ => matches!(kind, PacketKind::ZeroRtt | PacketKind::OneRtt),
    }
}
