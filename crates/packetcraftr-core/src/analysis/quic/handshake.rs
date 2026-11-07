use super::keylog::hex;
use super::state::{IssuedCid, Observation, State};
use super::{Direction, EarlyData, Limits, TransportParameter};
use crate::protocol::application::{
    quic::{Error, Reader},
    tls,
};

impl State {
    pub(super) fn crypto_data(
        &mut self,
        level: usize,
        offset: u64,
        data: &[u8],
        observation: &Observation<'_>,
        limits: &Limits,
    ) -> Result<(), Error> {
        let Observation {
            direction,
            number: frame,
            timestamp,
            ..
        } = *observation;
        let stream = &mut self.crypto[direction.index()][level];
        stream
            .ranges
            .insert(offset, data, 132 * 1024, limits.max_ranges)?;
        loop {
            let stream = &self.crypto[direction.index()][level];
            let input = stream.ranges.prefix(stream.consumed);
            if input.len() < 4 {
                break;
            }
            let length = u32::from_be_bytes([0, input[1], input[2], input[3]]) as usize;
            if length > 132 * 1024 - 4 {
                return Err(Error::Limit);
            }
            let Some(message) = input.get(..length + 4) else {
                break;
            };
            self.handshake_message(direction, level, message, frame, timestamp, limits)?;
            self.crypto[direction.index()][level].consumed += message.len() as u64;
        }
        Ok(())
    }
    fn handshake_message(
        &mut self,
        direction: Direction,
        level: usize,
        message: &[u8],
        frame: u64,
        timestamp: std::time::SystemTime,
        limits: &Limits,
    ) -> Result<(), Error> {
        match message[0] {
            1 | 2 => {
                if level != 0 {
                    return Err(Error::Invalid);
                }
                let tls::Outcome::Complete { value, .. } = tls::parse_handshake(message) else {
                    return Err(Error::Invalid);
                };
                match value {
                    tls::Handshake::ClientHello(hello) if direction == Direction::Client => {
                        self.random = Some(hello.random);
                        self.report.sni = hello.sni.as_deref().map(tls::escape_wire_text);
                        self.report.sni_is_outer = hello.ech && hello.has_sni_extension;
                        self.report.offered_alpn = hello
                            .alpn_raw
                            .iter()
                            .map(|s| tls::escape_wire_bytes(s))
                            .collect();
                        self.report.ja3 = Some(tls::ja3(&hello).md5);
                        self.report.ja4 = Some(tls::ja4(&hello, tls::Transport::Quic));
                        self.report.client_hello_frame = Some(frame);
                        self.hello_time = Some(timestamp);
                        self.keys_changed = true;
                        for extension in &hello.extensions {
                            if extension.kind == 0x39 {
                                self.report.client_transport_parameters =
                                    self.parameters(&extension.data, Direction::Client, limits)?;
                            }
                        }
                    }
                    tls::Handshake::ServerHello(hello) if direction == Direction::Server => {
                        if hello.is_hello_retry_request {
                            return Ok(());
                        }
                        self.report.cipher_suite = Some(hello.cipher_suite);
                        self.report.server_hello_frame = Some(frame);
                        self.report.hello_elapsed_ms = self
                            .hello_time
                            .and_then(|t| timestamp.duration_since(t).ok())
                            .map(|d| d.as_secs_f64() * 1000.0);
                        self.keys_changed = true;
                        if super::crypto::Suite::from_tls(hello.cipher_suite).is_none() {
                            self.diagnostic(frame, "unsupported_cipher", "The negotiated TLS cipher suite is not supported for QUIC decryption", limits);
                        }
                    }
                    _ => return Err(Error::Invalid),
                }
            }
            8 => {
                if direction != Direction::Server || level != 1 {
                    return Err(Error::Invalid);
                }
                let body = &message[4..];
                let header: [u8; 2] = body
                    .get(..2)
                    .ok_or(Error::Truncated)?
                    .try_into()
                    .map_err(|_| Error::Truncated)?;
                if usize::from(u16::from_be_bytes(header)) != body.len() - 2 {
                    return Err(Error::Invalid);
                }
                let mut r = Reader::new(&body[2..]);
                let mut early = false;
                let mut seen = std::collections::BTreeSet::new();
                while r.left() != 0 {
                    if seen.len() >= 256 {
                        return Err(Error::Limit);
                    }
                    let kind =
                        u16::from_be_bytes(r.take(2)?.try_into().map_err(|_| Error::Truncated)?);
                    if !seen.insert(kind) {
                        return Err(Error::Invalid);
                    }
                    let length = usize::from(u16::from_be_bytes(
                        r.take(2)?.try_into().map_err(|_| Error::Truncated)?,
                    ));
                    let data = r.take(length)?;
                    match kind {
                        0x10 => {
                            if data.len() < 3
                                || usize::from(u16::from_be_bytes([data[0], data[1]]))
                                    != data.len() - 2
                                || data[2] == 0
                                || usize::from(data[2]) != data.len() - 3
                            {
                                return Err(Error::Invalid);
                            }
                            self.report.negotiated_alpn = Some(tls::escape_wire_bytes(&data[3..]));
                        }
                        0x2a if data.is_empty() => early = true,
                        0x39 => {
                            self.report.server_transport_parameters =
                                self.parameters(data, direction, limits)?;
                        }
                        _ => {}
                    }
                }
                self.early_acceptance = Some(early);
                if self.report.early_data != EarlyData::NotObserved {
                    self.report.early_data = if early {
                        EarlyData::Accepted
                    } else {
                        EarlyData::Rejected
                    };
                }
                if early {
                    self.accept_early_data(limits)?;
                }
            }
            20 => {
                if level != 1 {
                    return Err(Error::Invalid);
                }
                match direction {
                    Direction::Client => self.report.client_finished_frame = Some(frame),
                    Direction::Server => self.report.server_finished_frame = Some(frame),
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn parameters(
        &mut self,
        data: &[u8],
        direction: Direction,
        limits: &Limits,
    ) -> Result<Vec<TransportParameter>, Error> {
        let mut r = Reader::new(data);
        let mut parameters = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        while r.left() != 0 {
            if parameters.len() >= limits.max_ranges.min(256) {
                return Err(Error::Limit);
            }
            let id = r.varint()?;
            if !seen.insert(id) {
                return Err(Error::Invalid);
            }
            let len = r.length()?;
            let value = r.take(len)?;
            if id == 2 && direction == Direction::Server {
                let token: [u8; 16] = value.try_into().map_err(|_| Error::Invalid)?;
                for cid in &mut self.cids {
                    if cid.owner == Direction::Server && cid.sequence == Some(0) {
                        cid.token = Some(token);
                    }
                }
            }
            if id == 13 {
                if direction != Direction::Server {
                    return Err(Error::Invalid);
                }
                let mut preferred = Reader::new(value);
                preferred.take(24)?;
                let length = usize::from(preferred.byte()?);
                if !(1..=20).contains(&length) {
                    return Err(Error::Invalid);
                }
                let cid = preferred.take(length)?;
                let token = preferred.take(16)?.try_into().map_err(|_| Error::Invalid)?;
                if preferred.left() != 0 {
                    return Err(Error::Invalid);
                }
                self.issue_cid(
                    IssuedCid {
                        id: cid,
                        owner: Direction::Server,
                        sequence: 1,
                        token,
                    },
                    0,
                    limits,
                )?;
            }
            parameters.push(TransportParameter {
                id,
                value_hex: hex(value),
            });
        }
        Ok(parameters)
    }
}
