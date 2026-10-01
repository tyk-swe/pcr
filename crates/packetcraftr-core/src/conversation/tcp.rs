// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::{Close, Endpoints, Error, Flow, Options, ensure_frames};
use crate::field::WireValue;
use crate::packet::Packet;
use crate::protocol::transport::{Tcp, TcpOption};

const PSH: u16 = 0x008;
/// Frames in the three-way handshake.
const HANDSHAKE_FRAMES: u128 = 3;

/// Frames the exchange produces, so the limit applies before any packet exists.
///
/// Each burst of data is acknowledged by the receiver after every
/// `(window - 1) / mss` segments (at least one) and at its end, which keeps
/// the data in flight below the advertised window rather than exactly filling
/// it, so the capture shows no window-full condition.
fn frame_count(request: usize, response: usize, mss: u16, window: u16, close: Close) -> u128 {
    let (mss, window) = (usize::from(mss), usize::from(window));
    let per_ack = u128::try_from(((window - 1) / mss).max(1)).unwrap_or(u128::MAX);
    let burst = |length: usize| {
        let segments = u128::try_from(length.div_ceil(mss)).unwrap_or(u128::MAX);
        segments.saturating_add(segments.div_ceil(per_ack))
    };
    let closing = match close {
        Close::Fin => 4,
        Close::Rst => 1,
        Close::None => 0,
    };
    HANDSHAKE_FRAMES
        .saturating_add(burst(request))
        .saturating_add(burst(response))
        .saturating_add(closing)
}

pub(super) fn expand(
    endpoints: &Endpoints,
    base: &Tcp,
    options: &Options,
    request: &Bytes,
    response: &Bytes,
) -> Result<Vec<Packet>, Error> {
    if options.mss == 0 {
        return Err(Error::ZeroMss);
    }
    if base.window == 0 {
        return Err(Error::ZeroWindow);
    }
    if options.mss > base.window {
        return Err(Error::MssExceedsWindow {
            mss: options.mss,
            window: base.window,
        });
    }
    ensure_frames(
        frame_count(
            request.len(),
            response.len(),
            options.mss,
            base.window,
            options.close,
        ),
        options.max_frames,
    )?;
    // Both payloads must stay within one 32-bit sequence space.
    if u32::try_from(request.len())
        .ok()
        .zip(u32::try_from(response.len()).ok())
        .and_then(|(request, response)| request.checked_add(response))
        .is_none_or(|total| total > u32::MAX - 8)
    {
        return Err(Error::SequenceSpace);
    }
    let mut conversation = Exchange {
        client: Side::new(&endpoints.client, options.client_isn),
        server: Side::new(&endpoints.server, options.server_isn),
        base,
        mss: usize::from(options.mss),
        per_ack: ((usize::from(base.window) - 1) / usize::from(options.mss)).max(1),
        frames: Vec::new(),
    };
    let mss_option = [TcpOption::Mss(options.mss)];
    conversation.send(Role::Client, Tcp::SYN, &mss_option, &Bytes::new());
    conversation.send(
        Role::Server,
        Tcp::SYN | Tcp::ACK,
        &mss_option,
        &Bytes::new(),
    );
    conversation.send(Role::Client, Tcp::ACK, &[], &Bytes::new());
    conversation.burst(Role::Client, request);
    conversation.burst(Role::Server, response);
    match options.close {
        Close::Fin => {
            conversation.send(Role::Client, Tcp::FIN | Tcp::ACK, &[], &Bytes::new());
            conversation.send(Role::Server, Tcp::ACK, &[], &Bytes::new());
            conversation.send(Role::Server, Tcp::FIN | Tcp::ACK, &[], &Bytes::new());
            conversation.send(Role::Client, Tcp::ACK, &[], &Bytes::new());
        }
        Close::Rst => conversation.send(Role::Client, Tcp::RST | Tcp::ACK, &[], &Bytes::new()),
        Close::None => {}
    }
    Ok(conversation.frames)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

impl Role {
    const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// One endpoint and the next sequence number it will send.
struct Side<'a> {
    flow: &'a Flow,
    next: u32,
}

impl<'a> Side<'a> {
    fn new(flow: &'a Flow, isn: u32) -> Self {
        Self { flow, next: isn }
    }
}

struct Exchange<'a> {
    client: Side<'a>,
    server: Side<'a>,
    base: &'a Tcp,
    mss: usize,
    per_ack: usize,
    frames: Vec<Packet>,
}

impl Exchange<'_> {
    fn side(&self, role: Role) -> &Side<'_> {
        match role {
            Role::Client => &self.client,
            Role::Server => &self.server,
        }
    }

    /// Sends one frame whose acknowledgment, when flagged, covers everything
    /// the peer has sent so far, then advances the sender's sequence number.
    fn send(&mut self, from: Role, flags: u16, options: &[TcpOption], payload: &Bytes) {
        let acknowledgment = if flags & Tcp::ACK == 0 {
            0
        } else {
            self.side(from.peer()).next
        };
        let sender = self.side(from);
        let tcp = Tcp {
            source_port: sender.flow.source_port,
            destination_port: sender.flow.destination_port,
            sequence: sender.next,
            acknowledgment,
            flags,
            checksum: WireValue::Auto,
            options: options.to_vec(),
            ..self.base.clone()
        };
        let packet = sender.flow.packet(tcp, payload);
        // SYN and FIN each occupy one sequence number; the payload fits u32 by `expand`.
        let consumed = u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .wrapping_add(u32::from(flags & (Tcp::SYN | Tcp::FIN) != 0));
        let sender = match from {
            Role::Client => &mut self.client,
            Role::Server => &mut self.server,
        };
        sender.next = sender.next.wrapping_add(consumed);
        self.frames.push(packet);
    }

    /// Sends `data` in segments, each group of which the peer acknowledges.
    fn burst(&mut self, from: Role, data: &Bytes) {
        let mut offset = 0;
        let mut unacknowledged = 0;
        while offset < data.len() {
            let end = data.len().min(offset.saturating_add(self.mss));
            let flags = if end == data.len() {
                Tcp::ACK | PSH
            } else {
                Tcp::ACK
            };
            self.send(from, flags, &[], &data.slice(offset..end));
            offset = end;
            unacknowledged += 1;
            if unacknowledged == self.per_ack || offset == data.len() {
                self.send(from.peer(), Tcp::ACK, &[], &Bytes::new());
                unacknowledged = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_count_matches_burst_and_close_rules() {
        // Three request segments, one response segment, each burst acknowledged once.
        assert_eq!(
            frame_count(3000, 100, 1460, 65_535, Close::Fin),
            3 + 4 + 2 + 4
        );
        assert_eq!(frame_count(0, 0, 1460, 65_535, Close::None), 3);
        assert_eq!(frame_count(0, 0, 1460, 65_535, Close::Rst), 4);
        // Two segments would fill a two-byte window, so every segment is acknowledged.
        assert_eq!(frame_count(5, 0, 1, 2, Close::None), 3 + 5 + 5);
        // A window holding two segments and a spare byte is acknowledged after every second one.
        assert_eq!(frame_count(5, 0, 1, 3, Close::None), 3 + 5 + 3);
    }

    #[test]
    fn frame_count_never_wraps() {
        assert!(frame_count(usize::MAX, usize::MAX, 1, 1, Close::Fin) > 4096);
    }
}
