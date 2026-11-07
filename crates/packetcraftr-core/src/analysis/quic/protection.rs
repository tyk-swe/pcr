use super::crypto::{Keys, Opened, Suite};
use super::keylog::Label;
use super::state::State;
use super::{Direction, KeyLog};
use crate::protocol::application::quic::{Error, Packet, PacketKind};

impl State {
    pub(super) fn install_keys(&mut self, log: &KeyLog) {
        let Some(random) = self.random else {
            return;
        };
        let Some(suite) = self.report.cipher_suite.and_then(Suite::from_tls) else {
            return;
        };
        for direction in [Direction::Client, Direction::Server] {
            let (handshake, traffic) = match direction {
                Direction::Client => (Label::ClientHandshake, Label::ClientTraffic),
                Direction::Server => (Label::ServerHandshake, Label::ServerTraffic),
            };
            let protection = &mut self.protections[direction.index()];
            if protection.handshake.is_none() {
                protection.handshake = log
                    .get(&random, handshake)
                    .and_then(|s| Keys::new(suite, self.version, s).ok());
            }
            if protection.application.is_none() {
                protection.application = log
                    .get(&random, traffic)
                    .and_then(|s| Keys::new(suite, self.version, s).ok());
            }
        }
    }
    pub(super) fn open(
        &mut self,
        packet: &Packet<'_>,
        direction: Direction,
        log: &KeyLog,
    ) -> Result<Option<Opened>, Error> {
        self.install_keys(log);
        let protection = &mut self.protections[direction.index()];
        let largest = protection.largest[packet.kind.space()];
        match packet.kind {
            PacketKind::Initial => {
                if protection.initial.is_none() {
                    protection.initial = Some(Keys::initial(
                        self.version,
                        &self.initial_dcid,
                        direction == Direction::Client,
                    )?);
                }
                let result = protection
                    .initial
                    .as_ref()
                    .map(|k| k.open(packet, largest))
                    .transpose();
                if matches!(result, Err(Error::Authentication))
                    && let Some(previous) = &protection.previous_initial
                {
                    return previous.open(packet, largest).map(Some);
                }
                result
            }
            PacketKind::Handshake => protection
                .handshake
                .as_ref()
                .map(|k| k.open(packet, largest))
                .transpose(),
            PacketKind::ZeroRtt => {
                if direction != Direction::Client {
                    return Err(Error::Invalid);
                }
                if let Some(keys) = &protection.early {
                    return keys.open(packet, largest).map(Some);
                }
                let Some(secret) = self
                    .random
                    .and_then(|random| log.get(&random, Label::Early))
                else {
                    return Ok(None);
                };
                for suite in [Suite::Aes128, Suite::Aes256, Suite::ChaCha] {
                    let Ok(keys) = Keys::new(suite, self.version, secret) else {
                        continue;
                    };
                    if let Ok(opened) = keys.open(packet, largest) {
                        protection.early = Some(keys);
                        return Ok(Some(opened));
                    }
                }
                Err(Error::Authentication)
            }
            PacketKind::OneRtt => {
                let Some(current) = &protection.application else {
                    return Ok(None);
                };
                match current.open(packet, largest) {
                    Ok(opened) => {
                        if opened.key_phase != protection.key_phase {
                            return Err(Error::Invalid);
                        }
                        return Ok(Some(opened));
                    }
                    Err(Error::Authentication) => {}
                    Err(error) => return Err(error),
                }
                if let Some(previous) = &protection.previous
                    && let Ok(opened) = previous.open(packet, largest)
                {
                    if opened.key_phase == protection.key_phase
                        || protection
                            .generation_start
                            .is_some_and(|n| opened.number >= n)
                    {
                        return Err(Error::Invalid);
                    }
                    return Ok(Some(opened));
                }
                let next = current.next()?;
                let opened = next.open(packet, largest)?;
                if opened.key_phase == protection.key_phase
                    || largest.is_some_and(|n| opened.number <= n)
                {
                    return Err(Error::Invalid);
                }
                protection.previous = protection.application.replace(next);
                protection.key_phase = opened.key_phase;
                protection.generation_start = Some(opened.number);
                self.report.metrics.key_updates += 1;
                self.keys_changed = true;
                Ok(Some(opened))
            }
            _ => Err(Error::Invalid),
        }
    }
}
