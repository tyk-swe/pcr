// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP diagnostic scan modes: the flag combination each raw probe carries and
//! the acknowledgment identity that binds a bare reset to its probe.

use super::Error;

const MAX_CUSTOM_FLAGS: u16 = 0x1ff;
const ACKNOWLEDGMENT_IDENTITY: u32 = 0x5043_5201;

/// Which TCP segment a raw scan sends to each scan endpoint.
///
/// `Custom` is observation-only: it never infers a port state, even when its
/// flags equal those of another mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TcpScan {
    #[default]
    Syn,
    Ack,
    Window,
    Fin,
    Null,
    Xmas,
    Maimon,
    Custom {
        flags: u16,
    },
}

impl TcpScan {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Ack => "ack",
            Self::Window => "window",
            Self::Fin => "fin",
            Self::Null => "null",
            Self::Xmas => "xmas",
            Self::Maimon => "maimon",
            Self::Custom { .. } => "custom",
        }
    }

    /// The TCP flag bits the probe carries.
    pub const fn flags(self) -> u16 {
        match self {
            Self::Syn => 0x002,
            Self::Ack | Self::Window => 0x010,
            Self::Fin => 0x001,
            Self::Null => 0x000,
            Self::Xmas => 0x029,
            Self::Maimon => 0x011,
            Self::Custom { flags } => flags,
        }
    }

    pub const fn is_syn(self) -> bool {
        matches!(self, Self::Syn)
    }

    pub fn validate(self) -> Result<(), Error> {
        match self {
            Self::Custom { flags } if flags > MAX_CUSTOM_FLAGS => Err(Error::InvalidLimit {
                field: "tcp_flags",
                value: u64::from(flags),
                reason: format!("must be within 0..={MAX_CUSTOM_FLAGS:#x}"),
            }),
            _ => Ok(()),
        }
    }

    /// The acknowledgment number a probe with `flags` carries: nonzero and
    /// distinct per sequence when ACK is set, so a bare reset binds to one
    /// probe, and zero otherwise.
    pub(super) fn acknowledgment(self, sequence: u64) -> u32 {
        if self.flags() & 0x010 != 0 {
            (sequence as u32).wrapping_add(ACKNOWLEDGMENT_IDENTITY)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_carry_exact_flags_and_validate_custom_range() {
        let expected = [
            (TcpScan::Syn, "syn", 0x002),
            (TcpScan::Ack, "ack", 0x010),
            (TcpScan::Window, "window", 0x010),
            (TcpScan::Fin, "fin", 0x001),
            (TcpScan::Null, "null", 0x000),
            (TcpScan::Xmas, "xmas", 0x029),
            (TcpScan::Maimon, "maimon", 0x011),
            (TcpScan::Custom { flags: 0x1ff }, "custom", 0x1ff),
        ];
        for (mode, name, flags) in expected {
            assert_eq!((mode.as_str(), mode.flags()), (name, flags));
            mode.validate().expect("valid mode");
        }
        assert_eq!(TcpScan::default(), TcpScan::Syn);
        assert!(TcpScan::Custom { flags: 0x200 }.validate().is_err());
        assert!(TcpScan::Custom { flags: u16::MAX }.validate().is_err());
    }

    #[test]
    fn acknowledgment_is_nonzero_per_sequence_only_with_ack() {
        assert_eq!(TcpScan::Syn.acknowledgment(5), 0);
        assert_eq!(TcpScan::Xmas.acknowledgment(5), 0);
        assert_eq!(TcpScan::Custom { flags: 0x100 }.acknowledgment(5), 0);
        for mode in [TcpScan::Ack, TcpScan::Window, TcpScan::Maimon] {
            assert_eq!(mode.acknowledgment(0), 0x5043_5201);
            assert_ne!(mode.acknowledgment(0), mode.acknowledgment(1));
        }
        assert_eq!(
            TcpScan::Custom { flags: 0x010 }.acknowledgment(u64::from(u32::MAX)),
            0x5043_5200
        );
    }

    fn probe(mode: TcpScan, sequence: u64) -> crate::scan::Probe {
        crate::scan::Probe {
            sequence,
            stage: crate::scan::Stage::Scan,
            address: "192.0.2.1".parse().unwrap(),
            scope: None,
            endpoint: crate::probe::ProbeEndpoint::Tcp { port: 80 },
            tcp_scan: mode,
            sctp_scan: Default::default(),
            attempt: 1,
            udp_payload: bytes::Bytes::new(),
            udp_profile: None,
        }
    }

    #[test]
    fn final_checks_bind_the_exact_flags_and_acknowledgment() {
        use packetcraftr_core::protocol::transport::Tcp;
        for mode in [
            TcpScan::Syn,
            TcpScan::Ack,
            TcpScan::Window,
            TcpScan::Fin,
            TcpScan::Null,
            TcpScan::Xmas,
            TcpScan::Maimon,
            TcpScan::Custom { flags: 0x1ff },
        ] {
            let probe = probe(mode, 9);
            let packet = probe.packet();
            let tcp = packet.get::<Tcp>().unwrap();
            assert_eq!(tcp.flags, mode.flags());
            assert_eq!(tcp.acknowledgment, mode.acknowledgment(9));
            assert!(crate::scan::plan::packet::sent_probe_matches(
                &probe, &packet
            ));

            let mut mutated = packet.clone();
            mutated.get_mut::<Tcp>().unwrap().flags ^= 0x004;
            assert!(!crate::scan::plan::packet::sent_probe_matches(
                &probe, &mutated
            ));
            let mut mutated = packet.clone();
            mutated.get_mut::<Tcp>().unwrap().acknowledgment ^= 1;
            assert!(!crate::scan::plan::packet::sent_probe_matches(
                &probe, &mutated
            ));
            let mut mutated = packet.clone();
            mutated
                .get_mut::<Tcp>()
                .unwrap()
                .options
                .push(packetcraftr_core::protocol::transport::TcpOption::Nop);
            assert!(!crate::scan::plan::packet::sent_probe_matches(
                &probe, &mutated
            ));
            assert!(!crate::scan::plan::packet::sent_probe_matches(
                &self::probe(mode, 10),
                &packet
            ));
        }
    }
}
