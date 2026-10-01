// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::path::StreamTransport;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Requirements {
    /// The filter reads `tcp.stream` or `udp.stream`.
    pub stream_index: bool,
    pub tcp_stream: bool,
    pub udp_stream: bool,
    pub timestamp: bool,
}

impl Requirements {
    /// Everything either operand requires.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self {
            stream_index: self.stream_index || other.stream_index,
            tcp_stream: self.tcp_stream || other.tcp_stream,
            udp_stream: self.udp_stream || other.udp_stream,
            timestamp: self.timestamp || other.timestamp,
        }
    }

    pub(super) fn require_stream(&mut self, transport: StreamTransport) {
        self.stream_index = true;
        match transport {
            StreamTransport::Tcp => self.tcp_stream = true,
            StreamTransport::Udp => self.udp_stream = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_union_ors_each_flag_independently() {
        let none = Requirements::default();
        let flags: [fn(&mut Requirements); 4] = [
            |requirements| requirements.stream_index = true,
            |requirements| requirements.tcp_stream = true,
            |requirements| requirements.udp_stream = true,
            |requirements| requirements.timestamp = true,
        ];

        for (index, set) in flags.iter().enumerate() {
            let mut one = Requirements::default();
            set(&mut one);
            assert_ne!(one, none, "flag {index}");
            assert_eq!(one.union(none), one, "flag {index}");
            assert_eq!(none.union(one), one, "flag {index}");
            for (other_index, other_set) in flags.iter().enumerate() {
                let mut other = Requirements::default();
                other_set(&mut other);
                let mut both = one;
                other_set(&mut both);
                assert_eq!(one.union(other), both, "flags {index} and {other_index}");
            }
        }
        assert_eq!(none.union(none), none);
    }
}
