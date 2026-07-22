// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Packet, byte, elapsed-time, and capture counters shared by live workflows.
pub use crate::client::Stats;

impl Stats {
    pub(super) fn checked_add(&mut self, value: &Self) -> Option<()> {
        let packets_attempted = self
            .packets_attempted
            .checked_add(value.packets_attempted)?;
        let packets_completed = self
            .packets_completed
            .checked_add(value.packets_completed)?;
        let bytes = self.bytes.checked_add(value.bytes)?;
        let elapsed = self.elapsed.checked_add(value.elapsed)?;
        let received_frames = self
            .capture
            .received_frames
            .checked_add(value.capture.received_frames)?;
        let received_bytes = self
            .capture
            .received_bytes
            .checked_add(value.capture.received_bytes)?;
        let dropped_frames = self
            .capture
            .dropped_frames
            .checked_add(value.capture.dropped_frames)?;
        let dropped_bytes = self
            .capture
            .dropped_bytes
            .checked_add(value.capture.dropped_bytes)?;
        let overflow_events = self
            .capture
            .overflow_events
            .checked_add(value.capture.overflow_events)?;
        let receiver_dropped_frames = self
            .capture
            .receiver_dropped_frames
            .checked_add(value.capture.receiver_dropped_frames)?;

        self.packets_attempted = packets_attempted;
        self.packets_completed = packets_completed;
        self.bytes = bytes;
        self.elapsed = elapsed;
        self.capture.received_frames = received_frames;
        self.capture.received_bytes = received_bytes;
        self.capture.dropped_frames = dropped_frames;
        self.capture.dropped_bytes = dropped_bytes;
        self.capture.overflow_events = overflow_events;
        self.capture.receiver_dropped_frames = receiver_dropped_frames;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_add_is_unchanged_when_the_final_field_overflows() {
        let mut total = Stats {
            packets_attempted: 1,
            packets_completed: 2,
            bytes: 3,
            elapsed: std::time::Duration::from_nanos(4),
            capture: crate::net::capture::Statistics {
                received_frames: 5,
                received_bytes: 6,
                dropped_frames: 7,
                dropped_bytes: 8,
                overflow_events: 9,
                receiver_dropped_frames: u64::MAX,
            },
        };
        let original = total.clone();
        let value = Stats {
            packets_attempted: 10,
            packets_completed: 11,
            bytes: 12,
            elapsed: std::time::Duration::from_nanos(13),
            capture: crate::net::capture::Statistics {
                received_frames: 14,
                received_bytes: 15,
                dropped_frames: 16,
                dropped_bytes: 17,
                overflow_events: 18,
                receiver_dropped_frames: 1,
            },
        };

        assert_eq!(total.checked_add(&value), None);
        assert_eq!(total, original);
    }
}
