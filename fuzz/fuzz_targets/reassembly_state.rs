#![no_main]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr::session::{fragment, tcp, Limits};

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_flows: 16,
        max_bytes_per_flow: 4096,
        max_aggregate_bytes: 64 * 1024,
        max_fragments_per_datagram: 64,
        max_tcp_segments_per_flow: 64,
        fragment_expiry: Duration::from_millis(50),
        tcp_idle_expiry: Duration::from_millis(50),
    };
    let mut fragments =
        fragment::Reassembler::new(limits.clone(), fragment::OverlapPolicy::RejectConflicting);
    let mut tcp = tcp::Reassembler::new(limits.clone());
    let now = Instant::now();
    for (step, command) in data.chunks(8).take(512).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes[..command.len()].copy_from_slice(command);
        let word = u64::from_le_bytes(bytes);
        if word & 1 == 0 {
            let before = (
                fragments.flow_count(),
                fragments.aggregate_bytes(),
                fragments.aggregate_memory_charge(),
            );
            let result = fragments.push(
                fragment::Fragment {
                    key: fragment::Key {
                        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                        identification: (word >> 8) as u32 % 24,
                        next_header: 17,
                    },
                    offset: ((word >> 24) as u32 % 512) & !7,
                    more_fragments: word & 2 != 0,
                    bytes: Bytes::from(vec![(word >> 56) as u8; ((word >> 40) as usize % 32) + 1]),
                },
                now + Duration::from_micros(step as u64),
            );
            if result.is_err() {
                assert_eq!(
                    before,
                    (
                        fragments.flow_count(),
                        fragments.aggregate_bytes(),
                        fragments.aggregate_memory_charge()
                    )
                );
            }
        } else {
            let before = (tcp.aggregate_bytes(), tcp.aggregate_memory_charge());
            let result = tcp.push(
                tcp::Segment {
                    flow: tcp::FlowKey {
                        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                        source_port: 40_000 + ((word >> 8) as u16 % 24),
                        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                        destination_port: 443,
                    },
                    sequence: (word >> 16) as u32,
                    payload: Bytes::from(vec![
                        (word >> 56) as u8;
                        ((word >> 48) as usize % 32) + 1
                    ]),
                    syn: word & 2 != 0,
                    fin: word & 4 != 0,
                    rst: word & 8 != 0,
                },
                now + Duration::from_micros(step as u64),
            );
            if result.is_err() {
                assert_eq!(
                    before,
                    (tcp.aggregate_bytes(), tcp.aggregate_memory_charge())
                );
            }
        }
        assert!(fragments.aggregate_memory_charge() <= limits.max_aggregate_bytes);
        assert!(tcp.aggregate_memory_charge() <= limits.max_aggregate_bytes);
    }
    fragments.flush();
    tcp.flush();
    assert_eq!(
        (
            fragments.aggregate_bytes(),
            fragments.aggregate_memory_charge()
        ),
        (0, 0)
    );
    assert_eq!(
        (tcp.aggregate_bytes(), tcp.aggregate_memory_charge()),
        (0, 0)
    );
});
