use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::analysis::reassembly::Limits as ReassemblyLimits;
use packetcraftr_core::analysis::reassembly::ip::{
    Error, Fragment, FragmentDisposition, Ipv4DatagramKey, Ipv4Fragment, Ipv6DatagramKey,
    Ipv6Fragment, MalformedError, OverlapPolicy, PushOutcome, Reassembler,
};
use packetcraftr_core::analysis::scope::Interner;

const CONFIG_BYTES: usize = 5;
const RECORD_BYTES: usize = 7;
const MAX_RECORDS: usize = 32;
const MAX_FRAGMENT_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Coverage {
    pub(crate) completed: bool,
    pub(crate) overlap: bool,
}

pub(crate) fn run(data: &[u8]) -> Coverage {
    let config = |index: usize, fallback: u8| data.get(index).copied().unwrap_or(fallback);
    let ip_idle_expiry = if config(4, 4) == u8::MAX {
        Duration::MAX
    } else {
        Duration::from_millis(u64::from(config(4, 4) % 16).saturating_add(1))
    };
    let limits = ReassemblyLimits {
        max_ip_datagrams: usize::from(config(0, 3) % 4).saturating_add(1),
        max_ip_fragments_per_datagram: usize::from(config(1, 7) % 12).saturating_add(1),
        max_ip_bytes_per_datagram: usize::from(config(2, 15) % 32)
            .saturating_add(1)
            .saturating_mul(8),
        // Four conservatively charged datagram slots fit even at the floor;
        // the configurable span still explores aggregate-pressure failures.
        max_ip_aggregate_bytes: usize::from(config(3, 128))
            .saturating_mul(512)
            .saturating_add(24_576),
        max_ip_retained_outcomes: 8,
        ip_idle_expiry,
        ..ReassemblyLimits::default()
    };

    let mut intern = Interner::new();
    let scopes = [0_u32, 1, 2].map(|interface| {
        intern
            .intern(Some(interface), Vec::new())
            .expect("three bounded fixture scopes fit")
    });
    let mut reassemblers = [
        Reassembler::new(limits.clone(), OverlapPolicy::Reject),
        Reassembler::new(limits.clone(), OverlapPolicy::First),
        Reassembler::new(limits, OverlapPolicy::Last),
    ];
    let start = Instant::now();
    let mut cursor = CONFIG_BYTES.min(data.len());
    let mut record_number = 0usize;
    let mut coverage = Coverage::default();

    while record_number < MAX_RECORDS {
        let Some(record_end) = cursor.checked_add(RECORD_BYTES) else {
            break;
        };
        let Some(record) = data.get(cursor..record_end) else {
            break;
        };
        let control = record[0];
        let scope = scopes[usize::from(record[1]) % scopes.len()];
        let identification = u16::from_be_bytes([record[2], record[3]]);
        let fragment_offset = if control & 0x80 == 0 {
            u16::from(record[4] % 16)
        } else {
            u16::from_be_bytes([record[4], record[5]]) & 0x3fff
        };
        let mutation = record[5] % 8;
        let requested = usize::from(record[6]) % MAX_FRAGMENT_BYTES.saturating_add(1);
        let payload_start = record_end;
        let payload_end = payload_start
            .checked_add(requested)
            .unwrap_or(data.len())
            .min(data.len());
        let payload =
            Bytes::copy_from_slice(data.get(payload_start..payload_end).unwrap_or_default());
        cursor = payload_end;
        record_number = record_number.saturating_add(1);
        let more_fragments = control & 0x02 != 0;
        let fragment = if control & 0x01 == 0 {
            make_ipv4(
                scope,
                identification,
                fragment_offset,
                more_fragments,
                mutation,
                payload,
            )
        } else {
            make_ipv6(
                scope,
                u32::from(identification) << 16 | u32::from(record[1]),
                fragment_offset,
                more_fragments,
                mutation,
                payload,
            )
        };
        let now = start
            .checked_add(Duration::from_millis(
                u64::try_from(record_number).unwrap_or(u64::MAX),
            ))
            .unwrap_or(start);
        for reassembler in &mut reassemblers {
            observe(reassembler.push(fragment.clone(), now), &mut coverage);
            if control & 0x10 != 0 {
                let _ = reassembler.expire(now);
            }
            if control & 0x20 != 0 {
                let _ = reassembler.flush();
            }
        }
    }

    for reassembler in &mut reassemblers {
        let _ = reassembler.expire(start.checked_add(Duration::from_secs(60)).unwrap_or(start));
        let _ = reassembler.flush();
    }
    coverage
}

fn observe(result: Result<PushOutcome, Error>, coverage: &mut Coverage) {
    match result {
        Ok(PushOutcome::Accepted(fragment)) => note_disposition(&fragment.disposition, coverage),
        Ok(PushOutcome::Completed { fragment, .. }) => {
            coverage.completed = true;
            note_disposition(&fragment.disposition, coverage);
        }
        Err(Error::Malformed(MalformedError::ConflictingOverlap { .. })) => {
            coverage.overlap = true;
        }
        Err(_) => {}
    }
}

fn note_disposition(disposition: &FragmentDisposition, coverage: &mut Coverage) {
    if matches!(disposition, FragmentDisposition::OverlapResolved { .. }) {
        coverage.overlap = true;
    }
}

fn make_ipv4(
    scope: packetcraftr_core::analysis::scope::ScopeId,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
    mutation: u8,
    payload: Bytes,
) -> Fragment {
    let key = Ipv4DatagramKey {
        scope,
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        identification,
        protocol: 17,
    };
    let options = usize::from(mutation == 1) * 4;
    let header_length = 20usize.saturating_add(options);
    let total_length = u16::try_from(header_length.saturating_add(payload.len())).unwrap_or(0);
    let mut header = vec![0_u8; header_length];
    header[0] = 0x40 | u8::try_from(header_length / 4).unwrap_or(5);
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    let flags_offset = fragment_offset | if more_fragments { 0x2000 } else { 0 };
    header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    header[8] = 64;
    header[9] = key.protocol;
    header[12..16].copy_from_slice(&key.source.octets());
    header[16..20].copy_from_slice(&key.destination.octets());
    if options != 0 {
        header[20..24].copy_from_slice(&[1, 1, 0, 0]);
    }
    match mutation {
        2 => header[0] = 0x65,
        3 => header[2..4].copy_from_slice(&0_u16.to_be_bytes()),
        4 => header[6] ^= 0x20,
        5 => header[12] ^= 1,
        6 => header[0] = 0x4f,
        7 => header.truncate(12),
        _ => {}
    }
    if header.len() >= 12 {
        header[10..12].fill(0);
        let checksum = packetcraftr_core::protocol::checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
    Fragment::Ipv4(Ipv4Fragment {
        key,
        fragment_offset,
        more_fragments,
        header: Bytes::from(header),
        payload,
    })
}

fn make_ipv6(
    scope: packetcraftr_core::analysis::scope::ScopeId,
    identification: u32,
    fragment_offset: u16,
    more_fragments: bool,
    mutation: u8,
    payload: Bytes,
) -> Fragment {
    let key = Ipv6DatagramKey {
        scope,
        source: "2001:db8::1".parse::<Ipv6Addr>().expect("fixture source"),
        destination: "2001:db8::2"
            .parse::<Ipv6Addr>()
            .expect("fixture destination"),
        identification,
    };
    let extension = mutation == 1;
    let extension_length = usize::from(extension) * 8;
    let prefix_length = 40usize.saturating_add(extension_length);
    let declared = extension_length
        .saturating_add(8)
        .saturating_add(payload.len());
    let mut prefix = vec![0_u8; prefix_length];
    prefix[0] = 0x60;
    prefix[4..6].copy_from_slice(&u16::try_from(declared).unwrap_or(0).to_be_bytes());
    prefix[6] = if extension { 60 } else { 44 };
    prefix[7] = 64;
    prefix[8..24].copy_from_slice(&key.source.octets());
    prefix[24..40].copy_from_slice(&key.destination.octets());
    let mut predecessor_next_header_offset = 6usize;
    if extension {
        prefix[40] = 44;
        predecessor_next_header_offset = 40;
    }
    let mut next_header = 17;
    match mutation {
        2 => prefix[0] = 0x40,
        3 => prefix[4..6].copy_from_slice(&0_u16.to_be_bytes()),
        4 => predecessor_next_header_offset = 8,
        5 => {
            prefix[8] = 44;
            predecessor_next_header_offset = 8;
        }
        6 => next_header = 6,
        7 => prefix.truncate(32),
        _ => {}
    }
    Fragment::Ipv6(Ipv6Fragment {
        key,
        fragment_offset,
        more_fragments,
        next_header,
        unfragmentable_prefix: Bytes::from(prefix),
        predecessor_next_header_offset,
        payload,
    })
}
