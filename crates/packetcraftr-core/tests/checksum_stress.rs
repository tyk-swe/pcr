// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use packetcraftr_core::protocol::ChecksumAccumulator;

/// Reference RFC 1071 Internet Checksum implementation over a single contiguous slice.
fn reference_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        let word = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        sum += u64::from(word);
        i += 2;
    }
    if i < bytes.len() {
        let word = u16::from_be_bytes([bytes[i], 0]);
        sum += u64::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "sum is folded until sum >> 16 == 0, so sum <= 0xffff"
    )]
    fn truncate(sum: u64) -> u16 {
        sum as u16
    }
    !truncate(sum)
}

/// Reference RFC 1071 Internet Checksum over multiple parts (concatenated logically).
fn reference_checksum_parts(parts: &[&[u8]]) -> u16 {
    let concatenated: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    reference_checksum(&concatenated)
}

#[test]
fn test_empty_slices_and_combinations() {
    // Single empty slice
    let mut acc = ChecksumAccumulator::default();
    acc.add(&[]);
    assert_eq!(acc.finish(), reference_checksum(&[]));

    // Multiple empty slices
    let mut acc = ChecksumAccumulator::default();
    acc.add(&[]);
    acc.add(&[]);
    acc.add(&[]);
    assert_eq!(acc.finish(), reference_checksum_parts(&[&[], &[], &[]]));

    // Empty slices interleaved with data
    let mut acc = ChecksumAccumulator::default();
    acc.add(&[]);
    acc.add(&[0x12]);
    acc.add(&[]);
    acc.add(&[]);
    acc.add(&[0x34]);
    acc.add(&[]);
    assert_eq!(acc.finish(), reference_checksum(&[0x12, 0x34]));
}

#[test]
fn test_odd_length_buffers_and_single_byte_chunks() {
    let data = (0..255_u32)
        .map(|i| u8::try_from((i * 37) % 256).unwrap())
        .collect::<Vec<u8>>();

    // Test for various odd lengths
    for len in [1, 3, 5, 7, 9, 15, 31, 63, 127, 255] {
        let slice = &data[..len];
        let ref_val = reference_checksum(slice);

        let mut acc = ChecksumAccumulator::default();
        acc.add(slice);
        assert_eq!(acc.finish(), ref_val, "Failed for length {len}");

        // Feed 1 byte at a time
        let mut acc_byte_by_byte = ChecksumAccumulator::default();
        for &b in slice {
            acc_byte_by_byte.add(&[b]);
        }
        assert_eq!(
            acc_byte_by_byte.finish(),
            ref_val,
            "Failed for byte-by-byte length {len}"
        );
    }
}

#[test]
fn test_all_partition_splits_up_to_length_40() {
    for len in 0..=40_usize {
        let data: Vec<u8> = (0..len)
            .map(|i| u8::try_from((i * 13 + 7) % 256).unwrap())
            .collect();
        let ref_val = reference_checksum(&data);

        // 1-cut (2 parts)
        for i in 0..=len {
            let part1 = &data[..i];
            let part2 = &data[i..];

            let mut acc = ChecksumAccumulator::default();
            acc.add(part1);
            acc.add(part2);
            assert_eq!(
                acc.finish(),
                ref_val,
                "Failed for 1-cut len {len} at split {i}"
            );
        }

        // 2-cut (3 parts)
        for i in 0..=len {
            for j in i..=len {
                let part1 = &data[..i];
                let part2 = &data[i..j];
                let part3 = &data[j..];

                let mut acc = ChecksumAccumulator::default();
                acc.add(part1);
                acc.add(part2);
                acc.add(part3);
                assert_eq!(
                    acc.finish(),
                    ref_val,
                    "Failed for 2-cut len {len} at splits {i},{j}"
                );
            }
        }
    }
}

#[test]
fn test_overflow_and_large_buffers() {
    // 1 MB of 0xFF -> tests sum exceeding u32::MAX and 64-bit carry accumulation
    let large_data = vec![0xff; 1_000_000];
    let ref_val = reference_checksum(&large_data);

    let mut acc = ChecksumAccumulator::default();
    acc.add(&large_data);
    assert_eq!(acc.finish(), ref_val);

    // Split 1MB into chunks of 10007 bytes (prime number length, odd)
    let mut acc_chunked = ChecksumAccumulator::default();
    for chunk in large_data.chunks(10007) {
        acc_chunked.add(chunk);
    }
    assert_eq!(acc_chunked.finish(), ref_val);
}

#[test]
fn test_special_checksum_values() {
    // [0xff, 0xff] -> sum = 0xffff -> complement is 0x0000
    let mut acc = ChecksumAccumulator::default();
    acc.add(&[0xff, 0xff]);
    assert_eq!(acc.finish(), 0x0000);

    // [0x00, 0x00] -> sum = 0x0000 -> complement is 0xffff
    let mut acc = ChecksumAccumulator::default();
    acc.add(&[0x00, 0x00]);
    assert_eq!(acc.finish(), 0xffff);

    // Multiple 0xffff pairs
    let mut acc = ChecksumAccumulator::default();
    acc.add(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(acc.finish(), 0x0000);
}

#[test]
fn test_fuzz_random_chunk_patterns() {
    // Deterministic pseudo-random generation using Xorshift32
    let mut state: u32 = 0xdeadbeef;
    let mut rand_u32 = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };

    for test_idx in 0..1000 {
        let total_len = (rand_u32() % 500) as usize;
        let data: Vec<u8> = (0..total_len)
            .map(|_| u8::try_from(rand_u32() % 256).unwrap())
            .collect();
        let ref_val = reference_checksum(&data);

        // Partition into random chunk sizes (0 to 50 bytes each)
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < total_len {
            let chunk_len = (rand_u32() % 51) as usize;
            let end = (offset + chunk_len).min(total_len);
            chunks.push(&data[offset..end]);
            offset = end;
            if rand_u32() % 5 == 0 {
                // Occasionally inject empty slice
                chunks.push(&[]);
            }
        }

        let mut acc = ChecksumAccumulator::default();
        for chunk in &chunks {
            acc.add(chunk);
        }
        assert_eq!(
            acc.finish(),
            ref_val,
            "Fuzz test iteration {test_idx} failed for total_len {total_len}"
        );
    }
}
