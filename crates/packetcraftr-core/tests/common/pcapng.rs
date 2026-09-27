// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Hand-built pcapng and classic capture fixtures shared by the capture
//! fidelity contracts.

use packetcraftr_core::capture_file::Endianness;

pub(crate) fn u16_bytes(endianness: Endianness, value: u16) -> [u8; 2] {
    match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    }
}

pub(crate) fn u32_bytes(endianness: Endianness, value: u32) -> [u8; 4] {
    match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    }
}

pub(crate) fn i64_bytes(endianness: Endianness, value: i64) -> [u8; 8] {
    match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    }
}

pub(crate) fn option(endianness: Endianness, code: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u16_bytes(endianness, code));
    bytes.extend_from_slice(&u16_bytes(
        endianness,
        u16::try_from(value.len()).expect("test option length fits u16"),
    ));
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

pub(crate) fn end_options(endianness: Endianness, options: &mut Vec<u8>) {
    options.extend_from_slice(&u16_bytes(endianness, 0));
    options.extend_from_slice(&u16_bytes(endianness, 0));
}

pub(crate) fn block(endianness: Endianness, block_type: u32, body: &[u8]) -> Vec<u8> {
    assert!(body.len().is_multiple_of(4));
    let length = u32::try_from(body.len() + 12).expect("test block length fits u32");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u32_bytes(endianness, block_type));
    bytes.extend_from_slice(&u32_bytes(endianness, length));
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&u32_bytes(endianness, length));
    bytes
}

pub(crate) fn section(endianness: Endianness, comment: &[u8]) -> Vec<u8> {
    let mut options = option(endianness, 1, comment);
    end_options(endianness, &mut options);
    let mut body = Vec::new();
    body.extend_from_slice(match endianness {
        Endianness::Little => &[0x4d, 0x3c, 0x2b, 0x1a],
        Endianness::Big => &[0x1a, 0x2b, 0x3c, 0x4d],
    });
    body.extend_from_slice(&u16_bytes(endianness, 1));
    body.extend_from_slice(&u16_bytes(endianness, 0));
    body.extend_from_slice(&i64_bytes(endianness, -1));
    body.extend_from_slice(&options);
    block(endianness, 0x0a0d_0d0a, &body)
}

pub(crate) fn idb(endianness: Endianness) -> Vec<u8> {
    let mut options = Vec::new();
    for (code, value) in [
        (1, b"interface comment".as_slice()),
        (2, b"eth-source".as_slice()),
        (3, b"interface description".as_slice()),
        (11, b"tcp port 443".as_slice()),
        (12, b"TestOS".as_slice()),
        (15, b"TestHardware".as_slice()),
        (0x7777, b"unknown-idb".as_slice()),
    ] {
        options.extend_from_slice(&option(endianness, code, value));
    }
    options.extend_from_slice(&option(endianness, 9, &[6]));
    end_options(endianness, &mut options);
    let mut body = Vec::new();
    body.extend_from_slice(&u16_bytes(endianness, 1));
    body.extend_from_slice(&u16_bytes(endianness, 0));
    body.extend_from_slice(&u32_bytes(endianness, 65_535));
    body.extend_from_slice(&options);
    block(endianness, 1, &body)
}

pub(crate) fn epb(endianness: Endianness, ticks: u64) -> Vec<u8> {
    let mut options = option(endianness, 1, b"packet comment");
    options.extend_from_slice(&option(endianness, 2, &u32_bytes(endianness, 1)));
    options.extend_from_slice(&option(endianness, 0x7778, b"unknown-epb"));
    options.extend_from_slice(&option(endianness, 2_988, b"custom-epb"));
    end_options(endianness, &mut options);
    let mut body = Vec::new();
    body.extend_from_slice(&u32_bytes(endianness, 0));
    body.extend_from_slice(&u32_bytes(endianness, (ticks >> 32) as u32));
    body.extend_from_slice(&u32_bytes(
        endianness,
        u32::try_from(ticks).expect("fixture timestamp fits the low word"),
    ));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&[0xaa, 0, 0, 0]);
    body.extend_from_slice(&options);
    block(endianness, 6, &body)
}

pub(crate) fn obsolete_packet(endianness: Endianness) -> Vec<u8> {
    let mut options = option(endianness, 1, b"obsolete");
    end_options(endianness, &mut options);
    let mut body = Vec::new();
    body.extend_from_slice(&u16_bytes(endianness, 0));
    body.extend_from_slice(&u16_bytes(endianness, 7));
    body.extend_from_slice(&u32_bytes(endianness, 0));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&[0xbb, 0, 0, 0]);
    body.extend_from_slice(&options);
    block(endianness, 2, &body)
}

pub(crate) fn simple_packet(endianness: Endianness) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&[0xcc, 0, 0, 0]);
    block(endianness, 3, &body)
}

pub(crate) fn metadata_block(endianness: Endianness, block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut padded = body.to_vec();
    padded.resize(padded.len().next_multiple_of(4), 0);
    block(endianness, block_type, &padded)
}

pub(crate) fn adversarial_pcapng() -> Vec<u8> {
    let mut bytes = section(Endianness::Little, b"first section");
    bytes.extend_from_slice(&idb(Endianness::Little));
    bytes.extend_from_slice(&epb(Endianness::Little, 0));
    bytes.extend_from_slice(&simple_packet(Endianness::Little));
    bytes.extend_from_slice(&obsolete_packet(Endianness::Little));
    bytes.extend_from_slice(&metadata_block(Endianness::Little, 4, &[0, 0, 0, 0]));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        5,
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        0x0000_0bad,
        &[1, 2, 3, 4, 5],
    ));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        0x4000_0bad,
        &[6, 7, 8, 9],
    ));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        0x1234_5678,
        &[9, 8, 7, 6],
    ));
    bytes.extend_from_slice(&section(Endianness::Big, b"second section"));
    bytes.extend_from_slice(&idb(Endianness::Big));
    bytes.extend_from_slice(&epb(Endianness::Big, 0));
    bytes
}

pub(crate) fn classic(endianness: Endianness, network: u32) -> Vec<u8> {
    let mut bytes = match endianness {
        Endianness::Little => vec![0xd4, 0xc3, 0xb2, 0xa1],
        Endianness::Big => vec![0xa1, 0xb2, 0xc3, 0xd4],
    };
    bytes.extend_from_slice(&u16_bytes(endianness, 2));
    bytes.extend_from_slice(&u16_bytes(endianness, 4));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 65_535));
    bytes.extend_from_slice(&u32_bytes(endianness, network));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 1));
    bytes.extend_from_slice(&u32_bytes(endianness, 1));
    bytes.push(0xdd);
    bytes
}
