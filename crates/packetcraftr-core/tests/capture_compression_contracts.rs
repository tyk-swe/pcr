// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use packetcraftr_core::capture_file::compression::{Error, Format, Input, Limits, Output};
use std::io::{self, Cursor, Read, Write};

fn compressed(format: Format, bytes: &[u8]) -> Vec<u8> {
    let mut encoder = Output::new(Vec::new(), format).unwrap();
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
struct OneByte(Cursor<Vec<u8>>);
impl Read for OneByte {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = bytes.len().min(1);
        self.0.read(&mut bytes[..length])
    }
}

fn compression_cause(error: &io::Error) -> Option<&Error> {
    match error.get_ref()?.downcast_ref::<Error>()? {
        Error::Io { source, .. } => compression_cause(source),
        cause => Some(cause),
    }
}

#[test]
fn expansion_and_encoded_source_limits_fail_without_exposing_excess_bytes() {
    for format in [Format::None, Format::Gzip, Format::Zstd] {
        let encoded = compressed(format, &vec![0; 1024 * 1024]);
        let mut input = Input::new(
            Cursor::new(encoded.clone()),
            Limits {
                max_decoded_bytes: 32,
                ..Default::default()
            },
        )
        .unwrap();
        let mut decoded = Vec::new();
        let error = input.read_to_end(&mut decoded).unwrap_err();
        assert!(matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<Error>()),
            Some(Error::ByteLimit { limit: 32 })
        ));
        assert_eq!(decoded.len(), 32);
        assert!(input.read(&mut [0u8; 1]).is_err());
        let mut input = Input::new(
            Cursor::new(encoded),
            Limits {
                max_encoded_bytes: 4,
                ..Default::default()
            },
        )
        .unwrap();
        let error = input.read_to_end(&mut Vec::new()).unwrap_err();
        assert!(matches!(
            compression_cause(&error),
            Some(Error::EncodedByteLimit { limit: 4 })
        ));
    }
    let mut encoded = compressed(Format::Gzip, b"");
    encoded.extend(compressed(Format::Gzip, b""));
    let mut input = Input::new(
        Cursor::new(encoded),
        Limits {
            max_encoded_bytes: 21,
            ..Default::default()
        },
    )
    .unwrap();
    let error = input.read_to_end(&mut Vec::new()).unwrap_err();
    assert!(matches!(
        compression_cause(&error),
        Some(Error::EncodedByteLimit { limit: 21 })
    ));
}

#[test]
fn truncated_compressed_data_and_hostile_zstd_windows_are_rejected() {
    for format in [Format::Gzip, Format::Zstd] {
        let mut encoded = compressed(format, b"capture payload");
        encoded.pop();
        let mut input = Input::new(Cursor::new(encoded), Default::default()).unwrap();
        let error = input.read_to_end(&mut Vec::new()).unwrap_err();
        assert!(
            matches!(
                error.get_ref().and_then(|source| source.downcast_ref::<Error>()),
                Some(Error::Io { format: actual, source })
                    if *actual == format && source.kind() == io::ErrorKind::UnexpectedEof
            ),
            "{error:?}"
        );
    }
    // RFC 8878: descriptor 0, window exponent 17 => 128 MiB, empty last raw block.
    let hostile = [0x28, 0xb5, 0x2f, 0xfd, 0, 0x88, 1, 0, 0];
    let mut input = Input::new(Cursor::new(hostile), Default::default()).unwrap();
    assert_eq!(input.format(), Format::Zstd);
    assert!(input.read_to_end(&mut Vec::new()).is_err());
}
