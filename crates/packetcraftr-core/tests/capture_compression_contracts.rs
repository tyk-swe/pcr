// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
fn format_detection_and_concatenated_members_preserve_every_decoded_byte() {
    for format in [Format::None, Format::Gzip, Format::Zstd] {
        let mut encoded = compressed(format, b"first");
        encoded.extend(compressed(format, b"second"));
        let mut input = Input::new(
            OneByte(Cursor::new(encoded)),
            Limits {
                max_decoded_bytes: 11,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(input.format(), format);
        let mut decoded = Vec::new();
        input.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"firstsecond");
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

#[test]
fn finalization_reports_underlying_flush_errors() {
    struct FailsFlush;
    impl Write for FailsFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("fixture flush failure"))
        }
    }
    for format in [Format::None, Format::Gzip, Format::Zstd] {
        let mut output = Output::new(FailsFlush, format).unwrap();
        output.write_all(b"capture").unwrap();
        assert!(matches!(output.finish(), Err(Error::Io { .. })));
    }
}

#[test]
fn short_and_interrupted_prefixes_stay_plain_and_are_bounded_by_the_encoded_limit() {
    struct Flaky(Cursor<Vec<u8>>, bool);
    impl Read for Flaky {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.1) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let length = bytes.len().min(1);
            self.0.read(&mut bytes[..length])
        }
    }
    for bytes in [&b""[..], b"a", b"abc", b"abcd", b"abcde"] {
        let mut input =
            Input::new(Flaky(Cursor::new(bytes.to_vec()), true), Default::default()).unwrap();
        assert_eq!(input.format(), Format::None);
        let mut decoded = Vec::new();
        input.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, bytes);
    }
    let limits = Limits {
        max_encoded_bytes: 2,
        ..Default::default()
    };
    let Err(Error::Io {
        format: Format::None,
        source,
    }) = Input::new(Cursor::new(b"abcdefgh"), limits)
    else {
        panic!("prefix beyond the encoded limit must fail construction");
    };
    assert!(matches!(
        compression_cause(&source),
        Some(Error::EncodedByteLimit { limit: 2 })
    ));
}
