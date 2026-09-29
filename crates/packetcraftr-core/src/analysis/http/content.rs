// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{Classification, Classified, Kind};
use std::io::{Read, Write};
#[derive(Debug, thiserror::Error)]
pub enum ContentDecodeError {
    #[error("unsupported HTTP content encoding {0}")]
    Unsupported(String),
    #[error("HTTP decoded content exceeds {limit} bytes")]
    Limit { limit: u64 },
    #[error("HTTP content decoding or output failed")]
    Io(#[from] std::io::Error),
}
impl Classified for ContentDecodeError {
    fn classification(&self) -> Classification {
        match self {
            Self::Unsupported(_) => {
                Classification::new("packet.http_content_encoding", Kind::Packet, None)
            }
            Self::Limit { .. } => {
                Classification::new("policy.http_content_limit", Kind::Policy, None)
            }
            Self::Io(_) => Classification::new("io.http_content", Kind::Io, None),
        }
    }
}
/// Stream gzip or zlib-wrapped deflate into a staged entity output, enforcing
/// a decoded-byte ceiling before every write. Encoded input remains the caller's.
pub fn decode_content(
    input: impl Read,
    mut output: impl Write,
    encoding: &str,
    maximum: u64,
) -> Result<u64, ContentDecodeError> {
    if maximum > 256 * 1024 * 1024 {
        return Err(ContentDecodeError::Limit { limit: maximum });
    }
    let encoding = encoding.trim().to_ascii_lowercase();
    let mut decoder: Box<dyn Read + '_> = match encoding.as_str() {
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(input)),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(input)),
        _ => return Err(ContentDecodeError::Unsupported(encoding)),
    };
    let mut buffer = [0_u8; 16 * 1024];
    let mut bytes = 0_u64;
    loop {
        let count = decoder.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let next = bytes
            .checked_add(count as u64)
            .filter(|next| *next <= maximum)
            .ok_or(ContentDecodeError::Limit { limit: maximum })?;
        output.write_all(&buffer[..count])?;
        bytes = next;
    }
    output.flush()?;
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gzip_and_zlib_decode_with_expansion_limit() {
        for gzip in [true, false] {
            let input = vec![b'a'; 1000];
            let encoded = if gzip {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&input).unwrap();
                encoder.finish().unwrap()
            } else {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&input).unwrap();
                encoder.finish().unwrap()
            };
            let encoding = if gzip { "gzip" } else { "deflate" };
            let mut output = Vec::new();
            assert_eq!(
                decode_content(encoded.as_slice(), &mut output, encoding, 1000).unwrap(),
                1000
            );
            assert_eq!(output, input);
            assert!(matches!(
                decode_content(encoded.as_slice(), Vec::new(), encoding, 999),
                Err(ContentDecodeError::Limit { .. })
            ));
            assert!(
                decode_content(&encoded[..encoded.len() / 2], Vec::new(), encoding, 1000).is_err()
            );
        }
    }
}
