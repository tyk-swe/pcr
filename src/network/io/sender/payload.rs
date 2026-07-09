// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File};
use std::io::Read;

use rand::RngExt;

use crate::domain::spec::PayloadSource;
use crate::network::sender::error::{PayloadError, Result};

const MAX_PAYLOAD_SIZE: u64 = 10 * 1024 * 1024; // 10MB

fn ensure_payload_size(size: u64) -> Result<()> {
    if size > MAX_PAYLOAD_SIZE {
        return Err(PayloadError::PayloadTooLarge {
            size,
            limit: MAX_PAYLOAD_SIZE,
        }
        .into());
    }

    Ok(())
}

pub(crate) fn prepare_payload(source: &PayloadSource) -> Result<Vec<u8>> {
    Ok(match source {
        PayloadSource::Empty => Vec::new(),
        PayloadSource::Inline(data) => {
            let bytes = data.as_bytes();
            ensure_payload_size(bytes.len() as u64)?;
            bytes.to_vec()
        }
        PayloadSource::Hex(hex) => decode_hex_payload(hex)?,
        PayloadSource::File(path) => {
            let metadata = fs::metadata(path).map_err(|source| PayloadError::ReadFile {
                path: path.clone(),
                source,
            })?;

            ensure_payload_size(metadata.len())?;

            let file = File::open(path).map_err(|source| PayloadError::ReadFile {
                path: path.clone(),
                source,
            })?;

            let mut reader = file.take(MAX_PAYLOAD_SIZE + 1);
            let mut buffer = Vec::with_capacity(metadata.len() as usize);
            reader
                .read_to_end(&mut buffer)
                .map_err(|source| PayloadError::ReadFile {
                    path: path.clone(),
                    source,
                })?;

            if buffer.len() as u64 > MAX_PAYLOAD_SIZE {
                return Err(PayloadError::PayloadTooLarge {
                    size: buffer.len() as u64,
                    limit: MAX_PAYLOAD_SIZE,
                }
                .into());
            }

            buffer
        }
        PayloadSource::Random(size) => {
            ensure_payload_size(*size as u64)?;
            let mut rng = rand::rng();
            let mut buf = vec![0u8; *size];
            rng.fill(&mut buf[..]);
            buf
        }
        PayloadSource::Dns { query, record_type } => {
            let (bytes, _) = crate::network::dns::build_dns_query(query, record_type, None)
                .map_err(|e| PayloadError::InvalidInput(e.to_string()))?;
            ensure_payload_size(bytes.len() as u64)?;
            bytes
        }
        PayloadSource::Http { method, path, host } => {
            build_http_payload(method, path, host.as_deref())?
        }
        PayloadSource::TlsClientHello { server_name } => {
            build_tls_client_hello_payload(server_name)?
        }
        #[cfg(any(test, feature = "fuzz"))]
        PayloadSource::Bytes(b) => {
            ensure_payload_size(b.len() as u64)?;
            b.clone()
        }
    })
}

fn build_http_payload(method: &str, path: &str, host: Option<&str>) -> Result<Vec<u8>> {
    let mut payload = format!("{} {} HTTP/1.1\r\n", method.to_uppercase(), path);
    if let Some(h) = host {
        payload.push_str(&format!("Host: {}\r\n", h));
    }
    payload.push_str("User-Agent: PacketcraftR\r\n");
    payload.push_str("Accept: */*\r\n");
    // Add Connection: close to be polite
    payload.push_str("Connection: close\r\n");
    payload.push_str("\r\n");

    let bytes = payload.into_bytes();
    ensure_payload_size(bytes.len() as u64)?;
    Ok(bytes)
}

fn build_tls_client_hello_payload(server_name: &str) -> Result<Vec<u8>> {
    let server_name = server_name.trim();
    if server_name.is_empty() {
        return Err(
            PayloadError::InvalidInput("TLS Client Hello requires a non-empty SNI".into()).into(),
        );
    }

    let server_name_bytes = server_name.as_bytes();

    // Validate SNI hostname length fits in u16
    let sni_len = u16::try_from(server_name_bytes.len())
        .map_err(|_| PayloadError::InvalidInput("SNI hostname too long".into()))?;

    let mut handshake = Vec::new();

    // Minimal ClientHello (TLS 1.2, random, empty session ID, limited suites, null compression, SNI)
    let mut client_hello = Vec::new();

    client_hello.extend_from_slice(&0x0303u16.to_be_bytes()); // Client Version

    // Random: 32 bytes (random-only for simplicity)
    let mut rng = rand::rng();
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    client_hello.extend_from_slice(&random);

    client_hello.push(0); // Session ID Length: 0

    // Common cipher suites (ECDHE/ECDSA|RSA with AES-GCM or CHACHA20)
    let cipher_suites = [0xc02b, 0xc02f, 0x009e, 0xcc14, 0xcc13];
    let cipher_suites_data_len = u16::try_from(
        cipher_suites
            .len()
            .checked_mul(2)
            .ok_or_else(|| PayloadError::InvalidInput("cipher suites length overflow".into()))?,
    )
    .map_err(|_| PayloadError::InvalidInput("cipher suites length too large".into()))?;
    client_hello.extend_from_slice(&cipher_suites_data_len.to_be_bytes());
    for suite in cipher_suites {
        let suite_u16: u16 = suite;
        client_hello.extend_from_slice(&suite_u16.to_be_bytes());
    }

    // Compression Methods: 1 method (null = 0)
    client_hello.push(1);
    client_hello.push(0);

    let mut extensions = Vec::new();

    // Server Name Indication (SNI)
    // SNI list length = hostname length + 3 (type + length field + hostname)
    let sni_list_len = sni_len
        .checked_add(3)
        .ok_or_else(|| PayloadError::InvalidInput("SNI extension length overflow".into()))?;

    let mut sni_data = Vec::new();
    sni_data.extend_from_slice(&sni_list_len.to_be_bytes()); // List length
    sni_data.push(0); // Host name type
    sni_data.extend_from_slice(&sni_len.to_be_bytes());
    sni_data.extend_from_slice(server_name_bytes);

    let sni_ext_len = u16::try_from(sni_data.len())
        .map_err(|_| PayloadError::InvalidInput("SNI extension too large".into()))?;
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
    extensions.extend_from_slice(&sni_data);

    // Append extensions
    let extensions_len = u16::try_from(extensions.len())
        .map_err(|_| PayloadError::InvalidInput("total extensions length too large".into()))?;
    client_hello.extend_from_slice(&extensions_len.to_be_bytes());
    client_hello.extend_from_slice(&extensions);

    // Handshake: Client Hello + length
    handshake.push(1);
    let client_hello_len = client_hello.len();
    if client_hello_len > 0xFFFFFF {
        return Err(PayloadError::InvalidInput("ClientHello length exceeds maximum".into()).into());
    }
    handshake.push(((client_hello_len >> 16) & 0xFF) as u8);
    handshake.push(((client_hello_len >> 8) & 0xFF) as u8);
    handshake.push((client_hello_len & 0xFF) as u8);
    handshake.extend_from_slice(&client_hello);

    // TLS record layer
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // Version TLS 1.0 for compatibility
    let record_payload_len = u16::try_from(handshake.len())
        .map_err(|_| PayloadError::InvalidInput("TLS record payload too large".into()))?;
    record.extend_from_slice(&record_payload_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    ensure_payload_size(record.len() as u64)?;
    Ok(record)
}

fn decode_hex_payload(hex: &str) -> Result<Vec<u8>> {
    let decoded_len = validate_hex_payload_len(hex)?;
    let mut bytes = Vec::with_capacity(decoded_len);
    let mut high_nibble: Option<u8> = None;

    for &byte in hex.as_bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }

        let nibble = hex_nibble(byte)?;

        if let Some(h) = high_nibble {
            bytes.push((h << 4) | nibble);
            high_nibble = None;
        } else {
            high_nibble = Some(nibble);
        }
    }

    debug_assert!(high_nibble.is_none());
    debug_assert_eq!(bytes.len(), decoded_len);
    Ok(bytes)
}

fn validate_hex_payload_len(hex: &str) -> Result<usize> {
    let mut digit_count = 0u64;

    for &byte in hex.as_bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }

        let _ = hex_nibble(byte)?;
        digit_count += 1;

        if digit_count > MAX_PAYLOAD_SIZE.saturating_mul(2) {
            return Err(PayloadError::PayloadTooLarge {
                size: digit_count.div_ceil(2),
                limit: MAX_PAYLOAD_SIZE,
            }
            .into());
        }
    }

    if !digit_count.is_multiple_of(2) {
        return Err(PayloadError::HexLength.into());
    }

    Ok((digit_count / 2) as usize)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PayloadError::InvalidHexByte { byte }.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::sender::error::SenderError;
    use std::fs;

    #[test]
    fn prepare_payload_decodes_hex_with_whitespace_and_case() {
        let payload = prepare_payload(&PayloadSource::Hex("de AD\nbe ef".to_string())).unwrap();

        assert_eq!(payload, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn prepare_payload_rejects_odd_length_hex() {
        let err = prepare_payload(&PayloadSource::Hex("abc".to_string())).unwrap_err();

        assert!(matches!(err, SenderError::Payload(PayloadError::HexLength)));
    }

    #[test]
    fn prepare_payload_rejects_invalid_hex_byte() {
        let err = prepare_payload(&PayloadSource::Hex("00xz".to_string())).unwrap_err();

        assert!(matches!(
            err,
            SenderError::Payload(PayloadError::InvalidHexByte { byte: b'x' })
        ));
    }

    #[test]
    fn prepare_payload_rejects_oversized_hex_before_allocating_payload() {
        let hex = "00".repeat(MAX_PAYLOAD_SIZE as usize + 1);
        let err = prepare_payload(&PayloadSource::Hex(hex)).unwrap_err();

        assert!(matches!(
            err,
            SenderError::Payload(PayloadError::PayloadTooLarge { size, limit })
                if size == MAX_PAYLOAD_SIZE + 1 && limit == MAX_PAYLOAD_SIZE
        ));
    }

    #[test]
    fn validate_hex_payload_len_ignores_large_whitespace_without_payload_allocation() {
        let whitespace = " \n\t".repeat(1024 * 1024);

        assert_eq!(validate_hex_payload_len(&whitespace).unwrap(), 0);
    }

    #[test]
    fn prepare_payload_builds_http_request_with_defaults() {
        let payload = prepare_payload(&PayloadSource::Http {
            method: "get".to_string(),
            path: "/health".to_string(),
            host: Some("example.test".to_string()),
        })
        .unwrap();
        let text = String::from_utf8(payload).unwrap();

        assert!(text.starts_with("GET /health HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.test\r\n"));
        assert!(text.contains("User-Agent: PacketcraftR\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn prepare_payload_builds_tls_client_hello_containing_sni() {
        let payload = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: "example.test".to_string(),
        })
        .unwrap();

        assert_eq!(payload[0], 0x16);
        assert!(payload
            .windows("example.test".len())
            .any(|window| window == b"example.test"));
    }

    #[test]
    fn prepare_payload_rejects_blank_tls_sni() {
        let err = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: "  ".to_string(),
        })
        .unwrap_err();

        assert!(matches!(
            err,
            SenderError::Payload(PayloadError::InvalidInput(message))
                if message.contains("non-empty SNI")
        ));
    }

    #[test]
    fn prepare_payload_reads_file_source() {
        let path = std::env::temp_dir().join(format!(
            "packetcraftr-payload-test-{}-{}.bin",
            std::process::id(),
            "read"
        ));
        fs::write(&path, b"from-file").unwrap();

        let payload = prepare_payload(&PayloadSource::File(path.clone())).unwrap();

        assert_eq!(payload, b"from-file");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn prepare_payload_rejects_oversized_random_payload_before_allocating() {
        let err =
            prepare_payload(&PayloadSource::Random((MAX_PAYLOAD_SIZE + 1) as usize)).unwrap_err();

        assert!(matches!(
            err,
            SenderError::Payload(PayloadError::PayloadTooLarge { size, limit })
                if size == MAX_PAYLOAD_SIZE + 1 && limit == MAX_PAYLOAD_SIZE
        ));
    }

    #[test]
    fn prepare_payload_preserves_bytes_source() {
        let payload = prepare_payload(&PayloadSource::Bytes(vec![1, 2, 3])).unwrap();

        assert_eq!(payload, [1, 2, 3]);
    }

    #[test]
    fn prepare_payload_builds_dns_query_bytes() {
        let payload = prepare_payload(&PayloadSource::Dns {
            query: "example.test".to_string(),
            record_type: "AAAA".to_string(),
        })
        .unwrap();

        assert!(payload.len() > 12);
        assert!(payload
            .windows("example".len())
            .any(|window| window == b"example"));
    }
}
