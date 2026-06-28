// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File};
use std::io::Read;

use rand::Rng;

use crate::engine::spec::PayloadSource;
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
            let mut rng = rand::thread_rng();
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
    let mut rng = rand::thread_rng();
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
    // Decode in single pass to avoid allocation; heuristic: start with half length (upper bound)
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut high_nibble: Option<u8> = None;
    let mut current_size: u64 = 0;

    for &byte in hex.as_bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }

        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(PayloadError::InvalidHexByte { byte }.into()),
        };

        if let Some(h) = high_nibble {
            current_size += 1;
            // Check size limit incrementally
            if current_size > MAX_PAYLOAD_SIZE {
                return Err(PayloadError::PayloadTooLarge {
                    size: current_size,
                    limit: MAX_PAYLOAD_SIZE,
                }
                .into());
            }

            bytes.push((h << 4) | nibble);
            high_nibble = None;
        } else {
            high_nibble = Some(nibble);
        }
    }

    if high_nibble.is_some() {
        return Err(PayloadError::HexLength.into());
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    use super::*;

    use crate::network::sender::error::{PayloadError, SenderError};

    #[test]
    fn inline_hex_payload_is_decoded() {
        let bytes = prepare_payload(&PayloadSource::Hex("41 42 43".into()))
            .expect("hex payload should decode");
        assert_eq!(bytes, b"ABC");
    }

    #[test]
    fn invalid_hex_payload_returns_error() {
        let result = prepare_payload(&PayloadSource::Hex("ABC".into()));
        assert!(result.is_err());
    }

    #[test]
    fn empty_payload_returns_empty_vec() {
        let bytes = prepare_payload(&PayloadSource::Empty).expect("empty payload should work");
        assert_eq!(bytes, Vec::<u8>::new());
    }

    #[test]
    fn inline_payload_converts_string_to_bytes() {
        let bytes = prepare_payload(&PayloadSource::Inline("Hello World".into()))
            .expect("inline payload should work");
        assert_eq!(bytes, b"Hello World");
    }

    #[test]
    fn random_payload_generates_correct_size() {
        let size = 128;
        let bytes =
            prepare_payload(&PayloadSource::Random(size)).expect("random payload should work");
        assert_eq!(bytes.len(), size);
    }

    #[test]
    fn hex_payload_handles_no_whitespace() {
        let bytes = prepare_payload(&PayloadSource::Hex("414243".into()))
            .expect("hex payload without spaces should work");
        assert_eq!(bytes, b"ABC");
    }

    #[test]
    fn hex_payload_handles_mixed_whitespace() {
        let bytes = prepare_payload(&PayloadSource::Hex("41 42\t43\n44".into()))
            .expect("hex payload with mixed whitespace should work");
        assert_eq!(bytes, b"ABCD");
    }

    #[test]
    fn hex_payload_rejects_odd_length() {
        let result = prepare_payload(&PayloadSource::Hex("4142A".into()));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("even number"));
    }

    #[test]
    fn hex_payload_rejects_invalid_chars() {
        let result = prepare_payload(&PayloadSource::Hex("41ZZ".into()));
        assert!(result.is_err());
    }

    #[test]
    fn file_payload_fails_for_nonexistent_file() {
        let result = prepare_payload(&PayloadSource::File(PathBuf::from(
            "/nonexistent/file/path.bin",
        )));
        assert!(result.is_err());
    }

    #[test]
    fn decode_hex_payload_works_for_lowercase() {
        let bytes = decode_hex_payload("aabbcc").expect("lowercase hex should work");
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn tls_client_hello_rejects_empty_server_name() {
        let err = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: "   ".into(),
        })
        .expect_err("empty SNI should be rejected");

        match err {
            SenderError::Payload(PayloadError::InvalidInput(msg)) => {
                assert!(msg.contains("non-empty"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn decode_hex_payload_works_for_uppercase() {
        let bytes = decode_hex_payload("AABBCC").expect("uppercase hex should work");
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn decode_hex_payload_works_for_mixed_case() {
        let bytes = decode_hex_payload("AaBbCc").expect("mixed case hex should work");
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn file_payload_checks_size_limit() {
        // We can't easily create a 10MB+ file here without being slow/wasteful.
        // But we can check if it reads a small file correctly.
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "Hello File").expect("write");
        let path = file.path().to_path_buf();
        let bytes = prepare_payload(&PayloadSource::File(path)).expect("small file should work");
        assert_eq!(bytes, b"Hello File\n");
    }

    #[test]
    fn inline_payload_over_limit_returns_error() {
        let oversized = "A".repeat(MAX_PAYLOAD_SIZE as usize + 1);
        let err = prepare_payload(&PayloadSource::Inline(oversized)).unwrap_err();
        assert!(matches!(
            err,
            SenderError::Payload(PayloadError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn random_payload_over_limit_returns_error() {
        let err =
            prepare_payload(&PayloadSource::Random(MAX_PAYLOAD_SIZE as usize + 1)).unwrap_err();
        assert!(matches!(
            err,
            SenderError::Payload(PayloadError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn hex_payload_over_limit_returns_error() {
        let oversized_hex = "AA".repeat(MAX_PAYLOAD_SIZE as usize + 1);
        let err = prepare_payload(&PayloadSource::Hex(oversized_hex)).unwrap_err();
        assert!(matches!(
            err,
            SenderError::Payload(PayloadError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn http_payload_generation_defaults() {
        let bytes = prepare_payload(&PayloadSource::Http {
            method: "GET".into(),
            path: "/".into(),
            host: None,
        })
        .expect("http payload");

        let s = std::str::from_utf8(&bytes).expect("utf8");
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("User-Agent: PacketcraftR\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn http_payload_generation_with_host() {
        let bytes = prepare_payload(&PayloadSource::Http {
            method: "POST".into(),
            path: "/api/v1".into(),
            host: Some("example.com".into()),
        })
        .expect("http payload");

        let s = std::str::from_utf8(&bytes).expect("utf8");
        assert!(s.starts_with("POST /api/v1 HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
    }

    #[test]
    fn tls_client_hello_basic_structure() {
        let bytes = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: "example.com".into(),
        })
        .expect("tls payload");

        // Content Type: Handshake (22 -> 0x16)
        assert_eq!(bytes[0], 0x16);
        // Version: TLS 1.0 (0x03, 0x01) for record layer
        assert_eq!(bytes[1], 0x03);
        assert_eq!(bytes[2], 0x01);

        // Record length (2 bytes)
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        assert_eq!(bytes.len(), 5 + record_len);

        // Handshake Type: Client Hello (1)
        assert_eq!(bytes[5], 0x01);

        // Handshake Length (3 bytes)
        // bytes[6..9]

        // Client Version (TLS 1.2 -> 0x0303)
        assert_eq!(bytes[9], 0x03);
        assert_eq!(bytes[10], 0x03);

        // Check for SNI in extensions (simplified check)
        // "example.com" is 11 bytes.
        let sni_bytes = b"example.com";
        assert!(bytes
            .windows(sni_bytes.len())
            .any(|window| window == sni_bytes));
    }

    #[test]
    fn tls_client_hello_rejects_empty_sni() {
        let result = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: "".into(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn dns_payload_integration() {
        // This tests that PayloadSource::Dns calls into dns::build_dns_query correctly
        let bytes = prepare_payload(&PayloadSource::Dns {
            query: "example.org".into(),
            record_type: "A".into(),
        })
        .expect("dns payload");

        // Basic DNS header check (Transaction ID at bytes 0-1)
        // Flags at 2-3 (Standard Query + Recursion Desired = 0x0100)
        assert_eq!(bytes[2], 0x01);
        assert_eq!(bytes[3], 0x00);

        // Question count = 1
        assert_eq!(bytes[4], 0x00);
        assert_eq!(bytes[5], 0x01);

        // "example" (7) ... "org" (3)
        // Just spot check presence of "example"
        assert!(bytes.windows(7).any(|window| window == b"example"));
    }

    #[test]
    fn tls_client_hello_boundary_valid_hostname() {
        // Fixed overhead before hostname:
        // version(2) + random(32) + session_id_len(1) + cipher_suites_len(2) + cipher_suites(10)
        // + compression(2) + extensions_len(2) + ext_type(2) + ext_len(2) + sni_list_len(2)
        // + sni_type(1) + sni_len(2) = 60 bytes.
        // Record layer: handshake_type(1) + handshake_len(3) + client_hello(60 + N) = 64 + N.
        // Max u16 record length = 65535, so N = 65535 - 64 = 65471.
        let hostname = "a".repeat(65471);
        let result = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: hostname,
        });
        assert!(result.is_ok(), "{:?}", result);
        let bytes = result.unwrap();
        // Verify record length matches actual buffer
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        assert_eq!(bytes.len(), 5 + record_len, "record length mismatch");
    }

    #[test]
    fn tls_client_hello_overlong_hostname_returns_error() {
        // 65472 bytes should exceed u16 record length
        let hostname = "a".repeat(65472);
        let result = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: hostname,
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("TLS record payload too large"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tls_client_hello_length_fields_match_actual_buffer() {
        let bytes = prepare_payload(&PayloadSource::TlsClientHello {
            server_name: "example.com".into(),
        })
        .expect("tls payload");

        // Record length (2 bytes)
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        assert_eq!(bytes.len(), 5 + record_len, "record length mismatch");

        // Handshake length (3 bytes)
        let handshake_len =
            ((bytes[6] as usize) << 16) | ((bytes[7] as usize) << 8) | (bytes[8] as usize);
        assert_eq!(
            bytes.len() - 5,
            1 + 3 + handshake_len,
            "handshake length mismatch"
        );

        // Client hello starts at byte 9
        let actual_client_hello_len = bytes.len() - 9;
        assert_eq!(
            actual_client_hello_len, handshake_len,
            "client_hello length mismatch"
        );
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;
    use crate::network::sender::error::{PayloadError, SenderError};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn file_payload_enforces_hard_limit() {
        // Create a file larger than MAX_PAYLOAD_SIZE
        let mut file = NamedTempFile::new().expect("temp file");
        // We write 1 byte past the limit. MAX_PAYLOAD_SIZE is 10MB.
        let data = vec![b'A'; (MAX_PAYLOAD_SIZE as usize) + 1];
        file.write_all(&data).expect("write");
        let path = file.path().to_path_buf();

        let result = prepare_payload(&PayloadSource::File(path));
        match result {
            Err(SenderError::Payload(PayloadError::PayloadTooLarge { size, limit })) => {
                // Currently this will match because of ensure_payload_size(metadata.len())
                // But we want to ensure this still holds (or is caught by read logic if we bypass metadata check)
                assert_eq!(size, MAX_PAYLOAD_SIZE + 1);
                assert_eq!(limit, MAX_PAYLOAD_SIZE);
            }
            _ => panic!("Expected PayloadTooLarge error, got {:?}", result),
        }
    }

    #[test]
    fn file_payload_allows_valid_size() {
        let mut file = NamedTempFile::new().expect("temp file");
        let data = vec![b'B'; MAX_PAYLOAD_SIZE as usize];
        file.write_all(&data).expect("write");
        let path = file.path().to_path_buf();

        let result = prepare_payload(&PayloadSource::File(path));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), MAX_PAYLOAD_SIZE as usize);
    }
}
