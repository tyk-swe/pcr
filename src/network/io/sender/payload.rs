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
