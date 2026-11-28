use std::collections::BTreeMap;

use crate::field::hex::decode_pairs;

#[derive(Clone)]
pub(super) struct Secret(pub(super) Vec<u8>);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Label {
    Early,
    ClientHandshake,
    ServerHandshake,
    ClientTraffic,
    ServerTraffic,
}
impl Label {
    fn parse(input: &str) -> Option<Self> {
        match input {
            "CLIENT_EARLY_TRAFFIC_SECRET" => Some(Self::Early),
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ClientHandshake),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ServerHandshake),
            "CLIENT_TRAFFIC_SECRET_0" => Some(Self::ClientTraffic),
            "SERVER_TRAFFIC_SECRET_0" => Some(Self::ServerTraffic),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Import {
    pub added: u64,
    pub rejected: u64,
}
pub struct KeyLog {
    secrets: BTreeMap<([u8; 32], Label), Secret>,
    partial: Vec<u8>,
    discard: bool,
    bytes: usize,
    revision: u64,
    limit: usize,
}
impl KeyLog {
    pub fn new() -> Self {
        Self::with_limit(16 * 1024 * 1024)
    }
    pub(super) fn with_limit(limit: usize) -> Self {
        Self {
            secrets: BTreeMap::new(),
            partial: Vec::new(),
            discard: false,
            bytes: 0,
            revision: 0,
            limit,
        }
    }
    pub fn append(&mut self, bytes: &[u8], finish: bool) -> Import {
        let mut result = Import::default();
        for &byte in bytes {
            if byte == b'\n' {
                if !self.discard {
                    self.line(&mut result);
                }
                self.partial.clear();
                self.discard = false;
            } else if !self.discard {
                if self.partial.len() == 512 {
                    self.partial.clear();
                    self.discard = true;
                    result.rejected += 1;
                } else {
                    self.partial.push(byte);
                }
            }
        }
        if finish {
            if !self.partial.is_empty() && !self.discard {
                self.line(&mut result);
            }
            self.partial.clear();
            self.discard = false;
        }
        result
    }
    fn line(&mut self, result: &mut Import) {
        let Ok(line) = std::str::from_utf8(&self.partial) else {
            result.rejected += 1;
            return;
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        let mut parts = line.split_whitespace();
        let Some(label) = parts.next().and_then(Label::parse) else {
            return;
        };
        let parsed = parts
            .next()
            .and_then(|text| decode_pairs(text).ok())
            .and_then(|random| {
                let random: [u8; 32] = random.try_into().ok()?;
                let secret = decode_pairs(parts.next()?).ok()?;
                if parts.next().is_some() || !matches!(secret.len(), 32 | 48) {
                    return None;
                }
                Some((random, Secret(secret)))
            });
        let Some((random, secret)) = parsed else {
            result.rejected += 1;
            return;
        };
        if let Some(old) = self.secrets.get(&(random, label)) {
            if old.0 != secret.0 {
                result.rejected += 1;
            }
            return;
        }
        let charge = 128 + secret.0.len();
        if self.secrets.len() >= 65536 || self.bytes.saturating_add(charge) > self.limit {
            result.rejected += 1;
            return;
        }
        self.bytes += charge;
        self.secrets.insert((random, label), secret);
        self.revision += 1;
        result.added += 1;
    }
    pub(super) fn get(&self, random: &[u8; 32], label: Label) -> Option<&Secret> {
        self.secrets.get(&(*random, label))
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }
    pub(super) fn memory(&self) -> usize {
        self.bytes + self.partial.capacity()
    }
}
impl Default for KeyLog {
    fn default() -> Self {
        Self::new()
    }
}
