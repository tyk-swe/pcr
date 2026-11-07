use super::keylog::Secret;
use crate::protocol::application::quic::{Error, Packet, Version};
use ring::{aead, hkdf};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum Suite {
    Aes128,
    Aes256,
    ChaCha,
}
impl Suite {
    pub(super) fn from_tls(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(Self::Aes128),
            0x1302 => Some(Self::Aes256),
            0x1303 => Some(Self::ChaCha),
            _ => None,
        }
    }
    fn hash(self) -> hkdf::Algorithm {
        match self {
            Self::Aes256 => hkdf::HKDF_SHA384,
            _ => hkdf::HKDF_SHA256,
        }
    }
    fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            _ => 32,
        }
    }
    fn hash_len(self) -> usize {
        match self {
            Self::Aes256 => 48,
            _ => 32,
        }
    }
    fn aead(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128 => &aead::AES_128_GCM,
            Self::Aes256 => &aead::AES_256_GCM,
            Self::ChaCha => &aead::CHACHA20_POLY1305,
        }
    }
    fn hp(self) -> &'static aead::quic::Algorithm {
        match self {
            Self::Aes128 => &aead::quic::AES_128,
            Self::Aes256 => &aead::quic::AES_256,
            Self::ChaCha => &aead::quic::CHACHA20,
        }
    }
}
struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}
fn expand(prk: &hkdf::Prk, label: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    let mut info = Vec::with_capacity(label.len() + 10);
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let mut output = vec![0; length];
    prk.expand(&[&info], Length(length))
        .map_err(|_| Error::Invalid)?
        .fill(&mut output)
        .map_err(|_| Error::Invalid)?;
    Ok(output)
}
fn label(version: Version, kind: &[u8]) -> Vec<u8> {
    let prefix: &[u8] = match version {
        Version::V1 => b"quic ",
        Version::V2 => b"quicv2 ",
    };
    [prefix, kind].concat()
}
pub(super) struct Keys {
    header: Arc<aead::quic::HeaderProtectionKey>,
    packet: aead::LessSafeKey,
    iv: [u8; 12],
    secret: Secret,
    suite: Suite,
    version: Version,
}
pub(super) struct Opened {
    pub(super) number: u64,
    pub(super) key_phase: bool,
    pub(super) plaintext: Vec<u8>,
}
impl Keys {
    pub(super) fn initial(version: Version, dcid: &[u8], client: bool) -> Result<Self, Error> {
        const V1: [u8; 20] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        const V2: [u8; 20] = [
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
            0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ];
        let salt = match version {
            Version::V1 => &V1,
            Version::V2 => &V2,
        };
        let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
        let secret = Secret(expand(
            &initial,
            if client { b"client in" } else { b"server in" },
            32,
        )?);
        Self::new(Suite::Aes128, version, &secret)
    }
    pub(super) fn new(suite: Suite, version: Version, secret: &Secret) -> Result<Self, Error> {
        if secret.0.len() != suite.hash_len() {
            return Err(Error::Invalid);
        }
        let prk = hkdf::Prk::new_less_safe(suite.hash(), &secret.0);
        let hp = expand(&prk, &label(version, b"hp"), suite.key_len())?;
        let header = Arc::new(
            aead::quic::HeaderProtectionKey::new(suite.hp(), &hp).map_err(|_| Error::Invalid)?,
        );
        Self::with_header(suite, version, secret.clone(), header)
    }
    fn with_header(
        suite: Suite,
        version: Version,
        secret: Secret,
        header: Arc<aead::quic::HeaderProtectionKey>,
    ) -> Result<Self, Error> {
        let prk = hkdf::Prk::new_less_safe(suite.hash(), &secret.0);
        let key = expand(&prk, &label(version, b"key"), suite.key_len())?;
        let iv = expand(&prk, &label(version, b"iv"), 12)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let packet = aead::LessSafeKey::new(
            aead::UnboundKey::new(suite.aead(), &key).map_err(|_| Error::Invalid)?,
        );
        Ok(Self {
            header,
            packet,
            iv,
            secret,
            suite,
            version,
        })
    }
    pub(super) fn next(&self) -> Result<Self, Error> {
        let prk = hkdf::Prk::new_less_safe(self.suite.hash(), &self.secret.0);
        let secret = Secret(expand(
            &prk,
            &label(self.version, b"ku"),
            self.suite.hash_len(),
        )?);
        Self::with_header(self.suite, self.version, secret, self.header.clone())
    }
    pub(super) fn open(&self, packet: &Packet<'_>, largest: Option<u64>) -> Result<Opened, Error> {
        let offset = packet.number_offset.ok_or(Error::Invalid)?;
        let sample = packet
            .bytes
            .get(offset + 4..offset + 20)
            .ok_or(Error::Truncated)?;
        let mask = self.header.new_mask(sample).map_err(|_| Error::Invalid)?;
        let mut bytes = packet.bytes.to_vec();
        let long = bytes[0] & 0x80 != 0;
        bytes[0] ^= mask[0] & if long { 0x0f } else { 0x1f };
        let pn_len = usize::from((bytes[0] & 3) + 1);
        let mut truncated = 0_u64;
        for i in 0..pn_len {
            bytes[offset + i] ^= mask[1 + i];
            truncated = (truncated << 8) | u64::from(bytes[offset + i]);
        }
        let number = reconstruct(truncated, pn_len * 8, largest)?;
        let mut nonce = self.iv;
        for (out, b) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *out ^= b;
        }
        let first = bytes[0];
        let (aad, payload) = bytes.split_at_mut(offset + pn_len);
        let plaintext = self
            .packet
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&*aad),
                payload,
            )
            .map_err(|_| Error::Authentication)?
            .to_vec();
        if first & if long { 0x0c } else { 0x18 } != 0 {
            return Err(Error::Invalid);
        }
        Ok(Opened {
            number,
            key_phase: !long && first & 4 != 0,
            plaintext,
        })
    }
    #[cfg(test)]
    pub(super) fn seal(
        &self,
        mut header: Vec<u8>,
        offset: usize,
        number: u64,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut payload = plaintext.to_vec();
        let mut nonce = self.iv;
        for (out, b) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *out ^= b;
        }
        self.packet
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&header),
                &mut payload,
            )
            .unwrap();
        header.extend_from_slice(&payload);
        let mask = self
            .header
            .new_mask(&header[offset + 4..offset + 20])
            .unwrap();
        let n = usize::from((header[0] & 3) + 1);
        header[0] ^= mask[0] & if header[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        for i in 0..n {
            header[offset + i] ^= mask[1 + i];
        }
        header
    }
}
pub(super) fn reconstruct(truncated: u64, bits: usize, largest: Option<u64>) -> Result<u64, Error> {
    let expected = largest.map_or(0, |n| n.saturating_add(1));
    let window = 1_u64 << bits;
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | truncated;
    let number = if candidate.saturating_add(half) <= expected && candidate < (1_u64 << 62) - window
    {
        candidate + window
    } else if candidate > expected.saturating_add(half) && candidate >= window {
        candidate - window
    } else {
        candidate
    };
    if number >= 1_u64 << 62 {
        return Err(Error::Invalid);
    }
    Ok(number)
}
pub(super) fn validate_retry(
    version: Version,
    original_dcid: &[u8],
    packet: &[u8],
) -> Result<(), Error> {
    const V1_KEY: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const V1_NONCE: [u8; 12] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ];
    const V2_KEY: [u8; 16] = [
        0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc,
        0x92,
    ];
    const V2_NONCE: [u8; 12] = [
        0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
    ];
    let (key, nonce) = match version {
        Version::V1 => (V1_KEY, V1_NONCE),
        Version::V2 => (V2_KEY, V2_NONCE),
    };
    let end = packet.len().checked_sub(16).ok_or(Error::Truncated)?;
    let aad = [&[original_dcid.len() as u8], original_dcid, &packet[..end]].concat();
    let mut tag = packet[end..].to_vec();
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &key).map_err(|_| Error::Invalid)?,
    );
    key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(&aad),
        &mut tag,
    )
    .map_err(|_| Error::Authentication)?;
    Ok(())
}
