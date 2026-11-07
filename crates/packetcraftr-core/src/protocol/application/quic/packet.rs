use super::{Error, Reader};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Version {
    V1,
    V2,
}
impl Version {
    pub const fn wire(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 0x6b3343cf,
        }
    }
    pub fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::V1),
            0x6b3343cf => Some(Self::V2),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
    VersionNegotiation,
    Unsupported,
}
impl PacketKind {
    pub const fn space(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            _ => 2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Packet<'a> {
    pub kind: PacketKind,
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub token: &'a [u8],
    pub number_offset: Option<usize>,
    pub bytes: &'a [u8],
}

fn connection_id<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let length = usize::from(reader.byte()?);
    if length > 20 {
        return Err(Error::Invalid);
    }
    reader.take(length)
}

pub(crate) fn long_destination_connection_id(input: &[u8]) -> Result<&[u8], Error> {
    let mut reader = Reader::new(input);
    if reader.byte()? & 0x80 == 0 {
        return Err(Error::Invalid);
    }
    reader.take(4)?;
    connection_id(&mut reader)
}

pub fn parse_packet(input: &[u8], short_dcid_length: Option<usize>) -> Result<Packet<'_>, Error> {
    let mut r = Reader::new(input);
    let first = r.byte()?;
    if first & 0x80 == 0 {
        if first & 0x40 == 0 {
            return Err(Error::Invalid);
        }
        let dcid = match short_dcid_length {
            Some(n) if n <= 20 => r.take(n)?,
            Some(_) => return Err(Error::Invalid),
            None => &[],
        };
        if r.left() < 17 {
            return Err(Error::Truncated);
        }
        return Ok(Packet {
            kind: PacketKind::OneRtt,
            version: 0,
            dcid,
            scid: &[],
            token: &[],
            number_offset: short_dcid_length.map(|_| r.position),
            bytes: input,
        });
    }
    let version = u32::from_be_bytes(r.take(4)?.try_into().map_err(|_| Error::Truncated)?);
    let dcid = connection_id(&mut r)?;
    let scid = connection_id(&mut r)?;
    let mut packet = Packet {
        kind: PacketKind::Unsupported,
        version,
        dcid,
        scid,
        token: &[],
        number_offset: None,
        bytes: input,
    };
    if version == 0 {
        if r.left() == 0 || !r.left().is_multiple_of(4) {
            return Err(Error::Invalid);
        }
        packet.kind = PacketKind::VersionNegotiation;
        return Ok(packet);
    }
    let Some(version) = Version::from_wire(version) else {
        return Ok(packet);
    };
    if first & 0x40 == 0 {
        return Err(Error::Invalid);
    }
    let ty = (first >> 4) & 3;
    packet.kind = match (version, ty) {
        (Version::V1, 0) | (Version::V2, 1) => PacketKind::Initial,
        (Version::V1, 1) | (Version::V2, 2) => PacketKind::ZeroRtt,
        (Version::V1, 2) | (Version::V2, 3) => PacketKind::Handshake,
        _ => PacketKind::Retry,
    };
    if packet.kind == PacketKind::Retry {
        let remaining = r.left();
        if remaining < 17 {
            return Err(Error::Truncated);
        }
        packet.token = r.take(remaining - 16)?;
        return Ok(packet);
    }
    if packet.kind == PacketKind::Initial {
        let len = r.length()?;
        packet.token = r.take(len)?;
    }
    let len = r.length()?;
    if len < 17 {
        return Err(Error::Truncated);
    }
    packet.number_offset = Some(r.position);
    r.take(len)?;
    packet.bytes = &input[..r.position];
    Ok(packet)
}
