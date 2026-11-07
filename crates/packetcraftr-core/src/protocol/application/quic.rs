use crate::codec::{DecodeContext, EncodeContext};
use bytes::Bytes;

mod frames;
mod packet;
pub use frames::{AckRange, Frame, parse_frames};
pub(crate) use packet::long_destination_connection_id;
pub use packet::{Packet, PacketKind, Version, parse_packet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("truncated QUIC field")]
    Truncated,
    #[error("invalid QUIC field")]
    Invalid,
    #[error("unsupported QUIC frame {0:#x}")]
    UnsupportedFrame(u64),
    #[error("QUIC resource limit reached")]
    Limit,
    #[error("QUIC packet authentication failed")]
    Authentication,
}

pub(crate) struct Reader<'a> {
    pub(crate) input: &'a [u8],
    pub(crate) position: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
    pub(crate) fn left(&self) -> usize {
        self.input.len() - self.position
    }
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Invalid)?;
        let bytes = self.input.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
    pub(crate) fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn varint(&mut self) -> Result<u64, Error> {
        let first = self.byte()?;
        let length = 1_usize << (first >> 6);
        self.take(length - 1)?
            .iter()
            .try_fold(u64::from(first & 0x3f), |n, b| {
                n.checked_mul(256)
                    .and_then(|n| n.checked_add(u64::from(*b)))
                    .ok_or(Error::Invalid)
            })
    }
    pub(crate) fn length(&mut self) -> Result<usize, Error> {
        usize::try_from(self.varint()?).map_err(|_| Error::Limit)
    }
}

pub fn parse_varint(input: &[u8]) -> Result<(u64, usize), Error> {
    let mut r = Reader::new(input);
    let n = r.varint()?;
    Ok((n, r.position))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Quic {
    pub version: u32,
    pub destination_connection_id: Bytes,
    pub source_connection_id: Bytes,
    pub packet_count: u64,
    pub data: Bytes,
}
crate::reflective_layer! {
    fn quic_schema() => { protocol: crate::protocol::BuiltinProtocol::Quic.id(), name: "Quic" }
    impl Quic {
        "version" => { kind: Unsigned, derived: true, required: false, description: "Wire version, zero for short headers or Version Negotiation", reflect: version },
        "destination_connection_id" => { kind: Bytes, derived: true, required: false, description: "First long header destination connection ID", reflect: destination_connection_id },
        "source_connection_id" => { kind: Bytes, derived: true, required: false, description: "First long header source connection ID", reflect: source_connection_id },
        "packet_count" => { kind: Unsigned, derived: true, required: false, description: "Coalesced packet count", reflect: packet_count },
        "data" => { kind: Bytes, derived: false, required: true, description: "Original protected datagram", reflect: data },
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct QuicCodec;
impl crate::codec::Codec for QuicCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &quic_schema().protocol
    }
    fn schema(&self) -> Option<&'static crate::layer::Schema> {
        Some(quic_schema())
    }
    fn new_layer(&self) -> Result<Box<dyn crate::layer::Layer>, crate::codec::Error> {
        Err(crate::codec::Error::unsupported(
            crate::protocol::BuiltinProtocol::Quic.id(),
            "packet construction is not supported",
        ))
    }
    fn framing(&self) -> crate::codec::Framing {
        crate::codec::Framing::Datagram
    }
    fn encode(
        &self,
        _: &dyn crate::layer::Layer,
        _: &[u8],
        context: &crate::codec::EncodeContext<'_>,
    ) -> Result<crate::codec::Encoded, crate::codec::Error> {
        Quic::default()
            .encode_wire(context)
            .map(|bytes| crate::codec::Encoded::header(bytes, Box::new(Quic::default())))
    }
    fn decode(
        &self,
        input: Bytes,
        context: &crate::codec::DecodeContext<'_>,
    ) -> Result<crate::codec::Decoded, crate::codec::Error> {
        let length = input.len();
        let (layer, fields) = Quic::parse_wire(input, context)?;
        let mut decoded = crate::codec::Decoded::terminal(Box::new(layer), length);
        decoded.fields = fields;
        Ok(decoded)
    }
}
impl Quic {
    fn encode_wire(&self, _: &EncodeContext<'_>) -> Result<Vec<u8>, crate::codec::Error> {
        Err(crate::protocol::common::unsupported(
            "quic",
            "QUIC construction is not supported",
        ))
    }
    fn parse_wire(
        data: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), crate::codec::Error> {
        let first = parse_packet(&data, None)
            .map_err(|e| crate::protocol::common::invalid("quic", e.to_string()))?;
        let mut value = Self {
            version: first.version,
            destination_connection_id: Bytes::copy_from_slice(first.dcid),
            source_connection_id: Bytes::copy_from_slice(first.scid),
            packet_count: 0,
            data: data.clone(),
        };
        let mut offset = 0;
        while offset < data.len() {
            let packet = parse_packet(&data[offset..], None)
                .map_err(|e| crate::protocol::common::invalid("quic", e.to_string()))?;
            offset += packet.bytes.len();
            value.packet_count += 1;
            if value.packet_count > 4096 {
                return Err(crate::protocol::common::invalid(
                    "quic",
                    "too many coalesced packets",
                ));
            }
        }
        Ok((value, vec![]))
    }
}

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        use crate::error::{Classification, Code, Kind};
        if matches!(self, Self::Limit) {
            return Classification::new(
                Code::PolicyAnalysisResourceLimit,
                Kind::Policy,
                Some("raise the finite QUIC analysis limit"),
            );
        }
        Classification::new(Code::PacketDecode, Kind::Packet, None)
    }
}
