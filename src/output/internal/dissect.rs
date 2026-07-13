/// Structured result of `dissect`.
#[derive(Clone, Debug)]
pub struct DissectCommandResult {
    bytes: Bytes,
    pub length: u64,
    pub link_type: u32,
    pub packet: PacketDocument,
    pub layout: OutputPacketLayout,
}

impl DissectCommandResult {
    pub fn from_decoded(decoded: DecodedPacket) -> (Self, Vec<Diagnostic>) {
        let DecodedPacket {
            packet,
            original,
            frame,
            layout,
            diagnostics,
        } = decoded;
        (
            Self {
                length: original.len() as u64,
                link_type: frame.link_type.0,
                packet: PacketDocument::from_packet(&packet),
                layout: layout.into(),
                bytes: original,
            },
            diagnostics,
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_hex(&self) -> String {
        compact_hex(&self.bytes)
    }
}

impl Serialize for DissectCommandResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;

        let mut output = serializer.serialize_struct("DissectCommandResult", 5)?;
        output.serialize_field("bytes_hex", &HexOutput(&self.bytes))?;
        output.serialize_field("length", &self.length.to_string())?;
        output.serialize_field("link_type", &self.link_type)?;
        output.serialize_field("packet", &self.packet)?;
        output.serialize_field("layout", &self.layout)?;
        output.end()
    }
}
