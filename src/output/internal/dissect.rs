/// Structured result of `dissect`.
#[derive(Clone, Debug, Serialize)]
pub struct DissectCommandResult {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
    pub link_type: u32,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
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
                bytes_hex: compact_hex(&original),
                length: original.len() as u64,
                link_type: frame.link_type.0,
                packet: PacketDocument::from_packet(&packet),
                layout,
                bytes: original,
            },
            diagnostics,
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
