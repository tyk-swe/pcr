/// Structured result of `build`.
#[derive(Clone, Debug)]
pub struct BuildCommandResult {
    bytes: Bytes,
    pub length: u64,
    pub packet: PacketDocument,
    pub layout: OutputPacketLayout,
    pub requires_live_opt_in: bool,
}

impl BuildCommandResult {
    pub fn from_built(built: BuiltPacket) -> (Self, Vec<Diagnostic>) {
        let BuiltPacket {
            bytes,
            packet,
            layout,
            diagnostics,
            requires_live_opt_in,
        } = built;
        (
            Self {
                length: bytes.len() as u64,
                packet: PacketDocument::from_packet(&packet),
                layout: layout.into(),
                requires_live_opt_in,
                bytes,
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

impl Serialize for BuildCommandResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;

        let mut output = serializer.serialize_struct("BuildCommandResult", 5)?;
        output.serialize_field("bytes_hex", &HexOutput(&self.bytes))?;
        output.serialize_field("length", &self.length.to_string())?;
        output.serialize_field("packet", &self.packet)?;
        output.serialize_field("layout", &self.layout)?;
        output.serialize_field("requires_live_opt_in", &self.requires_live_opt_in)?;
        output.end()
    }
}
