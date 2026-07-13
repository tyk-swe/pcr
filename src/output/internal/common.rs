fn compact_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// A zero-allocation hexadecimal view used by streaming JSON serializers.
struct HexOutput<'a>(&'a [u8]);

impl fmt::Display for HexOutput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for HexOutput<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}
fn serialize_u64_decimal<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_str(value)
}

fn serialize_i64_decimal<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_str(value)
}

fn serialize_usize_decimal<S>(value: &usize, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_str(value)
}

fn serialize_optional_usize_decimal<S>(
    value: &Option<usize>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serializer.collect_str(value),
        None => serializer.serialize_none(),
    }
}

fn serialize_duration<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct as _;

    let mut output = serializer.serialize_struct("Duration", 2)?;
    output.serialize_field("seconds", &value.as_secs().to_string())?;
    output.serialize_field("nanoseconds", &value.subsec_nanos())?;
    output.end()
}

fn serialize_optional_duration<S>(
    value: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serialize_duration(value, serializer),
        None => serializer.serialize_none(),
    }
}

fn serialize_u64_vec_decimal<S>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .serialize(serializer)
}

/// Output-v2 packet byte range. Packet-document v1 keeps its native numeric
/// representation; output-v2 renders platform-sized offsets as decimals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputByteRange {
    #[serde(serialize_with = "serialize_usize_decimal")]
    pub start: usize,
    #[serde(serialize_with = "serialize_usize_decimal")]
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputFieldLayout {
    pub name: String,
    pub range: OutputByteRange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputLayerLayout {
    #[serde(serialize_with = "serialize_usize_decimal")]
    pub index: usize,
    pub protocol: String,
    pub range: OutputByteRange,
    pub fields: Vec<OutputFieldLayout>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OutputPacketLayout {
    pub layers: Vec<OutputLayerLayout>,
}

impl From<crate::packet::internal::ByteRange> for OutputByteRange {
    fn from(value: crate::packet::internal::ByteRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl From<PacketLayout> for OutputPacketLayout {
    fn from(value: PacketLayout) -> Self {
        Self {
            layers: value
                .layers
                .into_iter()
                .map(|layer| OutputLayerLayout {
                    index: layer.index,
                    protocol: layer.protocol.to_string(),
                    range: layer.range.into(),
                    fields: layer
                        .fields
                        .into_iter()
                        .map(|field| OutputFieldLayout {
                            name: field.name,
                            range: field.range.into(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}
