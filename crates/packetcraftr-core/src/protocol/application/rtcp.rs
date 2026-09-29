// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded RTCP compounds. Packet bodies and unknown packet types remain exact.
use crate::protocol::common::{
    ensure_encode_budget, invalid, make_layer, protocol,
    structured::{self, Object},
    typed_layer,
};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{self, FieldValue},
    layer::{Layer, reflective_layer},
};
use bytes::Bytes;
use std::collections::BTreeMap;
const NAME: &str = "rtcp";
pub const MAX_COMPOUND_ENTRIES: usize = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub packet_type: u8,
    pub count: u8,
    pub body: Bytes,
    pub padding: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub cumulative_lost: i32,
    pub highest_sequence: u32,
    pub jitter: u32,
    pub last_sr: u32,
    pub delay_since_sr: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesItem {
    pub kind: u8,
    pub value: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub items: Vec<SdesItem>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Contents {
    SenderReport {
        ssrc: u32,
        ntp_timestamp: u64,
        rtp_timestamp: u32,
        packet_count: u32,
        octet_count: u32,
        reports: Vec<Report>,
        extension: Bytes,
    },
    ReceiverReport {
        ssrc: u32,
        reports: Vec<Report>,
        extension: Bytes,
    },
    SourceDescription(Vec<SdesChunk>),
    Bye {
        sources: Vec<u32>,
        reason: Option<Bytes>,
    },
    Unknown(Bytes),
}
impl Report {
    fn encode(&self, wire: &mut Vec<u8>) -> Result<(), crate::codec::Error> {
        if !(-8_388_608..=8_388_607).contains(&self.cumulative_lost) {
            return Err(invalid(NAME, "report loss exceeds signed 24-bit field"));
        }
        wire.extend_from_slice(&self.ssrc.to_be_bytes());
        wire.push(self.fraction_lost);
        wire.extend_from_slice(&self.cumulative_lost.to_be_bytes()[1..]);
        for value in [
            self.highest_sequence,
            self.jitter,
            self.last_sr,
            self.delay_since_sr,
        ] {
            wire.extend_from_slice(&value.to_be_bytes());
        }
        Ok(())
    }
}
fn u32_at(bytes: &[u8], index: usize) -> u32 {
    u32::from_be_bytes(bytes[index..index + 4].try_into().unwrap())
}
impl Packet {
    pub fn receiver_report(ssrc: u32, reports: &[Report]) -> Result<Self, crate::codec::Error> {
        if reports.len() > 31 {
            return Err(invalid(NAME, "exceeds 31 receiver reports"));
        }
        let mut body = ssrc.to_be_bytes().to_vec();
        for report in reports {
            report.encode(&mut body)?;
        }
        Ok(Self {
            packet_type: 201,
            count: reports.len() as u8,
            body: body.into(),
            padding: Bytes::new(),
        })
    }
    pub fn sender_report(
        ssrc: u32,
        ntp_timestamp: u64,
        rtp_timestamp: u32,
        packet_count: u32,
        octet_count: u32,
        reports: &[Report],
    ) -> Result<Self, crate::codec::Error> {
        let mut result = Self::receiver_report(ssrc, reports)?;
        let mut body = ssrc.to_be_bytes().to_vec();
        body.extend_from_slice(&ntp_timestamp.to_be_bytes());
        for value in [rtp_timestamp, packet_count, octet_count] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.extend_from_slice(&result.body[4..]);
        result.packet_type = 200;
        result.body = body.into();
        Ok(result)
    }
    pub fn source_description(chunks: &[SdesChunk]) -> Result<Self, crate::codec::Error> {
        if chunks.len() > 31 {
            return Err(invalid(NAME, "exceeds 31 SDES chunks"));
        }
        let mut body = Vec::new();
        for chunk in chunks {
            body.extend_from_slice(&chunk.ssrc.to_be_bytes());
            for item in &chunk.items {
                if item.kind == 0 || item.value.len() > 255 {
                    return Err(invalid(NAME, "invalid SDES item"));
                }
                body.extend_from_slice(&[item.kind, item.value.len() as u8]);
                body.extend_from_slice(&item.value);
            }
            body.push(0);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        Ok(Self {
            packet_type: 202,
            count: chunks.len() as u8,
            body: body.into(),
            padding: Bytes::new(),
        })
    }
    pub fn bye(sources: &[u32], reason: Option<Bytes>) -> Result<Self, crate::codec::Error> {
        if sources.len() > 31 || reason.as_ref().is_some_and(|v| v.len() > 255) {
            return Err(invalid(NAME, "invalid BYE source count or reason length"));
        }
        let mut body = Vec::new();
        for source in sources {
            body.extend_from_slice(&source.to_be_bytes());
        }
        if let Some(reason) = reason {
            body.push(reason.len() as u8);
            body.extend_from_slice(&reason);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        Ok(Self {
            packet_type: 203,
            count: sources.len() as u8,
            body: body.into(),
            padding: Bytes::new(),
        })
    }
    pub fn contents(&self) -> Result<Contents, crate::codec::Error> {
        let body = &self.body;
        let count = usize::from(self.count);
        if count > 31 {
            return Err(invalid(NAME, "count exceeds five bits"));
        }
        match self.packet_type {
            200 | 201 => {
                let base = if self.packet_type == 200 { 24 } else { 4 };
                let end = base + 24 * count;
                if body.len() < end {
                    return Err(invalid(NAME, "truncated sender/receiver reports"));
                }
                let mut reports = Vec::new();
                for bytes in body[base..end].as_chunks::<24>().0 {
                    let lost = i32::from_be_bytes([
                        if bytes[5] & 128 != 0 { 255 } else { 0 },
                        bytes[5],
                        bytes[6],
                        bytes[7],
                    ]);
                    reports.push(Report {
                        ssrc: u32_at(bytes, 0),
                        fraction_lost: bytes[4],
                        cumulative_lost: lost,
                        highest_sequence: u32_at(bytes, 8),
                        jitter: u32_at(bytes, 12),
                        last_sr: u32_at(bytes, 16),
                        delay_since_sr: u32_at(bytes, 20),
                    });
                }
                if self.packet_type == 200 {
                    Ok(Contents::SenderReport {
                        ssrc: u32_at(body, 0),
                        ntp_timestamp: u64::from_be_bytes(body[4..12].try_into().unwrap()),
                        rtp_timestamp: u32_at(body, 12),
                        packet_count: u32_at(body, 16),
                        octet_count: u32_at(body, 20),
                        reports,
                        extension: body.slice(end..),
                    })
                } else {
                    Ok(Contents::ReceiverReport {
                        ssrc: u32_at(body, 0),
                        reports,
                        extension: body.slice(end..),
                    })
                }
            }
            202 => {
                let mut index = 0;
                let mut chunks = Vec::new();
                for _ in 0..count {
                    if body.len() < index + 4 {
                        return Err(invalid(NAME, "truncated SDES source"));
                    }
                    let ssrc = u32_at(body, index);
                    index += 4;
                    let mut items = Vec::new();
                    loop {
                        let kind = *body
                            .get(index)
                            .ok_or_else(|| invalid(NAME, "missing SDES terminator"))?;
                        index += 1;
                        if kind == 0 {
                            break;
                        }
                        let len = usize::from(
                            *body
                                .get(index)
                                .ok_or_else(|| invalid(NAME, "truncated SDES item"))?,
                        );
                        index += 1;
                        if body.len() < index + len {
                            return Err(invalid(NAME, "truncated SDES value"));
                        }
                        items.push(SdesItem {
                            kind,
                            value: body.slice(index..index + len),
                        });
                        index += len;
                    }
                    while index % 4 != 0 {
                        if body.get(index) != Some(&0) {
                            return Err(invalid(NAME, "nonzero or missing SDES alignment"));
                        }
                        index += 1;
                    }
                    chunks.push(SdesChunk { ssrc, items });
                }
                if index != body.len() {
                    return Err(invalid(NAME, "unexpected SDES bytes"));
                }
                Ok(Contents::SourceDescription(chunks))
            }
            203 => {
                let base = count * 4;
                if body.len() < base {
                    return Err(invalid(NAME, "truncated BYE sources"));
                }
                let sources = body[..base]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|bytes| u32_at(bytes, 0))
                    .collect();
                let reason = if body.len() > base {
                    let len = usize::from(body[base]);
                    let end = base + 1 + len;
                    if body.len() < end
                        || body[end..].iter().any(|byte| *byte != 0)
                        || body.len() - end > 3
                    {
                        return Err(invalid(NAME, "invalid BYE reason"));
                    }
                    Some(body.slice(base + 1..end))
                } else {
                    None
                };
                Ok(Contents::Bye { sources, reason })
            }
            _ => Ok(Contents::Unknown(body.clone())),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rtcp {
    pub packets: Vec<Packet>,
}
impl Default for Rtcp {
    fn default() -> Self {
        Self {
            packets: vec![Packet::receiver_report(0, &[]).expect("empty report")],
        }
    }
}
impl Rtcp {
    fn set_packets(&mut self, value: FieldValue, name: &str) -> Result<(), field::Error> {
        let values = structured::list(value, MAX_COMPOUND_ENTRIES, rtcp_schema(), name)?;
        let mut packets = Vec::new();
        for value in values {
            let mut object = Object::new(value, rtcp_schema(), name)?;
            packets.push(Packet {
                packet_type: object.required_value("packet_type")?,
                count: object.value("count", 0u8)?,
                body: object.required_value("body")?,
                padding: object.value("padding", Bytes::new())?,
            });
            object.finish()?;
        }
        self.packets = packets;
        Ok(())
    }
}
const PACKET_FIELDS: &[crate::layer::FieldSchema] = &[
    structured::member("packet_type", crate::field::FieldKind::Unsigned, &[]),
    structured::member("count", crate::field::FieldKind::Unsigned, &[]),
    structured::member("body", crate::field::FieldKind::Bytes, &[]),
    structured::member("padding", crate::field::FieldKind::Bytes, &[]),
];
reflective_layer! {
    fn rtcp_schema()=>{protocol:protocol(NAME),name:"RTCP"}
    impl Rtcp {"packets"=>{kind:List,derived:false,required:false,description:"Ordered compound packets",children:PACKET_FIELDS,get |layer|Some(FieldValue::List(layer.packets.iter().map(|packet|structured::object([("packet_type",FieldValue::Unsigned(u64::from(packet.packet_type))),("count",FieldValue::Unsigned(u64::from(packet.count))),("body",FieldValue::Bytes(packet.body.clone())),("padding",FieldValue::Bytes(packet.padding.clone()))])).collect())),set |layer,value,name|layer.set_packets(value,name)},}
    layout fn rtcp_layout();
}
fn wire(layer: &Rtcp) -> Result<Vec<u8>, crate::codec::Error> {
    if layer.packets.is_empty() || layer.packets.len() > MAX_COMPOUND_ENTRIES {
        return Err(invalid(NAME, "compound requires 1..64 entries"));
    }
    let mut wire = Vec::new();
    for (index, packet) in layer.packets.iter().enumerate() {
        packet.contents()?;
        let length = 4 + packet.body.len() + packet.padding.len();
        if length % 4 != 0
            || length / 4 > 65536
            || !packet.padding.is_empty()
                && (index + 1 != layer.packets.len()
                    || packet.padding.len() > 255
                    || packet.padding.last().copied() != Some(packet.padding.len() as u8))
        {
            return Err(invalid(NAME, "invalid compound length or padding"));
        }
        wire.extend_from_slice(&[
            0x80 | u8::from(!packet.padding.is_empty()) << 5 | packet.count,
            packet.packet_type,
        ]);
        wire.extend_from_slice(&((length / 4 - 1) as u16).to_be_bytes());
        wire.extend_from_slice(&packet.body);
        wire.extend_from_slice(&packet.padding);
    }
    Ok(wire)
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RtcpCodec;
impl LayerCodec for RtcpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &rtcp_schema().protocol
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "RTCP is a complete UDP payload"));
        }
        let layer = typed_layer::<Rtcp>(NAME, layer)?;
        if layer.packets.len() > MAX_COMPOUND_ENTRIES {
            return Err(invalid(NAME, "exceeds 64 compound entries"));
        }
        let contribution = layer
            .packets
            .iter()
            .try_fold(0usize, |length, packet| {
                length
                    .checked_add(4)?
                    .checked_add(packet.body.len())?
                    .checked_add(packet.padding.len())
            })
            .ok_or_else(|| invalid(NAME, "message length overflow"))?;
        ensure_encode_budget(NAME, contribution, context)?;
        let wire = wire(layer)?;
        Ok(EncodedLayer::header(wire, Box::new(layer.clone())).with_fields(rtcp_layout()))
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let mut packets = Vec::new();
        let mut index = 0;
        while index < input.len() {
            if packets.len() >= MAX_COMPOUND_ENTRIES {
                return Err(invalid(NAME, "exceeds 64 compound entries"));
            }
            if input.len() < index + 4 || input[index] >> 6 != 2 {
                return Err(invalid(NAME, "truncated or non-v2 packet header"));
            }
            let length =
                (usize::from(u16::from_be_bytes([input[index + 2], input[index + 3]])) + 1) * 4;
            let end = index + length;
            if input.len() < end {
                return Err(invalid(NAME, "truncated packet body"));
            }
            let padding = if input[index] & 32 != 0 {
                let count = usize::from(input[end - 1]);
                if count == 0 || count > length - 4 || end != input.len() {
                    return Err(invalid(NAME, "invalid padding"));
                }
                count
            } else {
                0
            };
            let packet = Packet {
                packet_type: input[index + 1],
                count: input[index] & 31,
                body: input.slice(index + 4..end - padding),
                padding: input.slice(end - padding..end),
            };
            packet.contents()?;
            packets.push(packet);
            index = end;
        }
        if packets.is_empty() {
            return Err(invalid(NAME, "empty compound"));
        }
        Ok(DecodedLayer {
            layer: Box::new(Rtcp { packets }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: rtcp_layout(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Rtcp::default(), fields)
    }
}
