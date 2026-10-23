// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! BACnet/IPv4 BVLC and NPDU/APDU envelopes. Application object data remains opaque.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BacnetIp {
    pub bvlc_function: u8,
    pub forwarded_address: Bytes,
    pub control: u8,
    pub destination_network: u16,
    pub destination_address: Bytes,
    pub hop_count: u8,
    pub source_network: u16,
    pub source_address: Bytes,
    pub network_message_type: u8,
    pub vendor_id: u16,
    pub data: Bytes,
}
impl Default for BacnetIp {
    fn default() -> Self {
        Self {
            bvlc_function: 10,
            forwarded_address: Bytes::from_static(&[0; 6]),
            control: 0,
            destination_network: 0,
            destination_address: Bytes::new(),
            hop_count: 255,
            source_network: 0,
            source_address: Bytes::new(),
            network_message_type: 0,
            vendor_id: 0,
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn bacnetip_schema() => { protocol: crate::layer::Id::new("bacnet_ip"), name: "BacnetIp" }
 impl BacnetIp {
    "bvlc_function" => { kind: Unsigned, derived: false, required: false, description: "bvlc function", reflect: bvlc_function },
    "forwarded_address" => { kind: Bytes, derived: false, required: false, description: "forwarded address", reflect: forwarded_address },
    "control" => { kind: Unsigned, derived: false, required: false, description: "control", reflect: control },
    "destination_network" => { kind: Unsigned, derived: false, required: false, description: "destination network", reflect: destination_network },
    "destination_address" => { kind: Bytes, derived: false, required: false, description: "destination address", reflect: destination_address },
    "hop_count" => { kind: Unsigned, derived: false, required: false, description: "hop count", reflect: hop_count },
    "source_network" => { kind: Unsigned, derived: false, required: false, description: "source network", reflect: source_network },
    "source_address" => { kind: Bytes, derived: false, required: false, description: "source address", reflect: source_address },
    "network_message_type" => { kind: Unsigned, derived: false, required: false, description: "network message type", reflect: network_message_type },
    "vendor_id" => { kind: Unsigned, derived: false, required: false, description: "vendor id", reflect: vendor_id },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
 layout fn bacnetip_layout();
}
fn bacnetip_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = bacnetip_layout();
    let mut fields = Vec::new();
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "bvlc_function",
            range: crate::layout::ByteRange::new(1, 2),
        });
    }
    fields
}
message_codec!(
    BacnetIpCodec,
    BacnetIp,
    bacnetip_schema,
    bacnetip_layout_wire
);

const NAME: &str = "bacnet_ip";
impl BacnetIp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        if matches!(self.bvlc_function, 4 | 10 | 11) {
            if self.bvlc_function == 4 {
                if self.forwarded_address.len() != 6 {
                    return Err(invalid(NAME, "forwarded address requires six bytes"));
                }
                p.put(&self.forwarded_address)?;
            }
            p.u8(1)?;
            p.u8(self.control)?;
            if self.control & 32 != 0 {
                p.u16(self.destination_network)?;
                p.u8(u8::try_from(self.destination_address.len())
                    .map_err(|_| invalid(NAME, "destination address too long"))?)?;
                p.put(&self.destination_address)?;
            }
            if self.control & 8 != 0 {
                p.u16(self.source_network)?;
                p.u8(u8::try_from(self.source_address.len())
                    .map_err(|_| invalid(NAME, "source address too long"))?)?;
                p.put(&self.source_address)?;
            }
            if self.control & 32 != 0 {
                p.u8(self.hop_count)?;
            }
            if self.control & 128 != 0 {
                p.u8(self.network_message_type)?;
                if self.network_message_type >= 128 {
                    p.u16(self.vendor_id)?;
                }
            }
        }
        p.put(&self.data)?;
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&[0x81, self.bvlc_function])?;
        w.u16(
            u16::try_from(p.bytes.len() + 4).map_err(|_| invalid(NAME, "BVLC message too long"))?,
        )?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        if r.u8()? != 0x81 {
            return Err(unsupported(NAME, "not BACnet/IPv4 BVLC"));
        }
        let mut s = Self {
            bvlc_function: r.u8()?,
            ..Self::default()
        };
        if r.u16()? as usize != b.len() {
            return Err(invalid(NAME, "BVLC length mismatch"));
        }
        if matches!(s.bvlc_function, 4 | 10 | 11) {
            if s.bvlc_function == 4 {
                s.forwarded_address = Bytes::copy_from_slice(r.take(6)?);
            }
            if r.u8()? != 1 {
                return Err(unsupported(NAME, "unknown NPDU version"));
            }
            s.control = r.u8()?;
            if s.control & 32 != 0 {
                s.destination_network = r.u16()?;
                let n = r.u8()? as usize;
                s.destination_address = Bytes::copy_from_slice(r.take(n)?);
            }
            if s.control & 8 != 0 {
                s.source_network = r.u16()?;
                let n = r.u8()? as usize;
                s.source_address = Bytes::copy_from_slice(r.take(n)?);
            }
            if s.control & 32 != 0 {
                s.hop_count = r.u8()?;
            }
            if s.control & 128 != 0 {
                s.network_message_type = r.u8()?;
                if s.network_message_type >= 128 {
                    s.vendor_id = r.u16()?;
                }
            } else {
                let first = *r
                    .bytes
                    .get(r.pos)
                    .ok_or_else(|| invalid(NAME, "missing APDU"))?;
                let n = match first >> 4 {
                    0 => {
                        if first & 8 != 0 {
                            6
                        } else {
                            4
                        }
                    }
                    1 => 2,
                    2 | 4..=7 => 3,
                    3 => {
                        if first & 8 != 0 {
                            5
                        } else {
                            3
                        }
                    }

                    _ => return Err(unsupported(NAME, "unknown APDU type")),
                };
                if r.left() < n {
                    return Err(invalid(NAME, "truncated APDU header"));
                }
            }
        }
        s.data = Bytes::copy_from_slice(r.rest());
        Ok(s)
    }
}
