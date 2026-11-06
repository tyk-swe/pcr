// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNP3 link framing with per-block CRCs and transport/application fragment headers. No application-fragment reassembly.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{Reader, Writer, message_codec};
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dnp3 {
    pub control: u8,
    pub destination: u16,
    pub source: u16,
    pub has_transport: bool,
    pub transport: u8,
    pub has_application: bool,
    pub application_control: u8,
    pub function: u8,
    pub indications: u16,
    pub data: Bytes,
}
impl Default for Dnp3 {
    fn default() -> Self {
        Self {
            control: 0xc0,
            destination: 1,
            source: 1024,
            has_transport: false,
            transport: 0xc0,
            has_application: false,
            application_control: 0xc0,
            function: 1,
            indications: 0,
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn dnp3_schema() => { protocol: crate::protocol::BuiltinProtocol::Dnp3.id(), name: "Dnp3" }
 impl Dnp3 {
    "control" => { kind: Unsigned, derived: false, required: false, description: "control", reflect: control },
    "destination" => { kind: Unsigned, derived: false, required: false, description: "destination", reflect: destination },
    "source" => { kind: Unsigned, derived: false, required: false, description: "source", reflect: source },
    "has_transport" => { kind: Bool, derived: false, required: false, description: "has transport", reflect: has_transport },
    "transport" => { kind: Unsigned, derived: false, required: false, description: "transport", reflect: transport },
    "has_application" => { kind: Bool, derived: false, required: false, description: "has application", reflect: has_application },
    "application_control" => { kind: Unsigned, derived: false, required: false, description: "application control", reflect: application_control },
    "function" => { kind: Unsigned, derived: false, required: false, description: "function", reflect: function },
    "indications" => { kind: Unsigned, derived: false, required: false, description: "indications", reflect: indications },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
}
message_codec!(Dnp3Codec, Dnp3, dnp3_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Dnp3.as_str();
fn crc(b: &[u8]) -> u16 {
    let mut n = 0u16;
    for v in b {
        n ^= u16::from(*v);
        for _ in 0..8 {
            n = if n & 1 != 0 {
                (n >> 1) ^ 0xa6bc
            } else {
                n >> 1
            };
        }
    }
    !n
}
impl Dnp3 {
    fn reject_uncarried_fields(&self) -> Result<(), Error> {
        let default = Self::default();
        let application = self.has_transport && self.has_application;
        for (field, carried, unchanged) in [
            (
                "transport",
                self.has_transport,
                self.transport == default.transport,
            ),
            (
                "application_control",
                application,
                self.application_control == default.application_control,
            ),
            ("function", application, self.function == default.function),
            (
                "indications",
                application && self.function & 128 != 0,
                self.indications == default.indications,
            ),
        ] {
            if !carried && !unchanged {
                return Err(invalid(
                    NAME,
                    format!("{field} is not part of the selected headers"),
                ));
            }
        }
        Ok(())
    }

    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        self.reject_uncarried_fields()?;
        let mut p = Writer::new(NAME, 250);
        if self.has_transport {
            p.u8(self.transport)?;
            if self.has_application {
                if self.transport & 64 == 0 {
                    return Err(invalid(
                        NAME,
                        "application header requires first transport fragment",
                    ));
                }
                p.u8(self.application_control)?;
                p.u8(self.function)?;
                if self.function & 128 != 0 {
                    p.le16(self.indications)?;
                }
            }
            p.put(&self.data)?;
        } else if self.has_application || !self.data.is_empty() {
            return Err(invalid(NAME, "application data requires transport"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&[5, 100, (p.bytes.len() + 5) as u8, self.control])?;
        w.le16(self.destination)?;
        w.le16(self.source)?;
        w.le16(crc(&w.bytes))?;
        for chunk in p.bytes.chunks(16) {
            w.put(chunk)?;
            w.le16(crc(chunk))?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 3..4);
        r.mark(1, 4..6);
        r.mark(2, 6..8);
        if r.take(2)? != [5, 100] {
            return Err(unsupported(NAME, "invalid sync"));
        }
        let len = r.u8()? as usize;
        if len < 5 {
            return Err(invalid(NAME, "invalid length"));
        }
        let mut s = Self {
            control: r.u8()?,
            destination: r.le16()?,
            source: r.le16()?,
            ..Self::default()
        };
        if r.le16()? != crc(&b[..8]) {
            return Err(invalid(NAME, "header CRC mismatch"));
        }
        let mut payload = Vec::new();
        let mut left = len - 5;
        while left > 0 {
            let n = left.min(16);
            let chunk = r.take(n)?;
            if r.le16()? != crc(chunk) {
                return Err(invalid(NAME, "data CRC mismatch"));
            }
            payload.extend_from_slice(chunk);
            left -= n;
        }
        r.finish()?;
        if !payload.is_empty() {
            let mut p = Reader::new(NAME, &payload);
            s.has_transport = true;
            s.transport = p.u8()?;
            if s.transport & 64 != 0 {
                s.has_application = true;
                s.application_control = p.u8()?;
                s.function = p.u8()?;
                if s.function & 128 != 0 {
                    s.indications = p.le16()?;
                }
            }
            s.data = Bytes::copy_from_slice(p.rest());
        }
        Ok((s, r.take_layouts()))
    }
}
