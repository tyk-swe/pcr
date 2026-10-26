// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Error, ScopedFlowKey, Source, StreamRecord, compact_hex, sources};
use packetcraftr_core::{analysis::http2 as analysis, protocol::application::http2 as wire};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Priority {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u16,
}
impl From<wire::Priority> for Priority {
    fn from(value: wire::Priority) -> Self {
        Self {
            exclusive: value.exclusive,
            dependency: value.dependency,
            weight: value.weight,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}
impl From<wire::Setting> for Setting {
    fn from(value: wire::Setting) -> Self {
        Self {
            id: value.id,
            value: value.value,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    Headers {
        fragment_hex: String,
        priority: Option<Priority>,
        padding_hex: String,
    },
    Priority {
        exclusive: bool,
        dependency: u32,
        weight: u16,
    },
    Reset {
        error_code: u32,
    },
    Settings {
        settings: Vec<Setting>,
    },
    PushPromise {
        promised_stream_id: u32,
        fragment_hex: String,
        padding_hex: String,
    },
    Ping {
        opaque_hex: String,
    },
    Goaway {
        last_stream_id: u32,
        error_code: u32,
        debug_hex: String,
    },
    WindowUpdate {
        increment: u32,
    },
    Continuation {
        fragment_hex: String,
    },
    Unknown {
        payload_hex: String,
    },
}

#[derive(Debug, Serialize)]
pub struct Frame {
    pub index: u64,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub http2_stream_id: u32,
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub reserved: bool,
    pub header_wire_hex: String,
    pub control: Option<Control>,
    pub payload_wire_hex: Option<String>,
    pub data_bytes: u64,
    pub padding_bytes: usize,
    pub sources: Vec<Source>,
}
impl From<wire::Control> for Control {
    fn from(control: wire::Control) -> Self {
        match control {
            wire::Control::Headers {
                fragment,
                priority,
                padding,
            } => Self::Headers {
                fragment_hex: compact_hex(&fragment),
                priority: priority.map(Into::into),
                padding_hex: compact_hex(&padding),
            },
            wire::Control::Priority(priority) => Self::Priority {
                exclusive: priority.exclusive,
                dependency: priority.dependency,
                weight: priority.weight,
            },
            wire::Control::Reset { error_code } => Self::Reset { error_code },
            wire::Control::Settings(settings) => Self::Settings {
                settings: settings.into_iter().map(Into::into).collect(),
            },
            wire::Control::PushPromise {
                promised_stream_id,
                fragment,
                padding,
            } => Self::PushPromise {
                promised_stream_id,
                fragment_hex: compact_hex(&fragment),
                padding_hex: compact_hex(&padding),
            },
            wire::Control::Ping(opaque) => Self::Ping {
                opaque_hex: compact_hex(&opaque),
            },
            wire::Control::Goaway {
                last_stream_id,
                error_code,
                debug,
            } => Self::Goaway {
                last_stream_id,
                error_code,
                debug_hex: compact_hex(&debug),
            },
            wire::Control::WindowUpdate { increment } => Self::WindowUpdate { increment },
            wire::Control::Continuation(fragment) => Self::Continuation {
                fragment_hex: compact_hex(&fragment),
            },
            wire::Control::Unknown(payload) => Self::Unknown {
                payload_hex: compact_hex(&payload),
            },
        }
    }
}

impl TryFrom<analysis::Frame> for Frame {
    type Error = Error;
    fn try_from(value: analysis::Frame) -> Result<Self, Error> {
        let (control, payload_wire_hex, data_bytes, padding_bytes) = match value.body {
            analysis::FrameBody::Data {
                data_bytes,
                padding_bytes,
            } => (None, None, data_bytes, padding_bytes),
            analysis::FrameBody::Control {
                control,
                payload_wire,
            } => {
                let padding_bytes = match &control {
                    wire::Control::Headers { padding, .. }
                    | wire::Control::PushPromise { padding, .. } => padding.len(),
                    _ => 0,
                };
                (
                    Some(control.into()),
                    Some(compact_hex(&payload_wire)),
                    0,
                    padding_bytes,
                )
            }
        };
        Ok(Self {
            index: value.index,
            stream: value.stream,
            generation: value.generation,
            flow: value.flow.into(),
            http2_stream_id: value.header.stream_id,
            length: value.header.length,
            frame_type: value.header.frame_type,
            flags: value.header.flags,
            reserved: value.header.reserved,
            header_wire_hex: compact_hex(&value.header_wire),
            control,
            payload_wire_hex,
            data_bytes,
            padding_bytes,
            sources: sources(&value.sources)?,
        })
    }
}
impl StreamRecord for Frame {
    fn event_name(&self) -> &'static str {
        "http2_frame"
    }
}
