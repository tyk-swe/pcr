// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub reserved: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Payload,
    pub(crate) wire: Bytes,
}
impl Frame {
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Payload {
    Data {
        data: Bytes,
        padding: Bytes,
    },
    Headers {
        fragment: Bytes,
        priority: Option<Priority>,
        padding: Bytes,
    },
    Priority(Priority),
    Reset {
        error_code: u32,
    },
    Settings(Vec<Setting>),
    PushPromise {
        promised_stream_id: u32,
        fragment: Bytes,
        padding: Bytes,
    },
    Ping([u8; 8]),
    Goaway {
        last_stream_id: u32,
        error_code: u32,
        debug: Bytes,
    },
    WindowUpdate {
        increment: u32,
    },
    Continuation(Bytes),
    Unknown(Bytes),
}
