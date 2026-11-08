use super::{Error, Reader};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRange {
    pub first: u64,
    pub last: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    Ack {
        delay: u64,
        ranges: Vec<AckRange>,
    },
    ResetStream {
        id: u64,
        error: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        error: u64,
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken(&'a [u8]),
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: &'a [u8],
    },
    Limit {
        kind: u64,
        id: Option<u64>,
        value: u64,
    },
    NewConnectionId {
        sequence: u64,
        retire_before: u64,
        id: &'a [u8],
        reset_token: &'a [u8],
    },
    RetireConnectionId(u64),
    PathChallenge(&'a [u8]),
    PathResponse(&'a [u8]),
    Close {
        application: bool,
        error: u64,
        frame_type: Option<u64>,
        reason: &'a [u8],
    },
    HandshakeDone,
    Datagram(&'a [u8]),
}

pub fn parse_frames(input: &[u8], max_frames: usize) -> Result<Vec<Frame<'_>>, Error> {
    let mut r = Reader::new(input);
    let mut frames = Vec::new();
    while r.left() != 0 {
        if frames.len() >= max_frames {
            return Err(Error::Limit);
        }
        let ty = r.varint()?;
        let frame = match ty {
            0 => {
                while r.input.get(r.position) == Some(&0) {
                    r.position += 1;
                }
                Frame::Padding
            }
            1 => Frame::Ping,
            2 | 3 => {
                let largest = r.varint()?;
                let delay = r.varint()?;
                let count = r.length()?;
                if count >= max_frames {
                    return Err(Error::Limit);
                }
                let first = largest.checked_sub(r.varint()?).ok_or(Error::Invalid)?;
                let mut ranges = vec![AckRange {
                    first,
                    last: largest,
                }];
                for _ in 0..count {
                    let gap = r.varint()?;
                    let last = ranges
                        .last()
                        .ok_or(Error::Invalid)?
                        .first
                        .checked_sub(gap)
                        .and_then(|n| n.checked_sub(2))
                        .ok_or(Error::Invalid)?;
                    let first = last.checked_sub(r.varint()?).ok_or(Error::Invalid)?;
                    ranges.push(AckRange { first, last });
                }
                if ty == 3 {
                    r.varint()?;
                    r.varint()?;
                    r.varint()?;
                }
                Frame::Ack { delay, ranges }
            }
            4 => Frame::ResetStream {
                id: r.varint()?,
                error: r.varint()?,
                final_size: r.varint()?,
            },
            5 => Frame::StopSending {
                id: r.varint()?,
                error: r.varint()?,
            },
            6 => {
                let offset = r.varint()?;
                let len = r.length()?;
                Frame::Crypto {
                    offset,
                    data: r.take(len)?,
                }
            }
            7 => {
                let len = r.length()?;
                Frame::NewToken(r.take(len)?)
            }
            8..=15 => {
                let id = r.varint()?;
                let offset = if ty & 4 != 0 { r.varint()? } else { 0 };
                let len = if ty & 2 != 0 { r.length()? } else { r.left() };
                Frame::Stream {
                    id,
                    offset,
                    fin: ty & 1 != 0,
                    data: r.take(len)?,
                }
            }
            16..=23 => {
                let id = if ty == 17 || ty == 21 {
                    Some(r.varint()?)
                } else {
                    None
                };
                Frame::Limit {
                    kind: ty,
                    id,
                    value: r.varint()?,
                }
            }
            24 => {
                let sequence = r.varint()?;
                let retire_before = r.varint()?;
                let len = usize::from(r.byte()?);
                if !(1..=20).contains(&len) || retire_before > sequence {
                    return Err(Error::Invalid);
                }
                Frame::NewConnectionId {
                    sequence,
                    retire_before,
                    id: r.take(len)?,
                    reset_token: r.take(16)?,
                }
            }
            25 => Frame::RetireConnectionId(r.varint()?),
            26 => Frame::PathChallenge(r.take(8)?),
            27 => Frame::PathResponse(r.take(8)?),
            28 | 29 => {
                let error = r.varint()?;
                let frame_type = if ty == 28 { Some(r.varint()?) } else { None };
                let len = r.length()?;
                Frame::Close {
                    application: ty == 29,
                    error,
                    frame_type,
                    reason: r.take(len)?,
                }
            }
            30 => Frame::HandshakeDone,
            48 | 49 => {
                let len = if ty == 49 { r.length()? } else { r.left() };
                Frame::Datagram(r.take(len)?)
            }
            _ => return Err(Error::UnsupportedFrame(ty)),
        };
        frames.push(frame);
    }
    Ok(frames)
}
