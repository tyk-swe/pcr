use super::{Error, Range};
use bytes::{Bytes, BytesMut};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Ranges {
    pieces: BTreeMap<u64, Bytes>,
    pub(super) bytes: usize,
    pub(super) conflicting: bool,
}
impl Ranges {
    pub(super) fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
        max_bytes: usize,
        max_ranges: usize,
    ) -> Result<u64, Error> {
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|n| *n < 1_u64 << 62)
            .ok_or(Error::Invalid)?;
        let mut cursor = offset;
        let mut uncovered = Vec::new();
        let mut repeated = 0;
        while cursor < end {
            if let Some((&start, old)) = self.pieces.range(..=cursor).next_back()
                && start + old.len() as u64 > cursor
            {
                let stop = (start + old.len() as u64).min(end);
                let old_start = (cursor - start) as usize;
                let new_start = (cursor - offset) as usize;
                let length = (stop - cursor) as usize;
                if old[old_start..old_start + length] != data[new_start..new_start + length] {
                    self.conflicting = true;
                    return Err(Error::Invalid);
                }
                repeated += length as u64;
                cursor = stop;
                continue;
            }
            let stop = self
                .pieces
                .range(cursor..)
                .next()
                .map_or(end, |(&n, _)| n.min(end));
            uncovered.push((cursor, (cursor - offset) as usize..(stop - offset) as usize));
            cursor = stop;
        }
        let extra = data.len().saturating_sub(repeated as usize);
        if self.bytes.saturating_add(extra) > max_bytes
            || self.pieces.len().saturating_add(uncovered.len()) > max_ranges
        {
            return Err(Error::Limit);
        }
        for (offset, range) in uncovered {
            self.pieces
                .insert(offset, Bytes::copy_from_slice(&data[range]));
        }
        self.bytes += extra;
        Ok(repeated)
    }
    pub(super) fn prefix(&self, offset: u64) -> Vec<u8> {
        let mut output = Vec::new();
        let mut cursor = offset;
        if let Some((&start, piece)) = self.pieces.range(..offset).next_back()
            && start + piece.len() as u64 > offset
        {
            output.extend_from_slice(&piece[(offset - start) as usize..]);
            cursor = start + piece.len() as u64;
        }
        for (&start, piece) in self.pieces.range(cursor..) {
            if start != cursor {
                break;
            }
            output.extend_from_slice(piece);
            cursor += piece.len() as u64;
        }
        output
    }
    pub(super) fn complete(&self, final_size: u64) -> bool {
        let mut cursor = 0;
        for (&offset, data) in &self.pieces {
            if cursor != offset {
                return false;
            }
            cursor += data.len() as u64;
        }
        cursor == final_size && !self.conflicting
    }
    pub(super) fn memory(&self) -> usize {
        self.bytes + self.pieces.len() * 96
    }
    pub(super) fn finish(self) -> Vec<Range> {
        let mut ranges = Vec::new();
        let mut current = BytesMut::new();
        let mut start = 0;
        for (offset, data) in self.pieces {
            if !current.is_empty() && start + current.len() as u64 != offset {
                ranges.push(Range {
                    offset: start,
                    data: current.split().freeze(),
                });
            }
            if current.is_empty() {
                start = offset;
            }
            current.extend_from_slice(&data);
        }
        if !current.is_empty() {
            ranges.push(Range {
                offset: start,
                data: current.freeze(),
            });
        }
        ranges
    }
}

pub(super) struct StreamState {
    pub(super) ranges: Ranges,
    pub(super) observed_end: u64,
    pub(super) final_size: Option<u64>,
    pub(super) reset_error: Option<u64>,
    pub(super) final_size_error: bool,
    pub(super) omitted_bytes: u64,
}
impl StreamState {
    pub(super) fn new() -> Self {
        Self {
            ranges: Ranges::default(),
            observed_end: 0,
            final_size: None,
            reset_error: None,
            final_size_error: false,
            omitted_bytes: 0,
        }
    }
    pub(super) fn set_final(&mut self, size: u64) -> Result<(), Error> {
        if self.final_size.is_some_and(|old| old != size) || size < self.observed_end {
            self.final_size_error = true;
            return Err(Error::Invalid);
        }
        self.final_size = Some(size);
        Ok(())
    }
    pub(super) fn observe_end(&mut self, end: u64) -> Result<(), Error> {
        self.observed_end = self.observed_end.max(end);
        if self.final_size.is_some_and(|size| self.observed_end > size) {
            self.final_size_error = true;
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(super) fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
        fin: bool,
        limits: &super::Limits,
    ) -> Result<u64, Error> {
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|end| *end < 1_u64 << 62)
            .ok_or(Error::Invalid)?;
        self.observe_end(end)?;
        if fin {
            self.set_final(end)?;
        }
        match self
            .ranges
            .insert(offset, data, limits.max_stream_bytes, limits.max_ranges)
        {
            Ok(n) => Ok(n),
            Err(e) => {
                self.omitted_bytes = self.omitted_bytes.saturating_add(data.len() as u64);
                Err(e)
            }
        }
    }
    pub(super) fn finish(
        self,
        id: u64,
        direction: super::Direction,
        early_data: bool,
    ) -> super::Stream {
        let complete = self
            .final_size
            .is_some_and(|size| self.ranges.complete(size))
            && self.reset_error.is_none()
            && !self.final_size_error
            && self.omitted_bytes == 0;
        super::Stream {
            id,
            direction,
            final_size: self.final_size,
            reset_error: self.reset_error,
            complete,
            conflicting_overlap: self.ranges.conflicting,
            final_size_error: self.final_size_error,
            omitted_bytes: self.omitted_bytes,
            ranges: self.ranges.finish(),
            early_data,
        }
    }
}
