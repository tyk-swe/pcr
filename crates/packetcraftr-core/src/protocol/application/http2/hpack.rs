// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeSet, VecDeque};

use bytes::Bytes;

use super::{Error, Limit};

mod huffman;

#[cfg(test)]
mod tests;

const STATIC: &[(&[u8], &[u8])] = &[
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

const DEFAULT_MAXIMUM: u32 = 4096;
const ENTRY_OVERHEAD: usize = 32;
const ORIGIN_BYTES: usize = 8;
const ENTRY_STRUCT_BYTES: usize = size_of::<Entry>();

#[derive(Clone, Debug)]
struct Charge {
    remaining: usize,
    origins: usize,
}

pub(crate) struct Limits {
    pub max_block_bytes: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_table_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Field {
    pub name: Bytes,
    pub value: Bytes,
    pub never_indexed: bool,
    pub origins: Vec<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct Block {
    pub fields: Vec<Field>,
    pub decoded_bytes: usize,
}

#[derive(Clone, Debug)]
struct Entry {
    name: Bytes,
    value: Bytes,
    name_origins: Vec<u64>,
    insert_origin: u64,
}
impl Entry {
    fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
    fn charge(&self) -> usize {
        self.size() + self.name_origins.len() * ORIGIN_BYTES + ENTRY_STRUCT_BYTES
    }
    fn origins(&self) -> Vec<u64> {
        let mut origins = self.name_origins.clone();
        origins.push(self.insert_origin);
        origins.sort_unstable();
        origins.dedup();
        origins
    }
}

pub(crate) struct Decoder {
    table: VecDeque<Entry>,
    table_bytes: usize,
    accounted_bytes: usize,
    effective_max: u32,
    ceiling: u32,
    pending_min: Option<u32>,
    limits: Limits,
    poisoned: bool,
}
impl Decoder {
    pub(crate) fn new(limits: Limits) -> Result<Self, Error> {
        if limits.max_block_bytes == 0
            || limits.max_header_bytes == 0
            || limits.max_headers == 0
            || limits.max_table_bytes == 0
        {
            return Err(Error::Invalid("HPACK limits must be nonzero"));
        }
        Ok(Self {
            table: VecDeque::new(),
            table_bytes: 0,
            accounted_bytes: 0,
            effective_max: DEFAULT_MAXIMUM,
            ceiling: DEFAULT_MAXIMUM,
            pending_min: None,
            limits,
            poisoned: false,
        })
    }

    pub(crate) fn permit_table_size(&mut self, maximum: u32) {
        // An encoder may act on an advertised increase before sending its ACK.
        // Decreases still become mandatory through acknowledge_table_size.
        self.ceiling = self.ceiling.max(maximum);
    }

    pub(crate) fn acknowledge_table_size(&mut self, maximum: u32) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Compression("decoder is poisoned"));
        }
        self.ceiling = maximum;
        self.pending_min = Some(match self.pending_min {
            Some(minimum) => minimum.min(maximum),
            None => maximum,
        });
        Ok(())
    }

    pub(crate) fn decode(&mut self, block: &Bytes, origin: u64) -> Result<Block, Error> {
        if self.poisoned {
            return Err(Error::Compression("decoder is poisoned"));
        }
        self.decode_block(block, origin).inspect_err(|_| {
            self.poisoned = true;
        })
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.accounted_bytes
    }

    pub(crate) fn retained_origins(&self) -> Vec<u64> {
        let mut set = BTreeSet::new();
        for entry in &self.table {
            set.extend(entry.name_origins.iter().copied());
            set.insert(entry.insert_origin);
        }
        set.into_iter().collect()
    }

    fn decode_block(&mut self, block: &Bytes, origin: u64) -> Result<Block, Error> {
        if block.len() > self.limits.max_block_bytes {
            return Err(Error::Limit(Limit::BlockBytes));
        }
        let must_shrink = self
            .pending_min
            .is_some_and(|minimum| minimum < self.effective_max);
        let mut fields = Vec::new();
        let mut decoded_bytes = 0usize;
        let mut origin_bytes = 0usize;
        let mut pos = 0usize;
        let mut updating = true;
        let mut updated = false;
        while pos < block.len() {
            let first = block[pos];
            if first & 0xe0 == 0x20 {
                if !updating {
                    return Err(Error::Compression("table size update after header fields"));
                }
                self.size_update(block, &mut pos, must_shrink && !updated)?;
                updated = true;
                continue;
            }
            if updating {
                updating = false;
                if must_shrink && !updated {
                    return Err(Error::Compression("missing required table size update"));
                }
            }
            if fields.len() >= self.limits.max_headers {
                return Err(Error::Limit(Limit::HeaderCount));
            }
            let budget = self
                .limits
                .max_header_bytes
                .checked_sub(decoded_bytes)
                .and_then(|remaining| remaining.checked_sub(ENTRY_OVERHEAD))
                .ok_or(Error::Limit(Limit::HeaderBytes))?;
            let mut charge = Charge {
                remaining: budget,
                origins: origin_bytes,
            };
            let (field, lineage) = if first & 0x80 != 0 {
                let index = integer(block, &mut pos, 7)?;
                (self.indexed(index, origin, &mut charge)?, None)
            } else {
                let (prefix, never_indexed, incremental) = if first & 0xc0 == 0x40 {
                    (6, false, true)
                } else {
                    (4, first & 0x10 != 0, false)
                };
                let index = integer(block, &mut pos, prefix)?;
                let (field, lineage) =
                    self.literal(block, &mut pos, index, never_indexed, origin, &mut charge)?;
                (field, incremental.then_some(lineage))
            };
            origin_bytes = charge.origins;
            decoded_bytes = decoded_bytes
                .checked_add(field.name.len() + field.value.len() + ENTRY_OVERHEAD)
                .ok_or(Error::Limit(Limit::HeaderBytes))?;
            if let Some(lineage) = lineage {
                self.insert(&field, lineage, origin)?;
            }
            fields.push(field);
        }
        if updating && must_shrink && !updated {
            return Err(Error::Compression("missing required table size update"));
        }
        self.pending_min = None;
        Ok(Block {
            fields,
            decoded_bytes,
        })
    }

    fn size_update(
        &mut self,
        block: &[u8],
        pos: &mut usize,
        require_minimum: bool,
    ) -> Result<(), Error> {
        let maximum = integer(block, pos, 5)?;
        if maximum > u64::from(self.ceiling) {
            return Err(Error::Compression(
                "table size update exceeds the advertised maximum",
            ));
        }
        if require_minimum
            && self
                .pending_min
                .is_some_and(|minimum| maximum > u64::from(minimum))
        {
            return Err(Error::Compression("missing minimum table size update"));
        }
        self.effective_max = u32::try_from(maximum).expect("bounded by u32 ceiling");
        self.evict();
        if self.accounted_bytes > self.limits.max_table_bytes {
            return Err(Error::Limit(Limit::TableBytes));
        }
        Ok(())
    }

    fn evict(&mut self) {
        while self.table_bytes > self.effective_max as usize {
            let Some(entry) = self.table.pop_back() else {
                break;
            };
            self.table_bytes -= entry.size();
            self.accounted_bytes -= entry.charge();
        }
    }

    fn resolve(&self, index: u64) -> Result<Resolved<'_>, Error> {
        let index =
            usize::try_from(index).map_err(|_| Error::Compression("header index out of range"))?;
        if index == 0 {
            return Err(Error::Compression("header index zero is invalid"));
        }
        if index <= STATIC.len() {
            let (name, value) = STATIC[index - 1];
            return Ok(Resolved::Static(name, value));
        }
        self.table
            .get(index - STATIC.len() - 1)
            .map(Resolved::Dynamic)
            .ok_or(Error::Compression("header index out of range"))
    }

    fn charge_origins(&self, lineage_len: usize, charge: &mut Charge) -> Result<(), Error> {
        let added = lineage_len
            .checked_add(1)
            .and_then(|origins| origins.checked_mul(ORIGIN_BYTES))
            .ok_or(Error::Limit(Limit::OriginBytes))?;
        charge.origins = charge
            .origins
            .checked_add(added)
            .ok_or(Error::Limit(Limit::OriginBytes))?;
        if charge.origins > self.limits.max_header_bytes {
            return Err(Error::Limit(Limit::OriginBytes));
        }
        Ok(())
    }

    fn indexed(&self, index: u64, origin: u64, charge: &mut Charge) -> Result<Field, Error> {
        let resolved = self.resolve(index)?;
        if resolved.name().len() + resolved.value().len() > charge.remaining {
            return Err(Error::Limit(Limit::HeaderBytes));
        }
        self.charge_origins(resolved.origins_len(), charge)?;
        let mut origins = resolved.origins();
        origins.push(origin);
        origins.sort_unstable();
        origins.dedup();
        Ok(Field {
            name: resolved.name_bytes(),
            value: resolved.value_bytes(),
            never_indexed: false,
            origins,
        })
    }

    fn literal(
        &self,
        block: &Bytes,
        pos: &mut usize,
        index: u64,
        never_indexed: bool,
        origin: u64,
        charge: &mut Charge,
    ) -> Result<(Field, Vec<u64>), Error> {
        let (name, lineage) = if index == 0 {
            let value = self.string(block, pos, charge.remaining)?;
            self.charge_origins(0, charge)?;
            (value, Vec::new())
        } else {
            let resolved = self.resolve(index)?;
            if resolved.name().len() > charge.remaining {
                return Err(Error::Limit(Limit::HeaderBytes));
            }
            self.charge_origins(resolved.origins_len(), charge)?;
            (resolved.name_bytes(), resolved.origins())
        };
        let value = self.string(block, pos, charge.remaining - name.len())?;
        let mut origins = lineage.clone();
        origins.push(origin);
        origins.sort_unstable();
        origins.dedup();
        Ok((
            Field {
                name,
                value,
                never_indexed,
                origins,
            },
            lineage,
        ))
    }

    fn insert(&mut self, field: &Field, name_lineage: Vec<u64>, origin: u64) -> Result<(), Error> {
        let size = field.name.len() + field.value.len() + ENTRY_OVERHEAD;
        let charge = size
            .checked_add(name_lineage.len() * ORIGIN_BYTES)
            .and_then(|charge| charge.checked_add(ENTRY_STRUCT_BYTES))
            .ok_or(Error::Limit(Limit::TableBytes))?;
        while self.table_bytes + size > self.effective_max as usize && !self.table.is_empty() {
            let entry = self.table.pop_back().expect("nonempty table");
            self.table_bytes -= entry.size();
            self.accounted_bytes -= entry.charge();
        }
        if size > self.effective_max as usize {
            return Ok(());
        }
        if self.accounted_bytes + charge > self.limits.max_table_bytes {
            return Err(Error::Limit(Limit::TableBytes));
        }
        let entry = Entry {
            name: compact(&field.name),
            value: compact(&field.value),
            name_origins: name_lineage,
            insert_origin: origin,
        };
        self.table_bytes += size;
        self.accounted_bytes += charge;
        self.table.push_front(entry);
        Ok(())
    }

    fn string(&self, block: &Bytes, pos: &mut usize, max_output: usize) -> Result<Bytes, Error> {
        let first = *block
            .get(*pos)
            .ok_or(Error::Compression("truncated string literal"))?;
        let huffman_coded = first & 0x80 != 0;
        let length = integer(block, pos, 7)?;
        let length =
            usize::try_from(length).map_err(|_| Error::Compression("string length overflows"))?;
        let end = pos
            .checked_add(length)
            .ok_or(Error::Compression("string length overflows"))?;
        if end > block.len() {
            return Err(Error::Compression("truncated string literal"));
        }
        let raw = &block[*pos..end];
        *pos = end;
        if huffman_coded {
            Ok(Bytes::from(huffman::decode(raw, max_output)?))
        } else {
            if length > max_output {
                return Err(Error::Limit(Limit::HeaderBytes));
            }
            Ok(block.slice_ref(raw))
        }
    }
}

enum Resolved<'a> {
    Static(&'static [u8], &'static [u8]),
    Dynamic(&'a Entry),
}
impl Resolved<'_> {
    fn name(&self) -> &[u8] {
        match self {
            Self::Static(name, _) => name,
            Self::Dynamic(entry) => &entry.name,
        }
    }
    fn value(&self) -> &[u8] {
        match self {
            Self::Static(_, value) => value,
            Self::Dynamic(entry) => &entry.value,
        }
    }
    fn name_bytes(&self) -> Bytes {
        match self {
            Self::Static(name, _) => Bytes::from_static(name),
            Self::Dynamic(entry) => entry.name.clone(),
        }
    }
    fn value_bytes(&self) -> Bytes {
        match self {
            Self::Static(_, value) => Bytes::from_static(value),
            Self::Dynamic(entry) => entry.value.clone(),
        }
    }
    fn origins_len(&self) -> usize {
        match self {
            Self::Static(..) => 0,
            Self::Dynamic(entry) => entry.name_origins.len() + 1,
        }
    }
    fn origins(&self) -> Vec<u64> {
        match self {
            Self::Static(..) => Vec::new(),
            Self::Dynamic(entry) => entry.origins(),
        }
    }
}

fn compact(bytes: &Bytes) -> Bytes {
    Bytes::copy_from_slice(bytes)
}

fn integer(input: &[u8], pos: &mut usize, prefix: u32) -> Result<u64, Error> {
    let first = *input
        .get(*pos)
        .ok_or(Error::Compression("truncated integer"))?;
    *pos += 1;
    let mask = (1u64 << prefix) - 1;
    let mut value = u64::from(first) & mask;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let byte = *input
            .get(*pos)
            .ok_or(Error::Compression("truncated integer"))?;
        *pos += 1;
        let digit = u64::from(byte & 0x7f);
        if shift >= 64 || digit > (u64::MAX >> shift) {
            return Err(Error::Compression("integer overflows"));
        }
        value = value
            .checked_add(digit << shift)
            .ok_or(Error::Compression("integer overflows"))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}
