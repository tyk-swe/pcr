// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod history;
mod static_table;

use bytes::Bytes;

use super::header_compression::{IntegerError, huffman, integer};
use crate::error::BoundaryError;

pub(crate) use history::History;
use static_table::STATIC;

#[derive(Debug)]
pub(crate) enum Failure {
    Truncated,
    Invalid,
    Unavailable,
    Ambiguous,
    Limit,
    Interrupted(BoundaryError),
}

impl From<IntegerError> for Failure {
    fn from(error: IntegerError) -> Self {
        match error {
            IntegerError::Truncated => Self::Truncated,
            IntegerError::Overflow => Self::Invalid,
        }
    }
}

impl From<huffman::Error> for Failure {
    fn from(error: huffman::Error) -> Self {
        match error {
            huffman::Error::Limit => Self::Limit,
            _ => Self::Invalid,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Field {
    pub name: Bytes,
    pub value: Bytes,
}

impl Field {
    pub(crate) fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }

    fn static_entry(index: u64) -> Result<Self, Failure> {
        let (name, value) = usize::try_from(index)
            .ok()
            .and_then(|index| STATIC.get(index))
            .ok_or(Failure::Invalid)?;
        Ok(Self {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        })
    }
}

#[derive(Debug)]
enum Reference {
    Indexed(u64),
    Name(u64, Bytes),
}

#[derive(Debug)]
enum Line {
    Field(Field),
    Relative(Reference),
    PostBase(Reference),
}

impl Line {
    fn read(reader: &mut Reader<'_>, maximum: usize, work: &mut Work<'_>) -> Result<Self, Failure> {
        let flags = reader.first()?;
        match flags.leading_zeros() {
            0 => {
                let index = reader.integer(6)?;
                if flags & 0x40 != 0 {
                    return Ok(Self::Field(Field::static_entry(index)?));
                }
                Ok(Self::Relative(Reference::Indexed(index)))
            }
            1 => {
                let index = reader.integer(4)?;
                let value = reader.string(7, maximum, work)?;
                if flags & 0x10 != 0 {
                    return Ok(Self::Field(Field {
                        name: Field::static_entry(index)?.name,
                        value,
                    }));
                }
                Ok(Self::Relative(Reference::Name(index, value)))
            }
            2 => {
                let name = reader.string(3, maximum, work)?;
                let value = reader.string(7, maximum - name.len(), work)?;
                Ok(Self::Field(Field { name, value }))
            }
            3 => Ok(Self::PostBase(Reference::Indexed(reader.integer(4)?))),
            _ => {
                let index = reader.integer(3)?;
                let value = reader.string(7, maximum, work)?;
                Ok(Self::PostBase(Reference::Name(index, value)))
            }
        }
    }

    fn minimum_size(&self) -> usize {
        match self {
            Self::Field(field) => field.size(),
            Self::Relative(Reference::Name(_, value))
            | Self::PostBase(Reference::Name(_, value)) => 32 + value.len(),
            _ => 32,
        }
    }

    fn resolve(&self, history: &History, base: u64, required: u64) -> Option<(Field, u64)> {
        let (reference, post_base) = match self {
            Self::Field(field) => return Some((field.clone(), 0)),
            Self::Relative(reference) => (reference, false),
            Self::PostBase(reference) => (reference, true),
        };
        let relative = match reference {
            Reference::Indexed(index) | Reference::Name(index, _) => *index,
        };
        let absolute = if post_base {
            base.checked_add(relative)?
        } else {
            base.checked_sub(relative)?.checked_sub(1)?
        };
        let insert_count = absolute.checked_add(1)?;
        if insert_count > required {
            return None;
        }
        let mut field = history.at(absolute, required)?.clone();
        if let Reference::Name(_, value) = reference {
            field.value = value.clone();
        }
        Some((field, insert_count))
    }
}

type Work<'a> = dyn FnMut(usize) -> Result<(), Failure> + 'a;

pub(crate) struct Section {
    pub fields: Vec<Field>,
    pub required_insert_count: u64,
    pub size: usize,
}

pub(crate) fn decode(
    input: &[u8],
    history: &History,
    maximum: usize,
    work: &mut Work<'_>,
) -> Result<Section, Failure> {
    let mut reader = Reader::new(input);
    let encoded = reader.integer(8)?;
    let negative = reader.first()? & 0x80 != 0;
    let delta = reader.integer(7)?;
    let mut lines = Vec::new();
    let mut remaining = maximum;
    while !reader.done() {
        work(1)?;
        let maximum = remaining.checked_sub(32).ok_or(Failure::Limit)?;
        let line = Line::read(&mut reader, maximum, work)?;
        remaining = remaining
            .checked_sub(line.minimum_size())
            .ok_or(Failure::Limit)?;
        lines.push(line);
    }
    let has_dynamic = lines.iter().any(|line| !matches!(line, Line::Field(_)));
    if encoded == 0 && !has_dynamic && !negative {
        return Ok(Section {
            fields: lines
                .into_iter()
                .filter_map(|line| match line {
                    Line::Field(field) => Some(field),
                    _ => None,
                })
                .collect(),
            required_insert_count: 0,
            size: maximum - remaining,
        });
    }
    if encoded == 0 || !has_dynamic {
        return Err(Failure::Invalid);
    }
    let full_range = history.reliable_capacity().ok_or(Failure::Unavailable)? / 32 * 2;
    if encoded > full_range {
        return Err(Failure::Invalid);
    }
    let first = if encoded == 1 {
        full_range
    } else {
        encoded - 1
    };
    let mut selected = None;
    // The capture does not establish a decoder insert count at field-section receipt.
    for required in
        (first..=history.insert_count()).step_by(usize::try_from(full_range).unwrap_or(usize::MAX))
    {
        work(1)?;
        let base = if negative {
            required
                .checked_sub(delta)
                .and_then(|base| base.checked_sub(1))
        } else {
            required.checked_add(delta)
        };
        let Some(base) = base else { continue };
        let Some(section) = resolve(&lines, history, maximum, base, required, work)? else {
            continue;
        };
        if selected.is_some() {
            return Err(Failure::Ambiguous);
        }
        selected = Some(section);
    }
    selected.ok_or(Failure::Unavailable)
}

fn resolve(
    lines: &[Line],
    history: &History,
    maximum: usize,
    base: u64,
    required: u64,
    work: &mut Work<'_>,
) -> Result<Option<Section>, Failure> {
    let mut fields = Vec::new();
    let mut largest = 0;
    let mut size = 0;
    for line in lines {
        work(1)?;
        let Some((field, count)) = line.resolve(history, base, required) else {
            return Ok(None);
        };
        largest = largest.max(count);
        size = usize::saturating_add(size, field.size());
        if size <= maximum {
            fields.push(field);
        }
    }
    if largest != required {
        return Ok(None);
    }
    if size > maximum {
        return Err(Failure::Limit);
    }
    Ok(Some(Section {
        fields,
        required_insert_count: required,
        size,
    }))
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn done(&self) -> bool {
        self.position == self.input.len()
    }

    fn first(&self) -> Result<u8, Failure> {
        self.input
            .get(self.position)
            .copied()
            .ok_or(Failure::Truncated)
    }

    fn integer(&mut self, prefix: u32) -> Result<u64, Failure> {
        Ok(integer(self.input, &mut self.position, prefix)?)
    }

    fn string(&mut self, prefix: u32, limit: usize, work: &mut Work<'_>) -> Result<Bytes, Failure> {
        let compressed = self.first()? & (1 << prefix) != 0;
        let length = usize::try_from(self.integer(prefix)?).map_err(|_| Failure::Limit)?;
        let end = self.position.checked_add(length).ok_or(Failure::Invalid)?;
        let data = self
            .input
            .get(self.position..end)
            .ok_or(Failure::Truncated)?;
        self.position = end;
        work(length)?;
        if compressed {
            return huffman::decode(data, limit, &mut || work(0), Failure::from).map(Bytes::from);
        }
        if length > limit {
            return Err(Failure::Limit);
        }
        Ok(Bytes::copy_from_slice(data))
    }
}
