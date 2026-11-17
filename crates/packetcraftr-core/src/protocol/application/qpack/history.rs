// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Failure, Field, Reader, Work};

struct Entry {
    field: Field,
    evicted_at: Option<u64>,
}

pub(crate) struct History {
    entries: Vec<Entry>,
    oldest: usize,
    resident_bytes: usize,
    capacity: usize,
    max_capacity: Option<u64>,
    reliable: bool,
    history_bytes: usize,
    limit: usize,
}

impl History {
    pub(crate) fn new(max_capacity: Option<u64>, limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            oldest: 0,
            resident_bytes: 0,
            capacity: 0,
            max_capacity,
            reliable: true,
            history_bytes: 0,
            limit,
        }
    }

    pub(super) fn reliable_capacity(&self) -> Option<u64> {
        self.max_capacity.filter(|_| self.reliable)
    }

    pub(crate) fn mark_incomplete(&mut self) {
        self.reliable = false;
    }

    pub(crate) fn insert_count(&self) -> u64 {
        self.entries.len() as u64
    }

    pub(super) fn at(&self, index: u64, count: u64) -> Option<&Field> {
        let entry = self.entries.get(usize::try_from(index).ok()?)?;
        entry
            .evicted_at
            .is_none_or(|evicted| evicted >= count)
            .then_some(&entry.field)
    }

    pub(crate) fn replay(&mut self, input: &[u8], work: &mut Work<'_>) -> Result<(), Failure> {
        let mut reader = Reader::new(input);
        while !reader.done() {
            work(1)?;
            let flags = reader.first()?;
            let max_field = self.capacity.min(self.limit).saturating_sub(32);
            let field = match flags.leading_zeros() {
                0 => {
                    let index = reader.integer(6)?;
                    let field = if flags & 0x40 == 0 {
                        self.relative(index)?.clone()
                    } else {
                        Field::static_entry(index)?
                    };
                    Field {
                        name: field.name,
                        value: reader.string(7, max_field, work)?,
                    }
                }
                1 => {
                    let name = reader.string(5, max_field, work)?;
                    let value = reader.string(7, max_field - name.len(), work)?;
                    Field { name, value }
                }
                2 => {
                    let capacity = reader.integer(5)?;
                    let maximum = self.max_capacity.ok_or(Failure::Unavailable)?;
                    if capacity > maximum {
                        return Err(Failure::Invalid);
                    }
                    // A capacity above the offline budget can still have a small resident table.
                    let capacity = usize::try_from(capacity).unwrap_or(usize::MAX);
                    self.evict_to(capacity, work)?;
                    self.capacity = capacity;
                    continue;
                }
                _ => self.relative(reader.integer(5)?)?.clone(),
            };
            self.insert(field, work)?;
        }
        Ok(())
    }

    fn relative(&self, index: u64) -> Result<&Field, Failure> {
        let index = usize::try_from(index).map_err(|_| Failure::Invalid)?;
        let index = self
            .entries
            .len()
            .checked_sub(index)
            .and_then(|n| n.checked_sub(1))
            .filter(|index| *index >= self.oldest)
            .ok_or(Failure::Invalid)?;
        Ok(&self.entries[index].field)
    }

    fn insert(&mut self, field: Field, work: &mut Work<'_>) -> Result<(), Failure> {
        let bytes = field.size();
        let target = self.capacity.checked_sub(bytes).ok_or(Failure::Invalid)?;
        let charge = bytes + 2 * std::mem::size_of::<Entry>();
        let used = self
            .history_bytes
            .checked_add(charge)
            .filter(|used| *used <= self.limit)
            .ok_or(Failure::Limit)?;
        self.evict_to(target, work)?;
        self.resident_bytes += bytes;
        self.history_bytes = used;
        self.entries.push(Entry {
            field,
            evicted_at: None,
        });
        Ok(())
    }

    fn evict_to(&mut self, capacity: usize, work: &mut Work<'_>) -> Result<(), Failure> {
        let count = self.insert_count();
        while self.resident_bytes > capacity {
            work(1)?;
            let entry = &mut self.entries[self.oldest];
            entry.evicted_at = Some(count);
            self.resident_bytes -= entry.field.size();
            self.oldest += 1;
        }
        Ok(())
    }
}
