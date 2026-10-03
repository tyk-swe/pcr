// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::analysis::provenance::SourceSet;
use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;

struct Span {
    end: u64,
    sources: SourceSet,
}

pub(crate) struct SourceBuffer {
    bytes: BytesMut,
    spans: VecDeque<Span>,
    base: u64,
    offset: u64,
}
impl SourceBuffer {
    pub(crate) fn new() -> Self {
        Self {
            bytes: BytesMut::new(),
            spans: VecDeque::new(),
            base: 0,
            offset: 0,
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn push(&mut self, bytes: Bytes, sources: SourceSet) {
        self.offset += bytes.len() as u64;
        self.bytes.extend_from_slice(&bytes);
        self.spans.push_back(Span {
            end: self.offset,
            sources,
        });
    }
    fn consume(&mut self, n: usize) -> Vec<SourceSet> {
        self.base += n as u64;
        let _ = self.bytes.split_to(n);
        let mut dropped = Vec::new();
        while self.spans.front().is_some_and(|span| span.end <= self.base) {
            if let Some(span) = self.spans.pop_front() {
                dropped.push(span.sources);
            }
        }
        if self.bytes.is_empty() {
            self.bytes = BytesMut::new();
        }
        if self.spans.is_empty() {
            self.spans = VecDeque::new();
        }
        dropped
    }
    pub(crate) fn discard(&mut self, n: usize) -> Vec<SourceSet> {
        self.consume(n)
    }
    pub(crate) fn take(&mut self, n: usize) -> (Bytes, Vec<SourceSet>) {
        let taken = Bytes::copy_from_slice(&self.bytes[..n]);
        (taken, self.consume(n))
    }
    pub(crate) fn contributors(&self, n: usize) -> Vec<SourceSet> {
        let end = self.base + n as u64;
        let mut start = self.base;
        let mut sets = Vec::new();
        for span in &self.spans {
            if start >= end {
                break;
            }
            if span.end > start {
                sets.push(span.sources.clone());
            }
            start = span.end;
        }
        sets
    }
}
pub(crate) fn union_balanced(
    sets: Vec<SourceSet>,
) -> Result<Option<SourceSet>, crate::analysis::provenance::Error> {
    let mut level: Vec<SourceSet> = sets;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut iter = level.into_iter();
        while let Some(first) = iter.next() {
            next.push(match iter.next() {
                Some(second) => first.union(&second)?,
                None => first,
            });
        }
        level = next;
    }
    Ok(level.pop())
}
