// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Header-block assembly and bounded HPACK decoding.

use super::super::{Chain, ChainHead, ConnectionState, Context, Decoded, Evidence, Fault, Pos};
use crate::analysis::http2::Error;
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget::{self, Charge};
use crate::analysis::http2::buffer::union_balanced;
use crate::analysis::http2::model::{Certainty, Header, IssueScope, Status};
use crate::analysis::http2::side::Side;

use crate::protocol::application::http2 as wire;
use crate::protocol::application::http2::hpack;
use bytes::Bytes;
use std::collections::HashSet;

impl ConnectionState {
    pub(super) fn block_start(
        &mut self,
        at: Pos,
        head: ChainHead,
        fragment: Bytes,
        evidence: Evidence,
        context: &mut Context<'_>,
        end_headers: bool,
    ) -> Result<(), Error> {
        let Pos { side, stream_id } = at;
        let Evidence { wire, sources } = evidence;
        if fragment.len() > context.limits.max_header_block_bytes {
            self.limited_block(context, side, stream_id, wire, sources)?;
            return Ok(());
        }
        let mut charge = Charge::default();
        context.charge(&mut charge, fragment.len() + budget::HEADER_OVERHEAD)?;
        let mut chain = Chain {
            stream_id,
            head,
            bytes: bytes::BytesMut::from(&fragment[..]),
            frames: 1,
            sets: Vec::new(),
            charge,
        };
        if let Some(sources) = sources.clone() {
            if let Err(error) = context.track(&mut chain.charge, &sources) {
                context.release_all(&mut chain.charge)?;
                return Err(error);
            }
            chain.sets.push(sources);
        }
        if chain.bytes.len() > context.limits.max_header_block_bytes {
            context.release_all(&mut chain.charge)?;
            self.limited_block(context, side, stream_id, wire, sources)?;
            return Ok(());
        }
        if end_headers {
            self.block_done(side, chain, context)
        } else {
            let dir = self
                .directions
                .get_mut(side)
                .ok_or(Error::Invariant("dir"))?;
            dir.chain = Some(chain);
            Ok(())
        }
    }

    pub(super) fn block_continue(
        &mut self,
        side: Side,
        stream_id: u32,
        fragment: Bytes,
        flags: u8,
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Evidence { wire, sources } = evidence;
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("dir"))?;
        let Some(mut chain) = dir.chain.take() else {
            return Ok(());
        };
        debug_assert_eq!(chain.stream_id, stream_id);
        if chain.bytes.len() + fragment.len() > context.limits.max_header_block_bytes
            || chain.frames + 1 > context.limits.max_continuations + 1
        {
            context.release_all(&mut chain.charge)?;
            self.limited_block(context, side, stream_id, wire, sources)?;
            return Ok(());
        }
        if let Err(error) = context.charge(&mut chain.charge, fragment.len()) {
            context.release_all(&mut chain.charge)?;
            return Err(error);
        }
        chain.bytes.extend_from_slice(&fragment);
        chain.frames += 1;
        if let Some(sources) = sources.clone() {
            if let Err(error) = context.track(&mut chain.charge, &sources) {
                context.release_all(&mut chain.charge)?;
                return Err(error);
            }
            chain.sets.push(sources);
        }
        if flags & wire::FLAG_END_HEADERS != 0 {
            self.block_done(side, chain, context)
        } else {
            let dir = self
                .directions
                .get_mut(side)
                .ok_or(Error::Invariant("dir"))?;
            dir.chain = Some(chain);
            Ok(())
        }
    }

    fn limited_block(
        &mut self,
        context: &mut Context<'_>,
        side: Side,
        stream_id: u32,
        wire: Bytes,
        sources: Option<crate::analysis::provenance::SourceSet>,
    ) -> Result<(), Error> {
        let flow = self.dir_flow(side);
        self.issue(
            context,
            Fault::new(
                flow,
                IssueScope::Connection,
                Status::Limit,
                IssueCode::BlockLimit,
                "a header block exceeded its configured bound",
            )
            .stream(Some(stream_id))
            .evidence(wire, sources),
        )?;
        self.fail(context, Status::Limit)
    }

    fn block_done(
        &mut self,
        side: Side,
        mut chain: Chain,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.release_all(&mut chain.charge)?;
        context.check_deadline()?;
        let bytes = chain.bytes.freeze();
        let stream_id = chain.stream_id;
        let origin = self.streams.next_origin;
        self.streams.next_origin += 1;
        let block_sets = std::mem::take(&mut chain.sets);
        let block_sources = union_balanced(block_sets)?;
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("dir"))?;
        if let Some(sources) = block_sources.clone() {
            context.track(&mut dir.charge, &sources)?;
            dir.block_sources.insert(origin, sources);
            context.charge(&mut dir.charge, budget::ORIGIN_ENTRY_OVERHEAD)?;
        }
        let scratch = 6usize
            .checked_mul(context.limits.max_header_bytes)
            .and_then(|v| {
                v.checked_add(
                    2usize.saturating_mul(
                        context
                            .limits
                            .max_headers
                            .saturating_mul(size_of::<hpack::Field>()),
                    ),
                )
            })
            .and_then(|v| v.checked_add(2usize.saturating_mul(context.limits.max_table_bytes)))
            .and_then(|v| v.checked_add(2usize.saturating_mul(bytes.len())))
            .ok_or(Error::Application(
                crate::analysis::application::Error::Limit {
                    field: "hpack_scratch",
                    limit: context.limits.max_header_bytes,
                },
            ))?;
        context.reserve_scratch(scratch)?;
        let result = (|| {
            let updates = hpack::table_size_updates(&bytes, &mut || {
                context
                    .check_deadline()
                    .map_err(hpack::DecodeError::Interrupted)
            });
            let mut ambiguous_minimum = false;
            let decoded = match updates {
                Err(error) => Err(error),
                Ok(updates) => {
                    let (minimum, confirmed_prefix, pending_uncertain) =
                        updates.map_or((None, 0, None), |(_, maximum)| {
                            self.control.settings[side.peer()].causal_table_minimum(maximum)
                        });
                    let uncertain = [
                        pending_uncertain,
                        self.control.settings[side.peer()].uncertain_table_minimum,
                    ]
                    .into_iter()
                    .flatten()
                    .min();
                    let decoder = self
                        .directions
                        .get_mut(side)
                        .ok_or(Error::Invariant("dir"))?
                        .decoder
                        .as_mut()
                        .ok_or(Error::Invariant("decoder"))?;
                    ambiguous_minimum = uncertain.is_some_and(|bound| {
                        decoder.table_maximum() > bound
                            && updates.is_none_or(|(observed, _)| observed > bound)
                    });
                    if let Some(minimum) = minimum {
                        decoder.require_table_minimum(minimum);
                    }
                    let decoded = decoder.decode_checked(&bytes, origin, &mut || {
                        context
                            .check_deadline()
                            .map_err(hpack::DecodeError::Interrupted)
                    });
                    if decoded.is_ok() {
                        self.control.settings[side.peer()].uncertain_table_minimum = None;
                        if let Some((minimum, _)) = updates {
                            self.control.settings[side.peer()]
                                .observed_table_updates(minimum, confirmed_prefix);
                        }
                    }
                    decoded
                }
            };
            let decoded = match decoded {
                Ok(block) => Ok(block),
                Err(hpack::DecodeError::Wire(error)) => Err(error),
                Err(hpack::DecodeError::Interrupted(error)) => return Err(error),
            };
            if decoded.is_ok() && ambiguous_minimum {
                self.issue(context, Fault::new(self.dir_flow(side), IssueScope::Compression, Status::Incomplete, IssueCode::HpackTableSizeOrdering, "an earlier table shrink may precede or follow receipt of SETTINGS; its required minimum cannot be confirmed").stream(Some(stream_id)).certainty(Certainty::ObservedOrder).evidence(bytes.clone(), block_sources.clone()))?;
            }
            self.decoder_sync(side, context)?;
            match decoded {
                Err(error) => {
                    let flow = self.dir_flow(side);
                    let (code, status) = match &error {
                        wire::Error::Limit(_) => (IssueCode::HeaderBlockLimit, Status::Limit),
                        _ => (IssueCode::HpackDecode, Status::Malformed),
                    };
                    self.issue(
                        context,
                        Fault::new(
                            flow,
                            IssueScope::Compression,
                            status,
                            code,
                            error.to_string(),
                        )
                        .stream(Some(stream_id))
                        .evidence(bytes, block_sources),
                    )?;
                    self.fail(context, status)?;
                    Ok(())
                }
                Ok(block) => {
                    context.check_deadline()?;
                    let mut compression_sets: Vec<crate::analysis::provenance::SourceSet> =
                        Vec::new();
                    {
                        let dir = self.directions.get(side).ok_or(Error::Invariant("dir"))?;
                        let mut seen = HashSet::new();
                        for field in &block.fields {
                            for origin in &field.origins {
                                context.check_deadline()?;
                                if !seen.insert(*origin) {
                                    continue;
                                }
                                let Some(set) = dir.block_sources.get(origin) else {
                                    return Err(Error::Invariant("origin sources missing"));
                                };
                                // Origins are keyed above; the balanced source union
                                // deduplicates overlapping physical frames without an
                                // all-previous-sets comparison for each origin.
                                compression_sets.push(set.clone());
                            }
                        }
                    }
                    let compression = union_balanced(compression_sets)?;
                    let decoded_bytes = block.decoded_bytes;
                    {
                        let dir = self
                            .directions
                            .get_mut(side)
                            .ok_or(Error::Invariant("dir"))?;
                        let kept: HashSet<u64> = dir
                            .decoder
                            .as_ref()
                            .ok_or(Error::Invariant("decoder"))?
                            .retained_origins()
                            .into_iter()
                            .collect();
                        let removed: Vec<u64> = dir
                            .block_sources
                            .keys()
                            .filter(|id| !kept.contains(*id))
                            .copied()
                            .collect();
                        for id in removed {
                            if let Some(set) = dir.block_sources.remove(&id) {
                                context.untrack(&mut dir.charge, &set)?;
                                context.release(&mut dir.charge, budget::ORIGIN_ENTRY_OVERHEAD)?;
                            }
                        }
                    }
                    if let Some(limit) = self.control.settings[side.peer()]
                        .advertised
                        .max_header_list_size
                        && decoded_bytes > limit as usize
                    {
                        let flow = self.dir_flow(side);
                        self.issue(
                        context,
                        Fault::new(flow, IssueScope::Stream, Status::Incomplete, IssueCode::HeaderListSizeAdvisory, format!( "decoded header list {decoded_bytes} exceeds the peer's advertised maximum" )).stream(Some(stream_id)).certainty(Certainty::ObservedOrder),
                    )?;
                    }
                    let headers: Vec<Header> = block
                        .fields
                        .iter()
                        .map(|field| Header {
                            name: field.name.clone(),
                            value: field.value.clone(),
                            never_indexed: field.never_indexed,
                        })
                        .collect();
                    self.headers_block(
                        side,
                        stream_id,
                        chain.head,
                        Decoded {
                            headers,
                            block: bytes,
                            sources: block_sources,
                            compression,
                        },
                        context,
                    )
                }
            }
        })();
        context.release_scratch(scratch)?;
        result
    }
}
