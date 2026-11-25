// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Header-block assembly, bounded HPACK decoding, and compression provenance GC.

use super::super::{
    ActiveState, Chain, ChainHead, Context, ElectedDirection, Evidence, Fault, Pos, Reporter,
    StepAbort, StepResult,
};
use crate::analysis::http2::budget::{self, Charge};
use crate::analysis::http2::buffer::union_balanced;
use crate::analysis::http2::model::{Certainty, Header, Status};
use crate::analysis::http2::settings::DirectionSettings;
use crate::analysis::http2::side::Side;
use crate::analysis::http2::stream::Decoded;
use crate::analysis::http2::{Error, IssueCode};
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http2 as wire;
use crate::protocol::application::http2::hpack;
use bytes::Bytes;
use std::collections::HashSet;

fn hpack_scratch_bytes(
    limits: &crate::analysis::http2::Limits,
    block_len: usize,
) -> Result<usize, Error> {
    6usize
        .checked_mul(limits.max_header_bytes)
        .and_then(|v| {
            v.checked_add(
                2usize.saturating_mul(limits.max_headers.saturating_mul(size_of::<hpack::Field>())),
            )
        })
        .and_then(|v| v.checked_add(2usize.saturating_mul(limits.max_table_bytes)))
        .and_then(|v| v.checked_add(2usize.saturating_mul(block_len)))
        .ok_or(Error::Application(
            crate::analysis::application::Error::Limit {
                field: "hpack_scratch",
                limit: limits.max_header_bytes,
            },
        ))
}

struct HpackDecodeOutcome {
    decoded: Result<hpack::Block, wire::Error>,
    ambiguous_minimum: bool,
}

fn decode_hpack_block(
    dir: &mut ElectedDirection,
    peer_settings: &mut DirectionSettings,
    bytes: &Bytes,
    origin: u64,
    context: &Context<'_>,
) -> Result<HpackDecodeOutcome, Error> {
    let updates = hpack::table_size_updates(bytes, &mut || {
        context
            .check_deadline()
            .map_err(hpack::DecodeError::Interrupted)
    });
    let mut ambiguous_minimum = false;
    let decoded = match updates {
        Err(error) => Err(error),
        Ok(updates) => {
            let causal = updates.map_or_else(Default::default, |(_, maximum)| {
                peer_settings.causal_table_minimum(maximum)
            });
            let uncertain = [causal.uncertain, peer_settings.uncertain_table_minimum]
                .into_iter()
                .flatten()
                .min();
            let decoder = dir.decoder.as_mut().ok_or(Error::Invariant("decoder"))?;
            ambiguous_minimum = uncertain.is_some_and(|bound| {
                decoder.table_maximum() > bound
                    && updates.is_none_or(|(observed, _)| observed > bound)
            });
            if let Some(required) = causal.required {
                decoder.require_table_minimum(required);
            }
            let decoded = decoder.decode_checked(bytes, origin, &mut || {
                context
                    .check_deadline()
                    .map_err(hpack::DecodeError::Interrupted)
            });
            if decoded.is_ok() {
                peer_settings.uncertain_table_minimum = None;
                if let Some((minimum, _)) = updates {
                    peer_settings.observed_table_updates(minimum, causal.confirmed_prefix);
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
    Ok(HpackDecodeOutcome {
        decoded,
        ambiguous_minimum,
    })
}

fn collect_compression_sources_and_prune_origins(
    dir: &mut ElectedDirection,
    block: &hpack::Block,
    context: &mut Context<'_>,
) -> Result<Option<SourceSet>, Error> {
    let mut compression_sets = Vec::new();
    let mut seen = HashSet::new();
    for field in &block.fields {
        for &origin in &field.origins {
            context.check_deadline()?;
            if !seen.insert(origin) {
                continue;
            }
            let set = dir
                .block_sources
                .get(&origin)
                .ok_or(Error::Invariant("origin sources missing"))?;
            // Origins are keyed above; the balanced source union deduplicates
            // overlapping physical frames without comparing all previous sets.
            compression_sets.push(set.clone());
        }
    }
    let compression = union_balanced(compression_sets)?;
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
            context.untrack(&mut dir.origins_charge, &set)?;
            context.release(&mut dir.origins_charge, budget::ORIGIN_ENTRY_OVERHEAD)?;
        }
    }
    Ok(compression)
}

pub(super) struct BlockStart {
    pub at: Pos,
    pub head: ChainHead,
    pub fragment: Bytes,
    pub evidence: Evidence,
    pub end_headers: bool,
}

pub(super) struct BlockContinue {
    pub at: Pos,
    pub fragment: Bytes,
    pub end_headers: bool,
    pub evidence: Evidence,
}

struct CompletedBlock {
    at: Pos,
    head: ChainHead,
    origin: u64,
    bytes: Bytes,
    sources: Option<SourceSet>,
}

impl ActiveState {
    pub(super) fn block_start(
        &mut self,
        start: BlockStart,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let BlockStart {
            at: Pos { side, stream_id },
            head,
            fragment,
            evidence,
            end_headers,
        } = start;
        if fragment.len() > context.limits.max_header_block_bytes {
            return self.limited_block(side, stream_id, evidence, reporter, context);
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
        if let Some(sources) = evidence.sources {
            if let Err(error) = context.track(&mut chain.charge, &sources) {
                context.release_all(&mut chain.charge)?;
                return Err(error.into());
            }
            chain.sets.push(sources);
        }
        if end_headers {
            self.block_done(side, chain, reporter, context)
        } else {
            if let Some(dir) = self.directions.get_mut(side) {
                dir.chain = Some(chain);
            } else {
                context.release_all(&mut chain.charge)?;
            }
            Ok(())
        }
    }

    pub(super) fn block_continue(
        &mut self,
        cont: BlockContinue,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let BlockContinue {
            at: Pos { side, stream_id },
            fragment,
            end_headers,
            evidence,
        } = cont;
        let Some(mut chain) = self
            .directions
            .get_mut(side)
            .and_then(|dir| dir.chain.take())
        else {
            return Ok(());
        };
        debug_assert_eq!(chain.stream_id, stream_id);
        if chain.bytes.len() + fragment.len() > context.limits.max_header_block_bytes
            || chain.frames + 1 > context.limits.max_continuations + 1
        {
            context.release_all(&mut chain.charge)?;
            return self.limited_block(side, stream_id, evidence, reporter, context);
        }
        if let Err(error) = context.charge(&mut chain.charge, fragment.len()) {
            context.release_all(&mut chain.charge)?;
            return Err(error.into());
        }
        chain.bytes.extend_from_slice(&fragment);
        chain.frames += 1;
        if let Some(sources) = evidence.sources {
            if let Err(error) = context.track(&mut chain.charge, &sources) {
                context.release_all(&mut chain.charge)?;
                return Err(error.into());
            }
            chain.sets.push(sources);
        }
        if end_headers {
            self.block_done(side, chain, reporter, context)
        } else {
            if let Some(dir) = self.directions.get_mut(side) {
                dir.chain = Some(chain);
            } else {
                context.release_all(&mut chain.charge)?;
            }
            Ok(())
        }
    }

    fn limited_block(
        &self,
        side: Side,
        stream_id: u32,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        reporter.reject(
            context,
            Fault::connection(
                self.directions.flow(side),
                Status::Limit,
                IssueCode::BlockLimit,
                "a header block exceeded its configured bound",
            )
            .with_stream(Some(stream_id))
            .with_evidence(evidence.wire, evidence.sources),
        )
    }

    fn block_done(
        &mut self,
        side: Side,
        mut chain: Chain,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        context.release_all(&mut chain.charge)?;
        context.check_deadline()?;
        let bytes = chain.bytes.freeze();
        let stream_id = chain.stream_id;
        let head = chain.head;
        let origin = self.streams.next_origin();
        let block_sources = union_balanced(std::mem::take(&mut chain.sets))?;
        if let Some(sources) = block_sources.clone()
            && let Some(dir) = self.directions.get_mut(side)
        {
            context.track(&mut dir.origins_charge, &sources)?;
            dir.block_sources.insert(origin, sources);
            context.charge(&mut dir.origins_charge, budget::ORIGIN_ENTRY_OVERHEAD)?;
        }
        let scratch = hpack_scratch_bytes(context.limits, bytes.len())?;
        let completed = CompletedBlock {
            at: Pos { side, stream_id },
            head,
            origin,
            bytes,
            sources: block_sources,
        };
        context.with_scratch(scratch, |context| {
            self.decode_and_dispatch_block(completed, reporter, context)
        })
    }

    fn decode_and_dispatch_block(
        &mut self,
        completed: CompletedBlock,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let CompletedBlock {
            at: Pos { side, stream_id },
            head,
            origin,
            bytes,
            sources: block_sources,
        } = completed;
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("direction not found"))?;
        let outcome = decode_hpack_block(
            dir,
            &mut self.control.settings[side.peer()],
            &bytes,
            origin,
            context,
        )?;
        dir.sync_decoder(context)?;
        if outcome.decoded.is_ok() && outcome.ambiguous_minimum {
            reporter.issue(
                context,
                Fault::compression(
                    dir.flow.clone(),
                    stream_id,
                    Status::Incomplete,
                    IssueCode::HpackTableSizeOrdering,
                    "an earlier table shrink may precede or follow receipt of SETTINGS; its required minimum cannot be confirmed",
                )
                .with_certainty(Certainty::ObservedOrder)
                .with_evidence(bytes.clone(), block_sources.clone()),
            )?;
        }
        let block = match outcome.decoded {
            Ok(block) => block,
            Err(error) => {
                let (code, status) = match &error {
                    wire::Error::Limit(_) => (IssueCode::HeaderBlockLimit, Status::Limit),
                    _ => (IssueCode::HpackDecode, Status::Malformed),
                };
                reporter.issue(
                    context,
                    Fault::compression(
                        dir.flow.clone(),
                        stream_id,
                        status,
                        code,
                        error.to_string(),
                    )
                    .with_evidence(bytes, block_sources),
                )?;
                return Err(StepAbort::ConnectionFailed(status));
            }
        };
        context.check_deadline()?;
        let compression = collect_compression_sources_and_prune_origins(dir, &block, context)?;
        if let Some(limit) = self.control.settings[side.peer()]
            .advertised
            .max_header_list_size
            && block.decoded_bytes > limit as usize
        {
            reporter.issue(
                context,
                Fault::stream(
                    dir.flow.clone(),
                    stream_id,
                    Status::Incomplete,
                    IssueCode::HeaderListSizeAdvisory,
                    format!(
                        "decoded header list {} exceeds the peer's advertised maximum",
                        block.decoded_bytes
                    ),
                )
                .with_certainty(Certainty::ObservedOrder),
            )?;
        }
        let headers: Vec<Header> = block
            .fields
            .into_iter()
            .map(|field| Header {
                name: field.name,
                value: field.value,
                never_indexed: field.never_indexed,
            })
            .collect();
        self.headers_block(
            side,
            stream_id,
            head,
            Decoded {
                headers,
                block: bytes,
                sources: block_sources,
                compression,
            },
            reporter,
            context,
        )
    }
}
