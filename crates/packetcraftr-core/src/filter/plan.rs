// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Lowers postfix filters to jump-threaded predicates once at compile time.
//! Jumps encode boolean-stack state and short-circuit `&&`/`||`, so matching
//! allocates nothing and skips unnecessary field reads.

use super::ast::{Op, Predicate};
use super::eval::{self, Context};

const MATCH: u32 = u32::MAX;
const MISS: u32 = u32::MAX - 1;

/// One executable predicate and the next step each outcome selects.
#[derive(Clone, Debug)]
struct Step {
    predicate: Predicate,
    /// Next step index when the predicate holds, [`MATCH`], or [`MISS`].
    on_true: u32,
    /// Next step index when it does not, [`MATCH`], or [`MISS`].
    on_false: u32,
}

/// A filter as an executable sequence of short-circuiting predicate steps.
///
/// Steps sit in left-to-right source order and every jump moves strictly
/// forward or exits, so evaluation is bounded by the step count regardless of
/// how the source expression nested.
#[derive(Clone, Debug)]
pub(super) struct Plan {
    steps: Box<[Step]>,
}

impl Plan {
    /// Lowers a balanced postfix program into jump-threaded steps.
    ///
    /// Three linear passes: record each binary operator's left operand,
    /// propagate every subtree's true/false exits root-down, then keep only
    /// the leaves with their exits translated to step indexes. Predicate
    /// payloads move into the plan rather than being cloned into a second
    /// representation.
    ///
    /// A jump always targets the first leaf of a subtree — the program index
    /// just past the left operand's root — or a result sentinel. Anything
    /// else would be a compiler defect, so unresolvable targets degrade to
    /// [`MISS`] instead of accepting a packet by mistake.
    pub(super) fn compile(program: Vec<Op>) -> Self {
        let program_len = program.len() as u32;
        // First pass: the left operand's root for each binary operator. In
        // postfix order the right operand always ends at `index - 1`, so only
        // the left root needs recording; `roots` tracks completed subtree
        // roots the way the interpreter's stack tracked their values.
        let mut left_root = vec![0u32; program.len()];
        let mut roots: Vec<u32> = Vec::with_capacity(program.len());
        for (index, op) in program.iter().enumerate() {
            match op {
                Op::Leaf(_) => roots.push(index as u32),
                Op::Not => {
                    roots.pop();
                    roots.push(index as u32);
                }
                Op::And | Op::Or => {
                    roots.pop();
                    left_root[index] = roots.pop().unwrap_or(0);
                    roots.push(index as u32);
                }
            }
        }
        // Second pass: every subtree's exits, forwarded inward. A parent sits
        // behind its operands in postfix order, so walking backwards assigns a
        // node's exits before the node itself hands them to its children.
        let mut on_true = vec![0u32; program.len()];
        let mut on_false = vec![0u32; program.len()];
        if let Some(root) = program_len.checked_sub(1) {
            on_true[root as usize] = program_len;
            on_false[root as usize] = program_len + 1;
        }
        for (index, op) in program.iter().enumerate().rev() {
            match op {
                Op::Leaf(_) => {}
                Op::Not => {
                    let child = index - 1;
                    on_true[child] = on_false[index];
                    on_false[child] = on_true[index];
                }
                Op::And | Op::Or => {
                    // In postfix order the right operand ends at `index - 1`.
                    let (left, right) = (left_root[index] as usize, index - 1);
                    on_true[right] = on_true[index];
                    on_false[right] = on_false[index];
                    // The right subtree starts just past the left operand's
                    // root: `&&` reaches it only when the left side held, `||`
                    // only when it did not.
                    if matches!(op, Op::And) {
                        on_true[left] = left as u32 + 1;
                        on_false[left] = on_false[index];
                    } else {
                        on_true[left] = on_true[index];
                        on_false[left] = left as u32 + 1;
                    }
                }
            }
        }
        // Third pass: emit one step per leaf, translating program indexes to
        // step indexes and the root's exits to result sentinels.
        let mut step_of = vec![MISS; program.len()];
        let mut steps = Vec::with_capacity(roots.len());
        for (index, op) in program.into_iter().enumerate() {
            if let Op::Leaf(predicate) = op {
                step_of[index] = steps.len() as u32;
                steps.push(Step {
                    predicate,
                    on_true: on_true[index],
                    on_false: on_false[index],
                });
            }
        }
        for step in &mut steps {
            for target in [&mut step.on_true, &mut step.on_false] {
                *target = match *target {
                    sent if sent == program_len => MATCH,
                    sent if sent == program_len + 1 => MISS,
                    leaf => step_of[leaf as usize],
                };
            }
        }
        Self {
            steps: steps.into(),
        }
    }

    /// Intersects two already-compiled plans without recompiling caller input.
    /// A match in the left plan proceeds to the first step of the right plan;
    /// a miss still stops immediately.
    pub(super) fn intersect(&self, other: &Self) -> Self {
        let offset = self.steps.len() as u32;
        let mut steps = self.steps.to_vec();
        for step in &mut steps {
            if step.on_true == MATCH {
                step.on_true = offset;
            }
            if step.on_false == MATCH {
                step.on_false = offset;
            }
        }
        steps.extend(other.steps.iter().cloned().map(|mut step| {
            for target in [&mut step.on_true, &mut step.on_false] {
                if *target != MATCH && *target != MISS {
                    *target += offset;
                }
            }
            step
        }));
        Self {
            steps: steps.into(),
        }
    }

    /// Whether the packet satisfies the filter.
    ///
    /// Follows the precomputed jumps, so only predicates the outcome depends
    /// on actually run. An out-of-plan index — impossible for a compiled plan
    /// — rejects rather than accepting by accident.
    pub(super) fn evaluate(&self, context: &Context<'_>) -> bool {
        let mut index = 0u32;
        while let Some(step) = self.steps.get(index as usize) {
            index = if eval::test(&step.predicate, context) {
                step.on_true
            } else {
                step.on_false
            };
        }
        index == MATCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A placeholder leaf: the jump structure is what these tests check.
    fn leaf() -> Op {
        Op::Leaf(Predicate::LayerPresent {
            protocol: crate::layer::Id::new("fixture"),
            occurrence: None,
        })
    }

    /// Step indexes each leaf jumps to, as `(on_true, on_false)` pairs.
    fn jumps(program: Vec<Op>) -> Vec<(u32, u32)> {
        Plan::compile(program)
            .steps
            .iter()
            .map(|step| (step.on_true, step.on_false))
            .collect()
    }

    #[test]
    fn plan_compiles_leaves_and_operators_to_forward_jumps() {
        // `a` alone accepts on true and rejects on false.
        assert_eq!(jumps(vec![leaf()]), [(MATCH, MISS)]);

        // `a && b`: a false left skips the right operand entirely; `a || b`
        // does the same on a true left.
        assert_eq!(
            jumps(vec![leaf(), leaf(), Op::And]),
            [(1, MISS), (MATCH, MISS)]
        );
        assert_eq!(
            jumps(vec![leaf(), leaf(), Op::Or]),
            [(MATCH, 1), (MATCH, MISS)]
        );

        // `a && !b`: `!` swaps its operand's exits.
        assert_eq!(
            jumps(vec![leaf(), leaf(), Op::Not, Op::And]),
            [(1, MISS), (MISS, MATCH)]
        );
    }

    #[test]
    fn plan_short_circuits_chains_in_evaluation_order() {
        // `a || b && c` parses as `a || (b && c)`: a true `a` accepts without
        // touching b or c; a false `a` falls through to the `b && c` pair.
        assert_eq!(
            jumps(vec![leaf(), leaf(), leaf(), Op::And, Op::Or]),
            [(MATCH, 1), (2, MISS), (MATCH, MISS)]
        );

        // `(a || b) && c`: whichever of a/b holds still has to satisfy c.
        assert_eq!(
            jumps(vec![leaf(), leaf(), Op::Or, leaf(), Op::And]),
            [(2, 1), (2, MISS), (MATCH, MISS)]
        );

        // `a && b || c` parses as `(a && b) || c`.
        assert_eq!(
            jumps(vec![leaf(), leaf(), Op::And, leaf(), Op::Or]),
            [(1, 2), (MATCH, 2), (MATCH, MISS)]
        );
    }

    #[test]
    fn plan_keeps_every_jump_forward_or_terminal() {
        // A long mixed chain stays linear: every step's exits either advance
        // or terminate, so evaluation is bounded by the number of leaves.
        let mut program = Vec::new();
        for _ in 0..64 {
            program.push(leaf());
            program.push(Op::And);
        }
        program.push(leaf());
        program.push(Op::Not);
        for _ in 0..64 {
            program.push(Op::Or);
        }
        let steps = Plan::compile(program).steps;
        for (index, step) in steps.iter().enumerate() {
            for target in [step.on_true, step.on_false] {
                assert!(
                    target == MATCH || target == MISS || target as usize > index,
                    "step {index} jumps backward to {target}"
                );
            }
        }
    }

    #[test]
    fn empty_program_evaluates_to_no_match() {
        assert!(
            !Plan::compile(Vec::new()).evaluate(&Context {
                decoded: &crate::decode::DecodedPacket {
                    packet: crate::packet::Packet::new(),
                    original: bytes::Bytes::new(),
                    frame: crate::frame::Frame::new(
                        std::time::UNIX_EPOCH,
                        crate::frame::LinkType::RAW,
                        Vec::new(),
                    )
                    .expect("empty fixture frame"),
                    layout: crate::layout::PacketLayout::new(Vec::new()),
                    diagnostics: Vec::new(),
                },
                derived: &[],
                number: 1,
                tcp_stream: None,
                udp_stream: None,
            })
        );
    }
}
