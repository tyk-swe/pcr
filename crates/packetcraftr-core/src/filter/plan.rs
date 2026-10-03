// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Lowers postfix filters to jump-threaded predicates once at compile time.

use super::ast::{Op, Predicate};
use super::eval::{self, Context};

const MATCH: u32 = u32::MAX;
const MISS: u32 = u32::MAX - 1;

#[derive(Clone, Debug)]
struct Step {
    predicate: Predicate,
    on_true: u32,
    on_false: u32,
}

/// Every jump moves strictly forward or exits, so evaluation is bounded by the step count.
#[derive(Clone, Debug)]
pub(super) struct Plan {
    steps: Box<[Step]>,
}

impl Plan {
    /// Unresolvable jump targets degrade to [`MISS`] instead of accepting a packet by mistake.
    pub(super) fn compile(program: Vec<Op>) -> Self {
        let program_len = program.len() as u32;
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
