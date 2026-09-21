# Domain docs

## Layout

This repo uses a single context shared by all four Rust crates:

- `CONTEXT.md` at the repo root: the domain glossary.
- `docs/adr/<NNNN>-<slug>.md`: architecture decision records,
  numbered from `0001`.

## Before exploring

Read the root `CONTEXT.md` and any ADRs relevant to the area being explored.

If these files do not exist, proceed silently. The `domain-modeling`
skill creates them lazily as terms or decisions are resolved.

## Use the glossary's vocabulary

Use glossary terms when naming domain concepts in issue titles,
proposals, hypotheses, and tests. Follow any explicit guidance on
synonyms to avoid.

If a needed concept is missing, reconsider whether it belongs to the
domain or note the gap for `domain-modeling`.

## Flag ADR conflicts

If a proposal contradicts an existing ADR, identify the ADR and explain
why its decision should be reconsidered.
