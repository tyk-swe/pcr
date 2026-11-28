# Give CLI input sources one owner

## Context

Capture and document inputs shared capped reads but defined platform file opening in two places. Stdin validation also compared the dash sentinel independently from source opening.

## Decision

The input source module owns platform file opening and the two existing stdin comparisons. Capture opening and multi-source validation use path equality, which accepts `-/.`. The bounded document reader and manifest selector require the exact dash argument. The caller owns its validation message. Bounded reads still enforce their own file type and size requirements.

## Alternatives

Treating every spelling that compares equal to `-` as stdin would change document and manifest behavior. Requiring the exact argument everywhere would remove a supported capture spelling. Keeping both comparisons in the input module preserves those contracts and gives preflight and opening code shared definitions.
