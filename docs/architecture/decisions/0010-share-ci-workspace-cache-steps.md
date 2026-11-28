# Share workspace cache steps in CI

## Context

Eight CI jobs cache the same workspace Cargo paths and run the same cleanup before saving. The mutation matrix adds its gate name to the key. The release workflow and the separate fuzz workspace have their own keys and cache paths.

## Decision

Use YAML anchors for the common restore step, paths, and cleanup. Mutation jobs reuse the paths and specify their full gate-specific key. Preserve step order and the expanded definition for every job.

## Alternatives

A composite action would add another file and move the cleanup away from the jobs whose output it controls. YAML aliases express the existing workflow with fewer copies and preserve the job context of each expression.
