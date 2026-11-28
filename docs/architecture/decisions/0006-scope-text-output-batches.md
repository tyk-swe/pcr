# Scope text output batches to capture reads

## Context

Regular-file capture reads coalesce styled text and projected rows. Piped reads publish each row as soon as it is ready. Batching changed shared invocation state, and the projection budget stored an invocation clone just to decide where to write text.

## Decision

The terminal gives the regular-file read its own scoped invocation and flushes remaining bytes when the read returns. The read error takes precedence over a flush error. Field projection receives the invocation at publication time and retains only its own accounting and row state.

## Alternatives

Passing an explicit writer through every packet renderer would spread the choice between immediate and batched output to callers. Putting JSON, NDJSON, and file output into the text batch would mix distinct deadline, retry, and persistence guarantees. Scope the buffer to the two existing regular-file text paths.
