# Use core analysis defaults

## Context

Offline analysis commands pass several Clap values directly into core option and limit fields. The CLI duplicated those default literals, so help, resource diagnostics, and core behavior could drift. Some values remain CLI-owned because they govern publication or command presentation rather than core analysis state.

## Decision

Core defaults drive the matching CLI settings for DNS and beacon thresholds, security findings, groups and observations, offline provenance bytes, and QUIC connections, buffering, pending packets, streams, and idle expiry. The CLI keeps its resource presets and publication limits, including `max_result_bytes`, `max_output_connections`, and application output bytes. Duration conversion follows the existing idle-expiry saturation behavior. Clap prints each numeric default beside its option. The CLI field projector owns the default and help for the encoded projection budget across read, dissect, and capture. Each command still owns its field conflicts and resource reporting.

## Alternatives

Duplicated literals keep help self-contained but can disagree with the values passed to core. Moving CLI publication limits into core would mix output policy into the runtime-neutral analysis contract.
