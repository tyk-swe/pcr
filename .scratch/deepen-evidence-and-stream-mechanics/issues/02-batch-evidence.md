# Unify batch evidence and retention

Status: open
Blocked by: 01
Spec: ../spec.md §§ Implementation Decisions 2; Testing Decisions

Replace probe lifecycle with batch-evidence module around the live step. Migrate scan/traceroute sequential and scan pipeline, and DNS/fuzz retention through shared evidence state; preserve workflow diagnostic codes and bounded undecoded retention. Remove old retention assembly helpers and duplicated lifecycle tests once interface contracts cover sink failure, ordering, invalid evidence, retention limits. Coordinate with ticket 01's live-step interface. Record fuzz deltas in `[Unreleased]` at integration.
