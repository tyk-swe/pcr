# Own stream selection in analysis session

Status: resolved
Blocked by: none
Spec: ../spec.md §§ Implementation Decisions 6; Testing Decisions

Have session accept optional stream reference, derive and compose filter with caller's frame filter, return typed absent outcome after drain. Encapsulate CLI analysis setup and unify absent-stream wording for http, offline dns, tls, follow in every format. Test TCP/UDP selection, filter composition, absent path and process contracts. Avoid touching stream-event generation (ticket 04). Record message delta in `[Unreleased]` at integration.
