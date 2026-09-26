# 10: Core error convention

**What to build:** Apply the workspace error convention in core.
- `codec::Error` carries a real typed source (dropping `Eq`). The 97 `invalid(name, String)` call sites keep the original protocol error as the source instead of a string: DNS, HTTP, DHCP, IPv4, `fuzz/prepare.rs`.
- One `Error` per owning module, used module-qualified: rename the 15+ `XError` types, and merge DNS's `DecodeError` and `name::Error`.
- Every public error implements `Classified`: `codec::Error`, `registry::Error`, the field, packet, semantics and path errors, reassembly, scope, and DNS decode.
- Messages never repeat the source text.
- `&'static str`-reason variants become typed variants where the set is closed.

Phase 1. See the spec's "Workspace conventions → Errors".

**Blocked by:** 08

**Status:** ready-for-agent

- [ ] No typed error is converted to a string inside core.
- [ ] `std::error::Error::source()` chains reach the original protocol error. Add contract tests for DNS and DHCP decode failures.
- [ ] Classification codes are unchanged. Human-readable messages may change, and `[Unreleased]` notes it.
- [ ] fmt, clippy and the workspace tests pass.
