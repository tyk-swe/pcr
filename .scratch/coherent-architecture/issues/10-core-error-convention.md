# 10: Core error convention

**What to build:** Apply the workspace error convention in core.
- `codec::Error` carries a real typed source (dropping `Eq`). The 97 `invalid(name, String)` call sites keep the original protocol error as the source instead of a string: DNS, HTTP, DHCP, IPv4, `fuzz/prepare.rs`.
- One `Error` per owning module, used module-qualified: rename the 15+ `XError` types, and merge DNS's `DecodeError` and `name::Error`.
- Every public error implements `Classified`: `codec::Error`, `registry::Error`, the field, packet, semantics and path errors, reassembly, scope, and DNS decode.
- Messages never repeat the source text.
- `&'static str`-reason variants become typed variants where the set is closed.

Phase 1. See the spec's "Workspace conventions → Errors".

**Blocked by:** 08

**Status:** resolved

- [x] No typed error is converted to a string inside core.
- [x] `std::error::Error::source()` chains reach the original protocol error. Add contract tests for DNS and DHCP decode failures.
- [x] Classification codes are unchanged. Human-readable messages may change, and `[Unreleased]` notes it.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Renames/merges: `packet::Error`, `field::Error` (absorbs `FieldError` and
  `PathError`), `layer::Refusal` (a reason, not an error),
  `capture_file::Error` (absorbs selection/map/merge), `analysis::Error`
  (absorbs `SessionError`), `filter::Error` (absorbs `ProjectionError`),
  `fuzz::Error` (absorbs `TargetParseError`), `dns::Error` (absorbs
  `name::Error`), reassembly `Resource`/`Malformed` category types.
- Kept: `error::BoundaryError` (the cross-crate boundary carrier, 380+ uses)
  and `budget::{DeadlineExceeded, Cancelled, Interrupted}` (shared by netio and
  packetcraftr; tickets 04/19 own them). `QuotedIcmpError` is not an error type
  (an ICMP error kind); ticket 13 decides the matcher helpers.
- `codec::Error` keeps `PartialEq` but drops `Eq`: the new
  `error::Source` compares by rendered chain, so `dns::Error`/`tls::Error`
  keep `PartialEq`. Literal codec messages stay `Invalid { message }`; typed
  protocol failures use the new `Rejected { source }`.
- Typed reasons: DHCP/HTTP `Limit`, `analysis::Constraint`, forwarding
  expectation syntax. Descriptive `&'static str` violation texts stay (transform
  `Invalid`/`Unsupported`/`Limit` — ticket 12 rewrites those sites; capture-file
  `InvalidData`/metadata from shared pcapng validators; IP reassembly header
  reasons; DHCP/HTTP `Invalid`; `WrongType.expected`). `semantics::Error::Field`
  reasons are left to ticket 09, which replaces the string-field reads.
- Text records (malformed-layer reasons, diagnostics, TLS verdict reasons)
  render the full chain with the new public `error::render`, so published
  reason text is byte-identical. The sticky capture-writer failure still keeps
  a rendered chain snapshot because an `io::Error` payload cannot be cloned.
- Upper crates: a few packetcraftr/CLI sites that copied a core error's text
  now carry its chain (`source_chain`/`render`) so no detail is lost; their own
  conventions are left to their tickets.
