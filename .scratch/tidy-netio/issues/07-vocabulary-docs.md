# 07: Vocabulary and docs

**What to build:** "materialized route" → "resolved route"; "adapter" → "backend" in docs; `lib.rs` names the shared modules; `deadline.rs` lists the documented exceptions (`transmit::Provider::send`, `Session::shutdown`, `tcp::Stream` timeouts); `resources.rs` says `supported` is always true.

**Blocked by:** 06

**Status:** resolved

- [x] No CONTEXT.md "avoid" term remains in netio docs or messages.
- [x] fmt, clippy, and the workspace tests pass.

## Comments

- "adapter" stays where it names IP Helper's own adapter snapshot and the NIC that reports an MTU; the messages and docs that meant a backend now say backend.
