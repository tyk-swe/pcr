# 07: Vocabulary and docs

**What to build:** "materialized route" → "resolved route"; "adapter" → "backend" in docs; `lib.rs` names the shared modules; `deadline.rs` lists the documented exceptions (`transmit::Provider::send`, `Session::shutdown`, `tcp::Stream` timeouts); `resources.rs` says `supported` is always true.

**Blocked by:** 06

**Status:** ready-for-agent

- [ ] No CONTEXT.md "avoid" term remains in netio docs or messages.
- [ ] fmt, clippy, and the workspace tests pass.
