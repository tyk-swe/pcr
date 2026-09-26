# 14: Move route planning to packetcraftr::route

**What to build:** Per ADR 0001:
- netio's `route::plan`, together with `planner.rs`, `intent.rs` and the passive `Plan`/`Decision`/`Options` types, moves to a new `packetcraftr::route` module. The route cache moves there from `exchange/route_cache.rs`.
- netio keeps only the route contract: `route::Provider` and its query and route models, `route::SystemProvider`, and route materialization. Materialization stays for now because it performs neighbor resolution, and it moves with ticket 15 if that is what remains of it.
- The checks that currently run three times (preferred-source family, interface mismatch in the planner, `route_normalize`, and the netlink backend) run once in the planner, plus once in the backend where the kernel's answer must be verified.

Phase 2. See `CONTEXT.md` **Route plan**.

**Blocked by:** 13

**Status:** ready-for-agent

- [ ] netio contains no packet interpretation for routing.
- [ ] `Client::plan` returns `packetcraftr::route::Plan`.
- [ ] Planner unit tests move with the code. Route contract tests pass with only import changes.
- [ ] `AGENTS.md`'s netio description still holds, and `[Unreleased]` and the migration note list the moved paths.
- [ ] fmt, clippy and the workspace tests pass.
