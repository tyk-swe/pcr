# 14: Move route planning to packetcraftr::route

**What to build:** Per ADR 0001:
- netio's `route::plan`, together with `planner.rs`, `intent.rs` and the passive `Plan`/`Decision`/`Options` types, moves to a new `packetcraftr::route` module. The route cache moves there from `exchange/route_cache.rs`.
- netio keeps only the route contract: `route::Provider` and its query and route models, `route::SystemProvider`, and route materialization. Materialization stays for now because it performs neighbor resolution, and it moves with ticket 15 if that is what remains of it.
- The checks that currently run three times (preferred-source family, interface mismatch in the planner, `route_normalize`, and the netlink backend) run once in the planner, plus once in the backend where the kernel's answer must be verified.

Phase 2. See `CONTEXT.md` **Route plan**.

**Blocked by:** 13

**Status:** resolved

- [x] netio contains no packet interpretation for routing.
- [x] `Client::plan` returns `packetcraftr::route::Plan`.
- [x] Planner unit tests move with the code. Route contract tests pass with only import changes.
- [x] `AGENTS.md`'s netio description still holds, and `[Unreleased]` and the migration note list the moved paths.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Materialization moved with `Plan` (decision C1): `materialize` needs `Plan`
  and netio cannot depend on packetcraftr. Transmit frames now take a borrowed
  netio `transmit::Route` view (decision, mode, lookup destination), built
  with `Materialized::transmit_route()`. `for_prepared_layer2_frame` is gone;
  neighbor discovery builds its interface-only `Decision` itself.
- The preferred-source family check runs in the planner and once at
  `platform::dispatch::system_route` (pre-FFI, because `SystemProvider` is a
  public boundary also called directly by replay). It no longer runs at each
  backend entry or in `finish_route`. Interface-hint checks stay only where
  they verify the kernel's answer (`finish_route`, `find_interface`, netlink
  hint mapping) plus the planner's contract check.
- Moved netio route tests live in `packetcraftr/tests/route_contracts.rs`.
- Consumer examples changed only the `route::Options` path (decision C9).
