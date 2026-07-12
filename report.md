# PacketcraftR 0.2.0 bug report

This public report covers commit `6d967c729e1eb317271467fba3abeafa27445034`, audited on 2026-07-12. It records 28 confirmed defects and engineering gaps and now tracks remediation in the working tree based on commit `896e53cd40f7782474d1c3a10351bb4225d7206e`. Stable issue identifiers were not renumbered after unsupported item BR-012 was removed.

The canonical maintainer and auditor record is [`report.xml`](report.xml). That XML contains exact source-review provenance, commit-anchored locations, verification qualifications, and regression-test specifications. If this document and the XML differ, the XML controls.

## Summary

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 3 |
| Medium | 13 |
| Low | 11 |
| Informational | 1 |

Remediation status as of 2026-07-12: **28 fixed, 0 open**. Final verification passes all 363 tests under `cargo test --locked --all-features` (including 279 library tests and dedicated correlation, ingress-timing, deadline, DNS, and neighbor-race regressions), Linux Clippy with warnings denied under no-default, default, and all-feature profiles, `cargo deny check`, Windows default/all-feature cross-checks, and x86_64/arm64 macOS all-feature cross-checks.

Severity is based on supported defaults and the project's documented safety contracts. High denotes a supported-path safety-boundary bypass or memory-safety defect. Medium denotes material correctness, integrity, or availability impact, including safety defects with substantial preconditions. Low denotes narrow edge cases, non-default invariant failures, or limited API/interoperability defects. Informational denotes a verified control gap rather than a demonstrated vulnerability.

All 28 retained mechanisms were independently traced in source. `cargo test --locked --all-features` passed all 337 tests under Rust 1.96.0, and the exact commit passed the four configured [GitHub Actions jobs](https://github.com/tyk-swe/pcr/actions/runs/29157517928). Targeted runtime checks reproduced BR-008, BR-010, BR-013, BR-016, BR-019 through BR-022, and BR-025 through BR-027. Platform-native and network-dependent impacts were not locally exercised unless stated below; passing tests do not cover the reported failure paths.

## High severity

### BR-001 — IPv4 LSRR/SSRR route addresses bypass destination authorization

- **Status:** Fixed in the remediation worktree. Typed send and replay now share one fail-closed IPv4 option parser, authorize every LSRR/SSRR address, and reject malformed length, pointer, and truncation encodings before route lookup.

- **Evidence:** `src/client/internal/policy_impl.rs:31-54` authorizes the IPv4 destination but not opaque option bytes. `src/workflow/replay/wire.rs:86-123` independently recognizes LSRR/SSRR option types 131 and 137 as embedded destinations.
- **Condition and impact:** On a network that honors IPv4 source routing, an authorized outer destination can carry an unauthorized global route hop, bypassing the default live-target policy before route lookup and I/O.
- **Remediation:** Use one fail-closed destination extractor for live send and replay; authorize every embedded source-route address and reject malformed or unsupported route-affecting options.
- **Test:** Submit private-outer/public-hop LSRR and SSRR packets and assert rejection occurs before route or transmission provider use, including malformed encodings.
- **Reference:** [RFC 791](https://www.rfc-editor.org/rfc/rfc791).

### BR-002 — Globally scoped multicast bypasses the public-destination restriction

- **Status:** Fixed in the remediation worktree. Multicast destinations are denied by the default traffic policy for both families and require the explicit public-destination opt-in; global-scope regressions run before route use.

- **Evidence:** `src/client/internal/helpers.rs:362-380` classifies every multicast address as non-public, while `src/net/route/planner.rs:287-303,691-709` accepts multicast and derives its Ethernet destination.
- **Condition and impact:** Global IPv4 or IPv6 multicast, such as `232.1.2.3` or `ff0e::1234`, reaches transmission without the globally-routable-destination opt-in. Delivery beyond the local link depends on multicast routing.
- **Remediation:** Replace the boolean classifier with scope-aware policy. Reject multicast by default or explicitly permit only documented local scopes.
- **Test:** Reject global IPv4 and IPv6 multicast before route planning while retaining any deliberately allowed local scopes.
- **References:** [RFC 5771](https://www.rfc-editor.org/rfc/rfc5771) and [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291).

### BR-003 — macOS casts ifa_data to libc::if_data before validating the address family

- **Status:** Fixed in the remediation worktree. `ifa_data` crosses the `if_data` conversion boundary only after an `AF_LINK` check. Synthetic wrong-family data and native source both cross-compile for x86_64 and arm64 macOS.

- **Evidence:** `src/net/platform/macos.rs:65-100` dereferences every non-null `ifa_data` as `libc::if_data` before establishing that the entry is `AF_LINK`.
- **Condition and impact:** A non-`AF_LINK` entry with non-null, differently typed data can overwrite a correct MTU or create a wrong-type Rust reference at an unsafe FFI boundary. The platform-native failure was not locally reproduced.
- **Remediation:** Check `ifa_addr` and its family first, and interpret `ifa_data` as `if_data` only for `AF_LINK` at a single audited conversion boundary.
- **Test:** Add synthetic family/data-layout cases and a macOS enumeration test that checks stable, plausible MTUs.
- **Reference:** [Apple `getifaddrs(3)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html).

## Medium severity

### BR-004 — TCP traceroute replies can be destructively assigned to the wrong probe

- **Status:** Fixed in the remediation worktree. TCP reverse-tuple matching now validates request sequence consumption, response acknowledgment, flags, and bare-RST sequence state before assignment. Tests cover three reordered same-tuple probes plus valid and invalid SYN/ACK, ACK-bearing RST, and bare RST responses.

- **Evidence:** `src/protocol/matcher.rs:19-60` matches only reversed addresses and ports. `src/client/internal/exchange.rs:175-230` commits tied frames before `src/workflow/probe.rs:67-97` performs sequence-aware validation.
- **Condition and impact:** Reordered direct replies to multiple same-tuple TCP probes can each be assigned to the wrong request and then discarded, producing deterministic false timeouts. Tuple-only RST acceptance is also broader than TCP state permits.
- **Remediation:** Correlate SYN/ACK and RST traffic using request sequence, response acknowledgment, flags, and state before destructive assignment; unique source ports are an additional discriminator.
- **Test:** Deliver at least three same-tuple probe replies in reverse and arbitrary order and cover valid and invalid ACK-bearing and non-ACK RSTs.

### BR-005 — Valid immediate captures can be rejected as pre-send because timestamp precision and clocks differ

- **Status:** Fixed in the remediation worktree. Captured frames carry a monotonic ingress marker, native capture records it before validation and queueing, and exchange freshness no longer compares wall clocks. A response with `UNIX_EPOCH` evidence time is accepted when its monotonic ingress follows the send.

- **Evidence:** `src/client/internal/client.rs:306-342` records a nanosecond `SystemTime` marker, native captures may be reconstructed at microsecond precision, and `src/client/internal/exchange.rs:175-179` compares them exactly.
- **Condition and impact:** A response arriving later within the same truncated microsecond, or across disagreeing clocks, can appear earlier than the send and be discarded. Local DNS, loopback, and immediate resets are plausible cases.
- **Remediation:** Record a monotonic receive `Instant` at ingress and use it for freshness; retain wall-clock capture time only as evidence metadata.
- **Test:** Accept a later response that truncates into the send marker's microsecond and independently cover wall-clock movement.

### BR-006 — Response latency and timeout eligibility are measured at processing time instead of receive time

- **Status:** Fixed in the remediation worktree. Eligibility and RTT now use the monotonic capture-ingress marker, while wall time remains evidence metadata. A regression processes an on-time frame after its deadline and preserves its original one-millisecond RTT.

- **Evidence:** `src/client/internal/exchange.rs:203-230` computes `sent_at.elapsed()` while processing a queued frame, and DNS later compares that inflated duration with its timeout.
- **Condition and impact:** Send-provider time, queueing, scheduling, decoding, and matching delay inflate RTT and can invalidate a response captured before its deadline.
- **Remediation:** Carry a monotonic `received_at` from capture ingress, compute RTT from it, and expose processing delay separately if needed.
- **Test:** Capture inside the deadline, delay consumption beyond it, and verify the original RTT and eligibility remain intact.

### BR-007 — Sparse fragment and TCP ranges trigger dense scratch allocation before quota rejection

- **Status:** Fixed in the remediation worktree. Both reassemblers now plan interval unions and quota charges before direct interval splicing; zero-length fragments are rejected. Sparse high-offset regression tests verify aggregate rejection without span-sized scratch allocation.

- **Evidence:** `src/session/fragment.rs:332-387` and `src/session/tcp.rs:536-600` materialize and scan dense spans before aggregate quota rejection.
- **Condition and impact:** Defaults bound the per-flow span to 1 MiB, but sparse inserts still amplify work; caller-provided larger limits can provoke near-span-sized temporary allocation for only a few retained bytes.
- **Remediation:** Splice intervals directly, reject zero-length fragments, and validate retained-byte, span, gap, and work charges before allocation.
- **Test:** Assert sparse quota rejection precedes allocation in both reassemblers and benchmark high-offset zero- and one-byte inserts.

### BR-008 — A stale FIN entirely before the capture base can close an active TCP flow

- **Status:** Fixed in the remediation worktree. FIN position is derived in the original unwrapped sequence space; tests cover a fully stale FIN, the exact base, and a partially trimmed payload.

- **Evidence:** `src/session/tcp.rs:174-200,341-388` trims old payload, clamps its offset to zero, and then derives FIN position from the clamped range.
- **Condition and impact:** A fully pre-base payload plus FIN becomes `fin_offset=0`, immediately closing an active flow and potentially splitting or truncating reassembly.
- **Remediation:** Calculate FIN in the original unwrapped sequence space and ignore control information strictly before the retained receive interval.
- **Test:** Cover a fully pre-base FIN, a FIN exactly at the base, and a FIN after partially trimmed payload.

### BR-009 — macOS route sockaddr parsing reads sa_family before validating record length

- **Status:** Fixed in the remediation worktree. The parser accepts a bounded byte slice, requires two bytes before family access, performs family-size checks, and rejects zero/one-byte route records safely.

- **Evidence:** `src/net/platform/macos.rs:247-268,471-525` can pass a declared one-byte route record to `sockaddr_ip`, which reads its second byte as `sa_family` before a size check.
- **Condition and impact:** A malformed kernel route response can trigger an out-of-bounds unsafe read. No untrusted route-response control was established, and the failure was not locally reproduced. There is no separate unaligned-generic-`sockaddr` defect.
- **Remediation:** Accept a byte slice, require two bytes before reading family, and perform exact family-size checks before the existing unaligned family-specific reads.
- **Test:** Safely reject lengths zero and one, accept minimally sized unknown families without overread, and parse complete IPv4 and IPv6 records.

### BR-010 — A rejected PCAPNG frame can still mutate the output stream and interface table

- **Status:** Fixed in the remediation worktree. Interface selection is planned without mutation and the optional IDB is committed only after timestamp, snap-length, and EPB-size validation. Regression tests assert unchanged bytes and interface numbering.

- **Evidence:** `src/capture/pcap/writer.rs:505-540,568-607` auto-creates and writes an IDB before timestamp and EPB-size validation. Frame-count and stream-byte limits are checked earlier; snap-length cannot fail for an auto-created interface because its snap length is derived from the already-checked writer size limit.
- **Condition and impact:** An invalid frame with a previously unseen link type can return an error after changing output bytes and interface numbering, so retries observe different state.
- **Remediation:** Plan interface selection without mutation, validate the prospective frame completely, then commit the optional IDB and EPB.
- **Test:** Verify output bytes and interface count remain unchanged after timestamp and EPB-size failures for previously unseen link types.

### BR-013 — TCP reassembly conflates distinct connection incarnations that reuse a four-tuple

- **Status:** Fixed in the remediation worktree. An incompatible SYN/explicit reopen replaces retained tuple state, while an original-SYN retransmission remains idempotent.

- **Evidence:** `src/session/tcp.rs:19-25,131-139` keys state only by addresses and ports and treats reopening an existing key as success without checking the new initial sequence.
- **Condition and impact:** Tuple reuse before stale state expires can classify a new connection as retransmission, a huge gap, post-FIN data, or part of the previous stream.
- **Remediation:** Track connection generation and SYN/FIN/RST lifecycle, replacing incompatible stale state while keeping retransmitted original SYNs idempotent.
- **Test:** Reuse a tuple while incomplete state remains, including after an out-of-order FIN or a missed close; verify completed FIN/RST removal still permits reuse and original-SYN retransmission remains idempotent.

### BR-015 — The overall response timeout does not bound sending or unbounded zero-time capture drains

- **Status:** Fixed in the remediation worktree. Exchange establishes one absolute deadline before planning, readiness, draining, and sending; every zero-time drain has a frame cap, and blocking send time consumes the deadline so later requests are not sent. Neighbor readiness and pre-request drains are likewise bounded. Regressions cover a backend that never reports an empty zero-time capture and a delayed first send in a two-request exchange.

- **Evidence:** `src/client/internal/client.rs:281-390` drains until `None`, performs every send, and only then creates the exchange deadline; neighbor discovery has a comparable pre-request drain.
- **Condition and impact:** Slow sends inflate the advertised window, while sustained ingress can prevent a drain from becoming empty and defer progress indefinitely.
- **Remediation:** Establish an absolute deadline before readiness, draining, and sending; bound every drain by frame count and elapsed time.
- **Test:** Use a backend that always returns another zero-time frame and delayed sends, then assert bounded progress and deterministic per-request windows.

### BR-016 — Linux synchronous route lookup can panic when invoked inside a Tokio runtime

- **Status:** Fixed in the remediation worktree. Synchronous calls run private async netlink work on a dedicated worker thread; regressions cover invocation inside Tokio and concurrent callers.

- **Evidence:** `src/net/platform/linux.rs:143-160` creates a current-thread Tokio runtime and calls `Runtime::block_on` for a synchronous route operation.
- **Condition and impact:** Calling the public synchronous route path from a thread already executing Tokio panics instead of returning a route error; this was reproduced on Linux with the all-features build.
- **Remediation:** Expose an async route path or delegate synchronous work to a dedicated worker thread/runtime rather than nesting `block_on`.
- **Test:** Invoke synchronous route lookup inside a Tokio task and exercise repeated concurrent calls without panic.
- **Reference:** [Tokio `Runtime` documentation](https://docs.rs/tokio/latest/tokio/runtime/struct.Runtime.html).

### BR-017 — Windows collapses distinct IPv4 and IPv6 adapter indices into one InterfaceId index

- **Status:** Fixed in the remediation worktree. The Windows adapter snapshot retains LUID plus both family indices, selects the destination-family index for `GetBestRoute2`, accepts either family alias for constraints, and normalizes returned route identity. The default and all-feature Windows targets cross-check successfully.

- **Evidence:** `src/net/platform/windows.rs:147-165,188-217,248-269` prefers the IPv4 `IfIndex`, discards `Ipv6IfIndex`, and reuses the stored value for either route family.
- **Condition and impact:** An adapter whose family-specific indices differ can fail or misdirect constrained IPv6 route lookup. This was not reproduced on Windows.
- **Remediation:** Preserve adapter LUID and both family indices, selecting the correct index from the route address family.
- **Test:** Use a synthetic adapter with different indices and verify constrained routing and returned-route normalization for both families.
- **References:** [IP_ADAPTER_ADDRESSES](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh) and [GetBestRoute2](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/getbestroute2).

### BR-018 — The default Windows feature profile lacks documented interface enumeration and is not tested

- **Status:** Fixed in the remediation worktree. The default `live` feature enables the Windows IP Helper dependency, default-profile enumeration uses `GetAdaptersAddresses`, and CI now checks/tests the exact default Windows configuration in addition to all features.

- **Evidence:** `Cargo.toml:13-36` enables `live` by default but excludes `pnet` on Windows; `src/net/platform/mod.rs:145-155` returns unsupported without `native-route`, while CI tests only no-default and all-feature branches.
- **Condition and impact:** A default Windows build advertises interface enumeration but cannot perform it, and the exact configuration remains outside CI.
- **Remediation:** Implement default-profile Windows enumeration or document platform-specific defaults, and test default plus supported minimal feature combinations.
- **Test:** Add a Windows default-feature smoke test for `system_interfaces` without treating all-features coverage as a substitute.

### BR-021 — Removing the exact padding boundary silently changes protocol coverage semantics

- **Status:** Fixed in the remediation worktree. Removal preserves the shifted successor boundary and rejects removal when no enclosing successor can preserve it; structural regression tests cover both cases.

- **Evidence:** `src/packet/packet.rs:236-245` changes an exact `outside_layer` match to `None`; downstream code interprets `None` as padding excluded from every dependent payload.
- **Condition and impact:** When a shifted successor should remain the first excluding layer, removal can silently alter enclosing lengths, checksums, MTU calculations, and rebuilt bytes.
- **Remediation:** Preserve the boundary when an appropriate successor remains, otherwise require explicit reassignment instead of changing coverage semantics silently.
- **Test:** Remove an inner boundary in a nested Ethernet/IPv4/IPv4/UDP packet and verify enclosing coverage remains unchanged.

## Low severity

### BR-011 — The documented per-section PCAPNG interface limit is enforced cumulatively

- **Status:** Fixed in the remediation worktree. The per-section check now uses the current section count, with a separately configurable aggregate retained-interface ceiling. Multi-section and aggregate-limit regressions pass.

- **Evidence:** `src/capture/pcap/reader.rs:210-239,277-296` clears the section interface vector but validates `interface_base + interfaces.len()` against a limit documented as per-section.
- **Condition and impact:** Multiple individually valid sections can be rejected only because their cumulative interface count exceeds the nominal per-section limit.
- **Remediation:** Enforce the current-section limit with `interfaces.len()` and add a separately named total retained-interface limit, or explicitly redefine the existing contract.
- **Test:** Parse multiple sections with a packet in each section so every per-read metadata count stays within its limit while the cumulative interface count exceeds it.

### BR-014 — Public SessionLimits can violate TCP serial-number half-space

- **Status:** Fixed in the remediation worktree. TCP entry points reject windows at or above `2^31` and accept the largest lower value.

- **Evidence:** `src/session/tcp.rs:174-184` interprets wrapping deltas as signed 32-bit values, while public limits permit a per-flow window at or above `2^31`.
- **Condition and impact:** A caller must replace the safe 1 MiB default with an extreme window; sequence ordering then becomes intrinsically ambiguous. Zero limits and per-flow limits above aggregate limits are not inherently defective.
- **Remediation:** Validate TCP `max_bytes_per_flow < 2^31` at construction or every public entry point, independently documenting other quota semantics.
- **Test:** Reject `2^31` and larger, accept the largest lower value, and retain documented zero and aggregate-budget behavior.

### BR-019 — The public DNS decoder discards EDNS extended response codes

- **Status:** Fixed in the remediation worktree. OPT is parsed as a dedicated pseudo-record with root-owner, placement, uniqueness, version, and option-length validation. The decoder combines the 12-bit response code into `u16`, exposes EDNS metadata, and the output schema accepts values through 4095. Tests cover BADVERS, mixed bits, absent/duplicate/malformed OPT, unsupported versions, and option metadata.

- **Evidence:** `src/workflow/dns/wire.rs:44-68,95-104,143-145,175,228,363-400,680-717` exposes a general response decoder, emits no OPT in built-in queries, treats response OPT records generically, and retains only the header's four RCODE bits. `src/workflow/dns/model.rs:331-350,386` and `schemas/packetcraftr.output.v1.schema.json:1014-1018,1637-1641,2632-2636` cannot represent values above 15.
- **Condition and impact:** The public response decoder can emit an externally supplied EDNS error such as BADVERS as `response_code=0` and `no_error`. The built-in query encoder does not emit OPT, and RFC 6891 prohibits a compliant responder from including OPT when the request lacks it, so ordinary built-in queries cannot trigger this defect.
- **Remediation:** Parse OPT explicitly, combine the extended and header RCODE fields into a `u16`, expose EDNS metadata, and update schema bounds to 4095.
- **Test:** Cover BADVERS and mixed high/low RCODE bits through direct decoder use, plus no OPT, duplicate OPT, malformed OPT, and unsupported versions.
- **Reference:** [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891).

### BR-020 — DNS wire labels are incorrectly restricted to printable ASCII without dot bytes

- **Status:** Fixed in the remediation worktree. DNS names now retain length-delimited byte labels losslessly, fold only ASCII letters for semantic equality, and escape dot, backslash, control, and high bytes only for presentation. Tests cover dot, NUL, `0xff`, backslash, ASCII case folding, and preservation of non-ASCII distinctions.

- **Evidence:** `src/workflow/dns/wire.rs:270-360` applies presentation constraints to length-delimited wire labels; its `String` model cannot represent arbitrary octet labels losslessly.
- **Condition and impact:** Legal labels containing dot, NUL, high-bit octets, or other escaped bytes are rejected.
- **Remediation:** Represent names as lossless byte labels, fold only ASCII letters for comparison, and escape bytes only during presentation.
- **Test:** Decode dot, NUL, high-bit, and backslash bytes without conflation, render them with escaping, and preserve ASCII-only case-insensitive comparison.
- **Reference:** [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035).

### BR-022 — Packet::structurally_eq is not symmetric for public Layer implementations

- **Status:** Fixed in the remediation worktree. Structural comparison now requires identical canonical schemas before comparing reflected fields; asymmetric custom-layer regressions pass in both directions.

- **Evidence:** `src/packet/packet.rs:207-220` verifies matching protocol IDs but compares only fields exposed by the left-hand schema.
- **Condition and impact:** External layers sharing a protocol ID but exposing different schemas can make `a.structurally_eq(b)` differ from `b.structurally_eq(a)`.
- **Remediation:** Require equivalent canonical schemas before comparing values, or compare the union of both field sets.
- **Test:** Use public custom layers with one extra field and assert symmetry, reflexivity, and applicable transitivity.

### BR-023 — Rebinding a registry child with a different priority silently ignores the new priority

- **Status:** Fixed in the remediation worktree. Only an exact child-and-priority duplicate is idempotent; a changed priority returns `BindingConflict`.

- **Evidence:** `src/packet/registry.rs:382-408` treats an existing child as an idempotent success without comparing or updating priority.
- **Condition and impact:** A module receives `Ok` while its requested binding order is discarded.
- **Remediation:** Make only an exact child-and-priority duplicate idempotent; update deterministically or return a conflict for a different priority.
- **Test:** Cover equal-priority idempotence and the documented different-priority behavior.

### BR-024 — A matching ARP/NDP frame can arrive before the request send and still satisfy discovery

- **Status:** Fixed in the remediation worktree. Neighbor discovery compares monotonic ingress markers with each attempt's send boundary. Matching pre-send traffic is retained only as bounded evidence, while a following post-send match is accepted; the drain-to-send race has a dedicated regression.

- **Evidence:** `src/net/neighbor/provider.rs:233-261` drains before sending but does not attach a send-relative freshness marker to later matching.
- **Condition and impact:** A matching stale or unsolicited frame arriving in the drain-to-send race can satisfy lookup without answering the request. The race was not reproduced natively.
- **Remediation:** Use monotonic receive times or capture generations and require accepted evidence to be at or after the send boundary.
- **Test:** Inject matching traffic between final drain and send, reject it, then accept a matching post-send frame.

### BR-025 — Parse-error output-mode detection ignores end-of-options semantics

- **Status:** Fixed in the remediation worktree. Fallback output scanning stops at `--`; integration coverage distinguishes pre-terminator output options from post-terminator positional values.

- **Evidence:** `src/cli/errors.rs:105-119` scans raw arguments after parse failure without stopping at `--`.
- **Condition and impact:** A positional value such as `--output=json` can change only the parse-error format.
- **Remediation:** Stop fallback scanning at the terminator or preserve output context from the primary parser.
- **Test:** `packetcraftr read -- --output=json extra` was reproduced exiting 2 with JSON; it should use normal error formatting, while a pre-terminator option should still select JSON.

### BR-026 — Fuzz case-range validation has an off-by-one overflow check

- **Status:** Fixed in the remediation worktree. Validation checks `first_case + cases - 1`; `(u64::MAX, 1)` is accepted and `(u64::MAX, 2)` is rejected.

- **Evidence:** `src/workflow/fuzz/model.rs:217` validates `first_case + cases`, although the last generated index is `first_case + cases - 1`.
- **Condition and impact:** The valid range `(u64::MAX, 1)` is rejected.
- **Remediation:** Validate addition of `cases - 1` after proving the count is nonzero.
- **Test:** Accept `(u64::MAX, 1)` and reject `(u64::MAX, 2)`.

### BR-027 — Extremely small positive replay delays can round to zero and silently become immediate

- **Status:** Fixed in the remediation worktree. Paced modes reject a positive intended delay that converts to zero while `Immediate` and a zero original interval retain intentional zero-delay behavior.

- **Evidence:** `src/workflow/replay/model.rs:45-54` accepts finite positive values and does not reject a derived zero `Duration`. Rust 1.96.0 returned `Ok(0ns)` for several positive sub-nanosecond inputs.
- **Condition and impact:** An extreme rate or scale silently changes paced replay into immediate transmission.
- **Remediation:** Reject a zero derived duration in paced modes or clamp it to a documented minimum; keep zero intentional only for Immediate.
- **Test:** Cover very high fixed rates and very small scales, plus the intentional Immediate mode.
- **Reference:** [Rust `Duration::try_from_secs_f64`](https://doc.rust-lang.org/std/time/struct.Duration.html#method.try_from_secs_f64).

### BR-028 — Npcap drop aggregation aliases when an interval contains at least 2^32 combined drops

- **Status:** Fixed in the remediation worktree. Native drop components remain separate through capture ingress, each wrapping delta is computed independently, and widened totals at/either side of `2^32` are covered.

- **Evidence:** `src/net/platform/npcap.rs:411-412` wrapping-adds two `u32` counters before `src/net/platform/live_capture.rs:360-369` computes a wrapping delta.
- **Condition and impact:** If each native counter advances by less than `2^32`, its individual wrapping delta is recoverable; when those two deltas sum to at least `2^32`, the current pre-sum loses exactly one `2^32` increment. Multiple wraps within either individual counter remain inherently unobservable. This extreme Windows/Npcap condition was not reproduced.
- **Remediation:** Carry native counters separately, compute each wrapping delta, then sum into a widened accumulator.
- **Test:** Prove a single component wrap below the aggregate boundary is exact, then cover totals equal to and greater than `2^32`.

## Informational

### BR-029 — The committed CI workflow has no advisory, source, or license policy gate

- **Status:** Fixed in the remediation worktree. CI runs pinned `cargo-deny` advisory, license, source, and ban checks. The exact `paste 1.0.15` exception is documented and CI-enforced to expire on 2026-10-12; the current policy check passes.

- **Evidence:** `.github/workflows/ci.yml:24-32` runs formatting, checking, Clippy, and tests without a dependency-policy job; `Cargo.lock:474-475` contains transitive `paste` 1.0.15.
- **Impact:** Maintenance, advisory, source, or license-policy regressions can enter the lockfile without an automated signal. This is not a demonstrated packetcraftr vulnerability.
- **Remediation:** Add a maintained lockfile-aware policy gate with narrow, versioned, time-bounded exceptions.
- **Test:** Verify an unapproved advisory or disallowed source/license fails CI.
- **Reference:** [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html), status checked on 2026-07-12.
