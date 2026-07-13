# Operator and library manual

## Operating model

PacketcraftR is a local process. It reads explicit inputs, consults local interface and route state, optionally opens native sockets or capture handles, writes requested output, and exits. It has no GUI, daemon, database, account system, telemetry, update checker, or persistent history. Your shell and operating system may independently retain command lines or redirected output.

Offline commands (`build`, `dissect`, and `read`) work with `--no-default-features`. `interfaces`, `routes`, and `plan` are passive. `send`, `exchange`, `capture`, `replay`, live `fuzz`, `scan`, `traceroute`, and `dns` require the relevant native features and operating-system permissions.

The default `native` feature aggregates `native-route`, `native-layer2`, and `native-layer3`. Existing feature names remain independently selectable.

## Professional live controls

Live capture defaults to `--capture-mode promiscuous` and no BPF. Choose `--capture-mode host-only` to request non-promiscuous capture. `--auto-filter` derives a route-scoped filter; `--capture-filter BPF` installs the exact expression. Those flags are mutually exclusive, expressions are bounded to 4096 UTF-8 bytes, and compilation and installation finish before capture readiness and transmission.

`--discard-unmatched` omits uncorrelated and undecodable capture evidence. `--max-evidence-bytes` independently bounds raw aggregate evidence (16 MiB by default, 256 MiB maximum). Queue limits, snap length, packet policy, and operation duration remain separate controls.

No `--rate` means unlimited active rate within the finite operation budgets. Multi-packet commands issue a structured `traffic.unthrottled` warning when that default applies. Promiscuous unfiltered operations issue `capture.promiscuous_unfiltered`.

Traffic authorization happens before route, neighbor, capture, or send work wherever the destination is already known. Public destinations and permissive/malformed live packets require their explicit policy opt-ins. Authorization does not establish legal permission to test a target.

## Doctor and readiness

`packetcraftr doctor` reports version, build target, platform, compiled features, interfaces, routes, and Layer 2, Layer 3, and capture status. Status is one of `ready`, `not_built`, `unverified`, or `unavailable`.

Use `--interface NAME_OR_INDEX` to constrain the check and `--require interfaces,routes,layer2,layer3,capture` to make missing readiness fail in the existing capability/device exit families. Capture is `unverified` until `--probe-capture` is requested. The probe is host-only and filtered, opens and closes one capture session, retains nothing, and sends nothing.

## Privileges and native dependencies

On Linux, install libpcap and grant only the capabilities the selected operation needs. A typical packaged-binary setup may use `CAP_NET_RAW` for raw transmission and `CAP_NET_ADMIN` where the platform requires it for capture configuration. File capabilities are security-sensitive and are lost when the binary is replaced; verify them after upgrades. Running an entire shell as root is broader than necessary.

On macOS, libpcap is provided by the platform, but BPF device permissions determine capture access and raw sockets may require elevation. On Windows, install Npcap 1.88 from the official Npcap distribution and enable its compatibility mode if required by local policy. PacketcraftR dynamically loads Npcap; do not place untrusted DLLs on its search path.

If `doctor` reports `not_built`, inspect `compiled_features` and install a full-native artifact or rebuild with default features. `unavailable` generally means the device, route, dependency, or privilege is missing. Filter syntax errors and filter-install failures are typed and occur before transmission. A cleanup error means PacketcraftR could not confirm that capture work stopped; investigate the backend before retrying an active operation.

## Output and exit behavior

Text is for operators. Exact whole bytes require `--output hex`, `raw`, `pcap`, or `pcapng`; text previews only the first 128 bytes. Aggregate `json` is bounded. `ndjson` is the live incremental contract and flushes every record.

The immutable structured schema identifier is `packetcraftr.output/v2`. Aggregate records include `tool`, `operation_id`, `command`, `effective_request`, `status`, a `result` or classified `error`, `diagnostics`, `completion_reason`, and `stats` where applicable. Error `kind` preserves the established CLI family; `category` distinguishes validation, capability, policy, timeout, I/O, cleanup, and invariant recovery.

CLI/validation errors use status 2, packet/input errors 3, unavailable capability/device errors 4, I/O errors 5, and policy errors 6. Internal invariant failures use 70. SIGINT and SIGTERM use 130 and 143 after confirmed cleanup. Consult the structured `error.code` and `category` rather than matching message text.

## Replay guarantees

CLI replay opens one seekable file and performs a complete preflight pass. The pass checks capture decoding, per-frame and aggregate limits, link type and requested mode, selected interface, every wire destination, traffic policy, timing arithmetic, and total scheduled duration. Only after end-of-input is validated does execution rewind the same handle. Each frame identity is verified before its delay and send, preventing a changed file from being replayed under stale authorization.

Aggregate replay JSON is a bounded summary. NDJSON emits confirmed per-frame evidence. PCAP and PCAPNG preserve exact transmitted evidence and source timing metadata. Classic PCAP requires one link type; use PCAPNG for mixed interfaces or link types.

## Operation correlation and reproducibility

The CLI generates a 128-bit operation ID from operating-system entropy before active side effects. A stable domain-separated mixer derives generated TCP sequences, IP identifiers, IPv6 flow labels, ICMP identities, DNS transaction IDs, and candidate source ports. Generated source ports are reserved through the operating system for the context lifetime with at most 128 candidates. Explicit packet fields, DNS IDs, and source ports are never rewritten.

Pass `--operation-id` to reproduce derived values. Fuzzing also records its operation seed, case index, and case seed. The operation ID is correlation material, not a cryptographic secret.

## Library API

The crate exposes one `operation` module with `Id`, `Context`, cancellation, completion reasons, and `EventSink`. Streaming workflow functions accept a context and sink; aggregate functions are collector-backed conveniences.

`net::capture::Options` contains `Mode`, `Filter`, and unmatched-evidence behavior. `CaptureProvider::arm_capture_with_options` is additive: existing providers continue to support the broad default and return a typed capability error for requested options they cannot honor.

Replay uses `workflow::replay::prepare` and `execute`. `prepare` stores bounded frame identities and scheduling metadata, never a second copy of frame bytes. `replay_streaming` remains available for non-seekable input and documents its partial-execution risk.

Library callers should propagate one operation context, poll cancellation at their own expensive boundaries, flush streaming sinks, and treat capture shutdown errors as higher priority than an otherwise ordinary cancellation.

## Troubleshooting checklist

1. Run `packetcraftr --output json doctor` and inspect compiled features and readiness.
2. Select the interface by exact name or index; confirm it is up and has the intended route and source address.
3. Confirm libpcap/Npcap availability and minimum privileges.
4. Test a host-only automatic filter before using promiscuous unfiltered capture.
5. Set explicit rate, packet, byte, duration, queue, snap, and evidence limits appropriate to the engagement.
6. Preserve the operation ID and structured error code when reporting a failure. Do not include sensitive packet evidence unless necessary.
