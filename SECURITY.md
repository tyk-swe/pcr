# Security policy

PacketcraftR parses capture files, packets, and documents that may come from people you do not trust, and its live features can send and capture real traffic under a fail-closed policy. We take reports about both sides seriously, and we would rather hear about a problem privately first so a fix can ship before working exploit details are public.

## Supported versions

Security fixes land on the `main` branch and ship in the next release. The latest published release and `main` are supported. Older releases, including earlier beta releases in the same series, are not supported, and the fix for those users is to upgrade to the latest release.

## Reporting a vulnerability

Do not open a public issue or pull request for a suspected vulnerability.

Email `mail@mail.tyk.sh`, or use the Report a vulnerability button on the repository Security tab, which opens a private report that only the maintainer can see.

Include the release version or commit you tested, your platform and feature build, the smallest input file or command line that reproduces the problem, and what an attacker gains from it. A crashing capture or document file is enough on its own, and you do not need to develop it further before reporting.

We will acknowledge your report, investigate it, and coordinate a disclosure date with you once a fix is ready. We are happy to credit reporters in the release notes unless you would rather stay anonymous.

## Scope

Reports we especially want include the following items.

- Any capture input (classic PCAP, PCAPNG, gzip or Zstd compressed captures, raw frames, or hex frame files), packet expression, or display filter that crashes the tool, overflows the stack, or makes it use memory or time far beyond its declared limits.
- Any untrusted document or text input that crashes the tool or escapes its declared bounds, including JSON or YAML packet documents (`packetcraftr.packet/v1`), binary field files (`--payload-file`), rewrite rules (`packetcraftr.rewrite/v1`), indicator files (`packetcraftr.indicators/v1`), engagement `Scope` files (`packetcraftr.scope/v1` and `packetcraftr.scope/v2`), engagement journal files (`packetcraftr.journal/v1`), aggregate CLI outputs (`packetcraftr.output/v22`), `Responder` reception logs, service probe and exclusion corpora (`packetcraftr.service-probes/v1` and `packetcraftr.service-exclusions/v1`), OS fingerprint corpora (`packetcraftr.os-fingerprints/v1`), UDP profile documents (`packetcraftr.udp-profiles/v1`), target or exclusion manifests, TLS key logs, or CA PEM files.
- Any memory safety problem in the native platform code under `packetcraftr-netio` (`platform`, the only module permitted to contain `unsafe` code) that handles capture devices (libpcap or Npcap), raw sockets, routes, or interface enumeration.
- Any way for live traffic to leave the machine, or for hostname resolution or capture to start, before the traffic policy has authorized the destination, hostname resolution opt-in, source ownership, dual opt-in for permissive or malformed live packets, and packet, traffic-unit, or byte budgets, or any way for a `Scope` document to widen rather than narrow policy.
- Any way for `network audit-tls` or `network audit-http --tls` to present an untrusted, expired, or wrongly named certificate as verified, accept a non-certificate PEM section in `--ca-file`, or send an HTTP request after TLS verification fails.
- Any output path that follows a swapped symlink or directory, overwrites an existing file it promised not to clobber, lets captured bytes inject terminal escape sequences into human-readable output, or lets captured or imported values inject unescaped markup or leak HTTP `Set-Cookie` values into `analyze report` HTML or `Evidence bundle` outputs.
- Any weakness in the repository dependencies, CI, or release pipeline that could put modified code or binaries in front of users.

The following activities and conditions are outside the scope of this policy.

- Using live or capture commands (`network` active and capture commands `send`, `exchange`, `capture`, `replay`, `scan`, `identify`, `identify-os`, `traceroute`, `dns`, `audit-tls`, `audit-http`, `differential`, and `differential-responder`, as well as `packet fuzz --live` and `analyze quic --interface`) against systems you are not authorized to test. Those commands exist for authorized diagnostics and protocol testing, and policy defaults exist to prevent accidents rather than to make an authorized operator harmless.
- Resource use that only happens because an operator raised the documented limits on their own machine.
- Vulnerabilities inside the operating system, libpcap, or Npcap themselves. Report those to their own projects, and also tell us when our use of them triggers the problem.

## Guarantees and known platform limits

### Fail-closed policy and engagement Scope narrowing

Live operations fail closed with default-deny policy flags (`allow_public_destinations`, `allow_hostname_resolution`, `allow_permissive_packets`, and `allow_source_spoofing` all default to `false`) and bounded default ceilings (10,000 packets or traffic units, 256 MiB, and 64 resolved addresses). Hostname resolution must be enabled before any DNS lookup runs, and every resolved address is authorized independently before route lookup, capture, neighbor discovery, or transmission starts. Hand-built and replayed frames also verify packet destinations and interface-owned sources unless source spoofing is enabled, and permissive or malformed live frames require both policy approval and `--allow-permissive-live`.

When `--scope-file PATH` supplies a `packetcraftr.scope/v1` or `packetcraftr.scope/v2` JSON document (at most 1 MiB, regular file, unknown fields rejected, canonical CIDRs required), the `Scope` only narrows what command flags allow. Boolean opt-ins combine by logical AND, packet and byte budgets keep the smaller ceiling, `denied_destinations` entries accumulate, and non-empty `allowed_destinations` lists add another group that every destination must satisfy before the public-destination check runs. A v2 `Scope` also declares a half-open Window with `not_before_unix_seconds` and `not_after_unix_seconds`, where the start is included and the end is excluded. Windows intersect when a `Scope` narrows a `Policy` that already carries one, an empty intersection denies every operation, and a pre-epoch system clock fails closed whenever a Window is present. The Window is checked when an operation is admitted, including before hostname resolution starts, and when a live capture is planned. Admission judges the Window at the instant the operation was admitted, and reauthorizing one message or packet of an already admitted operation does not recheck it, so an operation admitted inside the Window is not retroactively failed for running past its end and the Window complements rather than replaces per-operation duration limits. You can validate a `Scope` passively and inspect its canonical SHA-256 digest and Window state with `network preflight --scope-file PATH`, and v1 canonical digests are unchanged by the v2 addition. Live `network capture --scope-file` applies `Scope` budgets and the Window only, and live `analyze quic --interface` derives its packet and byte ceilings from capture limits rather than `--scope-file`.

### Plan digests and engagement journals

`network send`, `network exchange`, `network scan` and `network replay` accept `--plan-only` to prepare the operation and print its plan digest without sending, and `--plan-digest HEX` to require the prepared plan to reproduce a reviewed digest before any transmission, mirroring the mandatory differential gate as an opt-in. Send and exchange digests bind every expanded packet as built before route address filling, scheduling, the destination override and a canonical digest of the full traffic `Policy`. Replay binds every frame in the snapshotted capture plus timing, routing and filter arguments. Scan binds target declarations, endpoint selection, scheduling, UDP payload bytes and policy before resolution, so hostname answers and interface selection are not pinned by any plan digest. When the scan gate is active, the exact UDP payload and profile document bytes that were hashed are the bytes handed to request building, including when they arrived on stdin. A mismatch or malformed digest fails with `policy.plan_digest` before the client operation starts.

`analyze journal-build` writes a bounded `packetcraftr.journal/v1` document (at most 1 MiB and 1024 records, unknown fields rejected) whose records chain each finished result file by SHA-256 to the previous record, and `analyze journal-verify` rechecks the chain and any supplied result files against it. `analyze report --journal` additionally requires every report input to appear in the journal and anchors the verified journal head in the report measurements that the Evidence bundle embeds. A journal is tamper-evident only once its head digest is anchored outside the operator's sole control, and no live command appends to a journal implicitly.

### Socket audit admission and TLS verification

`network audit-tls` and `network audit-http` connect only to an explicit numeric `IP:PORT` endpoint without performing DNS lookups or target expansion. `--server-name` sets SNI and the expected certificate identity, and `--host` sets the HTTP `Host` header, without altering the target IP address.

Socket audits are admitted once through the traffic policy before any TCP connection starts, reserving their full traffic budget upfront. A TLS or HTTPS audit reserves 1 connection plus 1 traffic unit per TLS transport step (`1 + max_steps`, default 64 steps) and the full ciphertext byte ceiling (`max_wire_bytes_sent`, default 131,072 bytes), because the TLS transport counts every native read, write, or flush attempt and refuses any attempt past those limits without native I/O. A plain HTTP audit reserves 1 connection and 1 request message plus the exact `HEAD` request length, sending a single `HEAD` request with `Connection: close` and following no redirects. Traffic units count connections and socket messages or TLS transport steps rather than IP packets. Both audits also recheck destination authorization before connecting, after confirming the connected peer matches the admitted endpoint, and on every encrypted TLS write.

During a TLS handshake, the observation verifier checks TLS 1.2 or TLS 1.3 handshake signatures and retains complete DER certificates up to the set bounds (`max_certificates` and `max_certificate_bytes`) without slicing individual certificates. Certificate chain verification against bundled WebPKI roots (or certificate-only PEM anchors from `--ca-file`) and server-name matching run afterward against the current system clock, with no revocation fetching or cipher enumeration. Missing or truncated certificate chains never verify, and `network audit-http --tls` withholds the HTTP request when certificate verification fails.

### Staged atomic publication

PacketcraftR stages new file outputs inside the destination's parent directory, refuses existing destinations (including dangling symlinks, directories, and special files) before reading inputs, syncs staged bytes, and publishes atomically without clobbering (`files merge`, `files rewrite`, `files export`, `analyze follow`, `analyze quic --write`, `analyze report`, and `network differential-responder --log-file`). `reference documentation --directory` uses a separate replacement path that accepts missing destinations or regular files, renders and syncs every file before publishing any, and preserves existing file permissions on replacement. Multi-file writers sync all staged files before publishing any and report already-published paths if a later file fails to publish. Live `network capture --write` opens new files in the existing parent directory with exclusive no-clobber persistence (`persist_noclobber`) and retains open handles for `--retention ring` reuse.

On Unix, PacketcraftR opens the parent directory once before reading any input. Every later check, staging open, publication, and cleanup step operates relative to that directory descriptor, so a symlink swap or a renamed or replaced parent or ancestor directory cannot redirect output. On Linux with `O_TMPFILE` and verified `/proc/self/fd` links, the staged file has no directory entry until it is linked into place (or linked to a hidden random name first when replacing documentation). On other Unix systems, and on Linux filesystems without `O_TMPFILE` or procfs, the staged file uses a hidden random name opened with `O_CREAT`, `O_EXCL`, and `O_NOFOLLOW`. Publication is refused if that name no longer refers to the file PacketcraftR wrote, and a substitution racing the atomic publish causes an error instead of silently keeping the substitute (removing the foreign entry in no-clobber mode). Missing filesystem primitives fail with an error rather than falling back to a weaker publication path.

On Windows, the parent directory is held open without `FILE_SHARE_DELETE` so it cannot be renamed or deleted while output is staged, and publication uses `tempfile` path-based persistence. Retargeting an ancestor of the parent directory or substituting the staged path between creation and rename is not prevented on Windows, and this path has not yet been verified on a native Windows host. Across all platforms, attackers running as the same local user and filesystems lacking the required primitives are out of scope. Atomic publication does not provide crash durability, because PacketcraftR syncs the staged file without syncing the parent directory entry.

### Input polling, deadlines, and signal cancellation

On Unix, PacketcraftR reads duplicated standard input and opened paths by file type, polling pipes, FIFOs, sockets, and character devices in short readiness slices clamped to the remaining deadline so `--max-duration-ms` and the first Ctrl-C stop an input that sends no data. On Linux, opening a path uses `O_NONBLOCK`, which also covers FIFO paths that never get a writer. On macOS and other Unix systems, FIFO paths keep an ordinary blocking open and blocking reads because polling a non-blocking FIFO there did not reliably deliver data or end of file.

On Windows, reads from redirected stdin pipes and named pipes still block because the Rust standard library offers no safe readiness wait there. On all platforms, reads from regular files (including files on network filesystems) cannot be interrupted while a single read call is in progress, and if another process shares and drains the same stdin pipe between a readiness check and a read on Unix, that read can then block.

The first Ctrl-C triggers cooperative cancellation so running workflows, polled readers, and staged cleanup can finish cleanly. A second Ctrl-C runs best-effort removal of registered temporary staging entries without waiting on locks and exits immediately.

## Running PacketcraftR with least privilege

Offline work such as building packets, reading captures, dissecting frames, and running offline analysis needs no elevation at all. Run those commands as your regular unprivileged user, especially on captures and documents that came from someone else.

Live capture and raw packet transmission need whatever permission your operating system requires for those operations. Grant only the capture or raw socket permission the feature needs where your operating system offers a narrower grant than full administrator or root access, and return to an unprivileged shell for analysis afterward. Do not mark the binary setuid to bypass a permission prompt.

Treat every capture, packet expression, display filter, key log, CA bundle, and indicator or rules document from another person as untrusted input. The parsers are bounded and fuzzed under that assumption, and the safest workflow is still to open external files without elevation and keep the default limits unless you have a reason to raise them.
