# Streaming capture write and replay

PacketcraftR v0.2 treats capture files as bounded streams of complete records.
Offline parsing and writing are pure Rust; native libpcap/Npcap is used only
when a replay actually selects Layer 2 transmission.

## Capture I/O contract

`CaptureReader` checks declared packet/block lengths before allocation and
bounds per-record bytes, PCAPNG interfaces, and metadata-only block runs.
`CaptureWriter` checks every record before emission and applies a
`CaptureStreamLimits` aggregate frame/captured-byte budget. The defaults are
10,000 frames, 256 MiB of captured payload, 16 MiB per packet/block, and 4,096
interfaces.

The public `CaptureInterface` metadata and `CaptureReader::interfaces()` retain
each open numeric link type, snap length, decimal/binary timestamp resolution,
and signed timestamp offset. `transcode_capture` copies one record at a time
and preserves:

- source byte order;
- globalized multi-interface identity and link type;
- snap length and timestamp resolution/offset;
- frame timestamp, direction, captured length, original wire length, and exact
  captured bytes.

Multiple PCAPNG sections are normalized into one section and one monotonically
increasing interface namespace. Unknown length-delimited metadata blocks are
skipped; they are not represented as packet metadata. Classic PCAP has no
interface/direction model, so PCAPNG-to-PCAP conversion is rejected instead of
silently discarding metadata. Classic PCAP microsecond or nanosecond precision
and either byte order survive a PCAP-to-PCAP copy.

The CLI exposes the writer through `read`:

```console
packetcraftr --output pcapng read input.pcapng \
  --max-frames 10000 --max-bytes 268435456 \
  --max-frame-bytes 16777216 --max-interfaces 4096 > copy.pcapng
```

## Replay contract

`replay_capture` is a reusable streaming engine with three mandatory injected
seams: `ReplayAuthorizer`, `ReplayTransmitter`, and `ReplayClock`. A caller can
test timing and live behavior without opening a native device. The system CLI
composition resolves the requested interface only after the current frame has
passed its resource and traffic-policy checks.

Live replay supports these exact capture roots:

| Capture root | Replay provider |
| ---: | --- |
| Ethernet / 1 | Layer 2 complete-frame injection |
| DLT_RAW / 12 | Raw Layer 3 |
| LINKTYPE_RAW / 101 | Raw Layer 3 |
| LINKTYPE_IPV4 / 228 | Raw Layer 3 |
| LINKTYPE_IPV6 / 229 | Raw Layer 3 |

`auto` selects the provider from this table. An explicit opposite mode fails;
BSD NULL/LOOP, Linux SLL/SLL2, and unknown numeric roots remain valid offline
evidence but are typed replay capability failures. No command strips a
capture-only header or silently changes provider.

Every frame must contain all original wire bytes. Dissection occurs before
interface discovery so explicit IP/SRH destinations pass the shared traffic
policy first. Public destinations are denied unless authorized. A preserved
`malformed` layer needs both the operation-level `--allow-malformed-live` flag
and policy-level `--allow-permissive-packets` flag.

Timing choices are:

- captured intervals (`--timing original`);
- captured intervals divided by a positive `--speed` multiplier;
- a positive fixed `--rate` in frames per second;
- no intentional delay (`--timing immediate`).

The frame, captured-byte, per-frame/block, interface, and cumulative scheduled
delay limits are checked with overflow-safe arithmetic before the affected
authorization, interface, delay, or send step. The maximum scheduled delay is
one hour. Bad/truncated records, unsupported roots, unavailable interfaces,
route mismatches, partial sends, and missing or changed backend wire evidence
are typed failures.

Text reports each successful exact send. Aggregate JSON retains bounded
per-frame evidence and terminal statistics. NDJSON emits one independently
valid `ReplayFrameCommandResult` per success followed by a terminal
`ReplayCommandResult`; an error uses the next source sequence. PCAP/PCAPNG
output contains only backend-confirmed successful frames. Classic PCAP replay
evidence is limited to classic single-root input; PCAPNG is the lossless choice
for mixed evidence.
