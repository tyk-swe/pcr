# ADR 0003: Capture records and exchange receive-stream ownership

- Status: Accepted
- Date: 2026-07-09

## Context

Starting a listener after sending loses immediate responses. Starting independent listeners for different stages causes competing consumers, duplicated platform handles, and receivers that can silently drain traffic intended for correlation. Summary-only listener events also discard bytes required for PCAP output, later dissection, evidence, and reassembly.

Capture inputs are not always Ethernet. PCAPNG can carry multiple interfaces with different link types, and unknown data-link types must survive an offline round trip without being guessed.

## Decision

Use a raw capture record independent of decoding. `CapturedFrame` contains:

- timestamp;
- captured length and original wire length;
- an open numeric link type;
- optional interface and direction metadata; and
- complete captured bytes up to the configured snap length.

Presentation truncation never mutates the bytes stored in the record. Unknown link types remain raw frames with a diagnostic. The dissector selects a root through the frame's actual link type and does not assume Ethernet.

Capture-record construction is fallible. `CapturedFrame::new` derives representable captured and original lengths from the supplied bytes, while `try_with_lengths` requires the byte count to equal the declared captured length and the original length to be at least as large. Deserialization and dissection validate the same invariants so inconsistent public-field mutation cannot become an unchecked parser input.

A coordinated exchange owns one receive stream:

1. Configure filters, queues, and bounds.
2. Start capture.
3. Wait for an explicit readiness result.
4. Transmit the first frame only after readiness.
5. Decode, optionally reassemble, and correlate frames from that owned stream.
6. Route unmatched frames into a bounded unsolicited collection rather than discarding them.
7. Stop and join capture on success, timeout, send failure, startup failure, or cancellation.

The send boundary is exact: a backend report must say that every submitted byte was sent, and any optional returned wire image must have that same length. A partial or internally inconsistent report is a typed I/O failure. Failure handling still stops and joins capture; if both the operation and shutdown fail, the result retains both causes instead of masking either one.

When reply capture has no explicit timeout, use a bounded three-second default reply window. The default backend queue is one aggregate 4,096-frame / 256 MiB bound shared by matched, unsolicited, and undecodable traffic; retention-class limits never add together to enlarge that queue. Snap length is independently bounded to 16 MiB per frame.

Queue overflow policy is explicit: `fail` is the default and returns a typed error; `drop-newest` and `drop-oldest` are opt-in loss policies. Every backend must return cumulative received-frame/byte, dropped-frame/byte, and overflow-event counters through the owned session. Inconsistent counters fail closed. Successful lossy capture adds a structured warning and the counters to operation statistics, so backend loss is never silent.

## Consequences

- Immediate loopback and low-latency replies are not lost to listener startup races.
- A response matcher sees full request and response packet evidence.
- Offline capture transforms can remain lazy and bounded.
- Malformed capture-length metadata is rejected before a dissector can trust it.
- Cancellation requires structured task ownership; detached capture tasks are defects.
- Packet-I/O adapters must distinguish a complete frame send from partial progress.
- A single receive stream needs internal fan-out to correlation, optional reassembly, and user-facing capture consumers.
- Unknown or unsupported link types remain round-trippable, even when no structured decode is possible.
- PCAPNG interface identity and per-interface link type must be preserved through reads and writes.

## Alternatives considered

### Send, then start listening

Rejected because it has an unavoidable race for immediate replies.

### A background receiver that discards frames until needed

Rejected because it steals traffic and destroys evidence. Frames must enter an owned, bounded stream with visible overflow behavior.

### Decode before constructing a capture record

Rejected because a decoder can fail, link types can be unknown, and later consumers still need the exact original record.

### Treat every capture as Ethernet

Rejected because raw IP, BSD NULL/LOOP, Linux cooked capture, and unknown DLT values have different layouts and would be silently misdecoded.
