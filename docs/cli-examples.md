# CLI workflows and executable examples

These examples cover the complete frozen v0.2 command surface. Run packet
construction, dissection, capture-file conversion, and offline fuzzing anywhere.
Run passive native discovery or live traffic only in an isolated lab that you
own or are explicitly authorized to test.

The checked-in examples use documentation or private lab addresses. They are
not permission to contact any network, and they are not a substitute for
replacing every address, interface, capture, and budget with values approved for
your environment. PacketcraftR denies public destinations and hostname
resolution by default, but policy checks are a last line of defense rather than
authorization.

Build the portable binary used by the documentation check:

```console
cargo build --locked --no-default-features
```

CI runs `python3 scripts/check-documentation-examples.py` against that binary.
The offline examples must succeed. Passive/native and live examples must parse
completely and then return the documented capability exit class (4) before any
route, capture, or transmission side effect. The checker also executes
`packetcraftr --help` and every `packetcraftr COMMAND --help`; the reviewed
snapshot is in [`tests/golden/cli-help.txt`](../tests/golden/cli-help.txt).

For actual native use, build the feature path listed in the
[platform matrix](platform-support.md#build-and-feature-contracts), satisfy its
runtime and privilege requirements, and replace `lab0` below with an exact
authorized interface name or index. Do not add public-destination, hostname,
permissive-packet, or malformed-packet acknowledgements unless the reviewed
operation genuinely requires them.

## Portable packet and capture-file workflows

### Build

Build a complete IPv4/UDP datagram and return typed bytes, materialized fields,
layout, and diagnostics.

<!-- cli-example:build -->
```console
packetcraftr --output json build \
  --packet 'ipv4(src="192.0.2.1",dst="192.0.2.2")/udp(sport=40000,dport=9)/raw(text="hello")'
```

### Dissect

Decode exact bytes under the open numeric DLT_RAW link type (12).

<!-- cli-example:dissect -->
```console
packetcraftr --output json dissect \
  --hex 45000021000000004011f6c8c0000201c00002029c400009000d9bb468656c6c6f \
  --link-type 12
```

### Read and write capture files

Stream a reviewed PCAP into PCAPNG without losing frame metadata, then read the
copy as independently valid NDJSON records. PCAPNG-to-PCAP conversion is
rejected when it would lose interface metadata.

<!-- cli-example:read -->
```console
packetcraftr --output pcapng read \
  tests/fixtures/captures/pcap/ethernet-ipv4-udp.pcap \
  > packetcraftr-example-copy.pcapng
packetcraftr --output ndjson read packetcraftr-example-copy.pcapng
```

### Offline fuzz

Generate two deterministic field-aware cases without constructing a resolver,
route provider, capture session, or transmitter. Reproduce one case with the
same seed plus `--first-case INDEX --cases 1`.

<!-- cli-example:fuzz -->
```console
packetcraftr --output json fuzz \
  --packet 'ipv4(src="192.0.2.1",dst="192.0.2.2")/udp(sport=40000,dport=9)/raw(text="hello")' \
  --seed 42 --cases 2 --strategy boundary
```

## Passive native discovery

These commands do not emit packets. They still require the platform-native
discovery capability, and the portable documentation build therefore proves
that they fail with exit 4 instead of inventing data or changing providers.

### Interfaces

<!-- cli-example:interfaces -->
```console
packetcraftr --output json interfaces
```

### Plan

Inspect the selected route, interface-owned source, next hop, MTU, and link mode
without ARP, NDP, capture, or transmission.

<!-- cli-example:plan -->
```console
packetcraftr --output json plan \
  --packet 'ipv4(dst="192.168.56.10")/udp(dport=9)/raw(text="hello")' \
  --interface lab0 --link-mode layer3 --max-packets 1 --max-bytes 1500
```

### Routes

Report one passive, interface-bound provider decision for each up interface;
this is not a verbatim operating-system route-table dump.

<!-- cli-example:routes -->
```console
packetcraftr --output json routes
```

## Authorized live workflows

The remaining commands can capture or transmit. Their examples use finite
private-lab targets, exact interfaces, short timeouts, and small traffic or
evidence budgets. The no-native-feature CI binary reaches a typed capability
failure before live I/O. A native build can perform the operation, so never copy
one unchanged onto a connected system.

### Send

<!-- cli-example:send -->
```console
packetcraftr --output json send \
  --packet 'ipv4(dst="192.168.56.10",identification=1)/udp(dport=9)/raw(text="hello")' \
  --interface lab0 --link-mode layer3 --max-packets 1 --max-bytes 1500
```

### Exchange

Arm capture before sending one request and retain at most one correlated
response and no unsolicited decoded frames.

<!-- cli-example:exchange -->
```console
packetcraftr --output json exchange \
  --packet 'ipv4(dst="192.168.56.10",identification=1)/udp(dport=9)' \
  --interface lab0 --link-mode layer3 --timeout-ms 100 \
  --max-packets 1 --max-bytes 1500 --max-responses 1 \
  --max-unsolicited 0 --max-queue-frames 8 --max-captured-bytes 12000 \
  --snap-length 1500
```

### Capture

Capture for a finite window. NDJSON preserves a valid terminal error record if
the requested native capability is unavailable.

<!-- cli-example:capture -->
```console
packetcraftr --output ndjson capture \
  --packet 'ipv4(dst="192.168.56.10")/udp(dport=9)' \
  --interface lab0 --timeout-ms 100 --max-packets 1 --max-bytes 1500 \
  --max-queue-frames 8 --max-captured-bytes 12000 --snap-length 1500
```

### Replay

Replay only an authorized, reviewed capture on the exact intended interface.
The checked-in fixture preserves exact captured field intent, so this validation
example supplies both required acknowledgements; do not generalize those flags
to unreviewed captures.

<!-- cli-example:replay -->
```console
packetcraftr --output json replay \
  tests/fixtures/captures/pcap/ethernet-ipv4-udp.pcap \
  --interface lab0 --link-mode layer2 --timing immediate \
  --max-packets 1 --max-bytes 16777216 --max-frame-bytes 16777216 \
  --allow-malformed-live --allow-permissive-packets
```

### Scan

<!-- cli-example:scan -->
```console
packetcraftr --output json scan 192.168.56.10 \
  --transport tcp --ports 443 --attempts 1 --timeout-ms 100 \
  --batch-size 1 --rate 1 --max-probes 1 --max-duration-ms 1000 \
  --interface lab0 --link-mode layer3 --max-packets 1 --max-bytes 1500
```

### Traceroute

<!-- cli-example:traceroute -->
```console
packetcraftr --output ndjson traceroute 192.168.56.10 \
  --strategy udp --first-hop 1 --max-hops 1 --attempts 1 \
  --timeout-ms 100 --rate 1 --max-probes 1 --max-duration-ms 1000 \
  --interface lab0 --link-mode layer3 --max-packets 1 --max-bytes 1500
```

### DNS

Query one explicitly authorized private-lab DNS server. A hostname in the server
position would additionally require the independent hostname-resolution policy
acknowledgement.

<!-- cli-example:dns -->
```console
packetcraftr --output json dns 192.168.56.53 www.example.test \
  --type a --attempts 1 --timeout-ms 100 --rate 1 \
  --max-duration-ms 1000 --interface lab0 --link-mode layer3 \
  --max-packets 1 --max-bytes 1500
```

Use the command-specific `--help` text for every finite default and maximum, the
[CLI contract](cli-contract.md) for exit/output guarantees, and the
[platform troubleshooting guide](platform-support.md#capability-troubleshooting)
for exit class 4. Exit 5 means the capability exists but route, device, timeout,
capture, send, or cleanup failed; exit 6 is a traffic-policy denial and must not
be worked around without a fresh authorization review.
