# ADR 0006: Native raw IP transmission

- Status: Accepted
- Date: 2026-07-10

## Context

Layer 3 mode needs a native path that submits complete IPv4 or IPv6 datagrams without accepting Ethernet bytes or silently switching to Layer 2. Raw-socket behavior is not byte-neutral on every target: Linux documents mandatory IPv4 filling in [`raw(7)`](https://man7.org/linux/man-pages/man7/raw.7.html), Apple's [XNU raw-IP implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/raw_ip.c) consumes BSD header conventions, and Microsoft documents raw TCP and spoofed UDP restrictions in [TCP/IP raw sockets](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2). A successful API result cannot claim the final built bytes were sent when the operating system necessarily changed their meaning.

## Decision

The opt-in `native-layer3` feature provides `SystemLayer3Io` through `socket2` 0.6 raw sockets on Linux, macOS, and Windows. The public `Layer3Io` seam remains independently injectable and contains no native handles. `Layer3Frame` continues to reject every materialized mode except `Layer3`, so explicit Ethernet/VLAN intent cannot reach this adapter.

Before opening a socket, the adapter validates a complete IPv4/IPv6 header, exact declared length, nonzero source and destination, route family/destination, and route MTU. IPv4 additionally requires a correct header checksum and nonzero identification. These checks guarantee mandatory kernel filling is byte-identical; values that would produce a post-build change fail with `InvalidTransmissionFrame`.

The socket binds the route-selected interface and interface-owned source independently from the source encoded in the packet. This preserves crafted/spoofed packet identity while constraining native routing. macOS receives a private submission copy whose IPv4 total-length and flags/fragment-offset fields are converted to host order; the immutable built bytes remain the reported wire evidence. Every target enables full-header inclusion, submits the route destination, requires a complete native write, and maps permission, interface, unsupported, and send failures to typed errors.

Raw UDP with a non-local crafted source is rejected on Windows because affected client versions can silently drop it. Raw TCP and other operating-system restrictions are attempted only where the native provider permits them and remain typed socket errors. Hosted tests use an injected raw backend for validation, exact-byte, partial-write, and error mapping; privileged runner qualification remains required for live capability claims.

## Consequences

- The same `DispatchPacketIo` can compose native Layer 2 and Layer 3 providers without mode ambiguity.
- Strictly built IPv4/IPv6 frames with supported fields can report exact optional wire bytes.
- A fresh IPv4 packet must use a nonzero identification for native Layer 3 transmission; zero remains valid for offline building but cannot be claimed as an exact raw-socket send.
- The no-default and Windows default profiles remain free of raw-socket dependencies.

## Alternatives considered

### Trust the kernel and omit wire evidence

Rejected because silent field correction violates crafted wire intent and makes post-build policy evidence differ from transmission.

### Route Layer 3 requests through the Layer 2 adapter

Rejected because it changes link intent, introduces neighbor discovery, and crosses the typed provider boundary.

### Put socket handles in `Layer3Io`

Rejected because native lifetime and ABI details belong exclusively to the private platform adapter subtree.
