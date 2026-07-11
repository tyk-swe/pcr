# packetcraftr-io

Offline capture, routing, neighbor resolution, provider contracts, and target-specific native adapters for [PacketcraftR](https://github.com/tyk-swe/pcr).

This internal workspace crate is not published independently. Applications should use the `packetcraftr` façade. Unsafe and native bindings are confined to the crate-private `io::platform` subtree.
