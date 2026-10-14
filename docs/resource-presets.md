# Versioned offline resource presets

Global `--resource-preset ci-v1` / `workstation-v1` sets finite offline defaults;
explicit flags win. Unsupported/live commands reject presets. Unlisted options
keep baseline defaults. Diagnostics report preset/default/override sources;
incompatible limits still fail, never automatically clamp.

```sh
packetcraftr --resource-preset ci-v1 --resource-diagnostics --output json \
  analyze verify-forwarding before.pcap after.pcap --identity ipv4.identification \
  --preserve ipv4.ttl --max-flows 2048
```

| Limit | ci-v1 | workstation-v1 |
| --- | ---: | ---: |
| Input frames | 10,000 | 1,000,000 |
| Captured payload bytes | 16 MiB | 256 MiB |
| Encoded source / decoded container bytes, each | 32 MiB | 512 MiB |
| Single captured frame | 1 MiB | 16 MiB |
| Interfaces per PCAPNG section | 64 | 1,024 |
| Invocation time | 30 s | 300 s |
| Conversations per requested transport | 1,024 | 8,192 |
| Scope / provenance charge, each | 2 MiB | 16 MiB |
| TCP bytes per direction | 256 KiB | 4 MiB |
| TCP / IP retained state, each | 4 MiB | 32 MiB |
| TCP pending segments per direction | 128 | 1,024 |
| Concurrent IP datagrams | 256 | 4,096 |
| Fragments per datagram | 64 | 256 |
| IP bytes per datagram | 65,535 bytes | 1 MiB |
| Retained IP outcomes | 128 | 1,024 |
| TLS assembly buffer | 4 MiB | 32 MiB |
| TLS sessions | 128 | 2,048 |
| Application messages / streams | 256 / 64 | 4,096 / 1,024 |
| Application parse buffer | 2 MiB | 16 MiB |
| Application retained / output charge, each | 8 MiB | 64 MiB |
| Application source spans | 2,048 | 16,384 |
| Forwarding evidence per capture | 8 MiB | 64 MiB |
| Forwarding projection per observation | 16 KiB | 64 KiB |
| Forwarding entries per detail category | 64 | 256 |
| Forwarding shared detail charge | 1 MiB | 4 MiB |
| Forwarding comparison scratch charge | 16 MiB | 128 MiB |

These are conservative starting values, not benchmark-derived capacity or a sum
guaranteeing RSS. Filtered input still counts; source bytes include metadata.
HTTP/2 inherits shared capture/TCP/IP/application values but v1 presets never
override `max-http2-*`; those sources remain default/override.
See [accounting](analysis-resources.md#what-the-ceilings-cover),
[diagnostics](analysis-resources.md#effective-settings-and-resource-ownership),
and [HTTP/2 bounds](analysis-resources.md#http2-limits).
