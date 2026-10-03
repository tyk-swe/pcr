# Versioned offline resource presets

`--resource-preset ci-v1` and `--resource-preset workstation-v1` choose a named
set of finite defaults for offline capture commands. The flag is global and
works before or after the subcommand. Explicit individual flags always win.
Unsupported/live commands reject presets rather than changing authorization
or traffic limits. Without a preset, the documented defaults apply.

```sh
packetcraftr --resource-preset ci-v1 --resource-diagnostics --output json \
  verify-forwarding before.pcap after.pcap --identity ipv4.identification \
  --preserve ipv4.ttl --max-flows 2048
```

Resource diagnostics report each setting's resolved value and provenance (for
example `preset:ci-v1`; see [effective settings](analysis-resources.md#effective-settings-and-resource-ownership)
for the full list). Help without resolved diagnostics documents baseline
defaults. A preset is not an RSS guarantee or an automatic clamp: incompatible
explicit limits still fail validation.

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

Only options present on a selected command are changed; options not named here
keep their documented defaults, including other TLS retention ceilings and
idle-expiry settings. The values are conservative starting configurations, not
benchmark-derived capacity recommendations, and the limits are not a sum that
guarantees all enabled stages fit in memory together.

`http2` inherits the shared capture, TCP/IP, and application preset values.
The versioned v1 presets do not override any `--max-http2-*` setting; these
retain their baseline defaults unless explicitly supplied. Diagnostics report
those settings as `default` or `override`, not `preset:ci-v1` or
`preset:workstation-v1`. See [HTTP/2 limits](analysis-resources.md#http2-limits).

Input limits count filtered-out frames, and encoded/decoded source limits
include container metadata. See [analysis resource
accounting](analysis-resources.md#what-the-ceilings-cover) for reader-level
versus CLI-wrapper enforcement and the remaining state, allocation, and
process-memory distinctions.
