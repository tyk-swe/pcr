# Windows x86_64 MSVC and Npcap qualification

The Windows qualification procedure separates facts that a disposable hosted
runner can prove from privileged native-dependency rows that require a
controlled runner. Both paths build and test the exact extracted candidate
archive with Rust 1.96.0; neither treats the workflow checkout or an uncommitted
workspace as the release input.

## 0.2.0 release decision

On 2026-07-11, the release owner explicitly waived the dedicated Npcap runner
because no eligible host was available. XOD-51 is canceled rather than marked
as passed. For 0.2.0, real Npcap capture/injection and live workflows that
depend on it are an unqualified preview. The hosted MSVC boundary below remains
qualified, and this complete live procedure is retained for a later Release.

## Hosted MSVC boundary

Every push that changes this gate runs `qualify-windows-hosted.py` on
`windows-2022`. The hosted runner must not contain Npcap. It proves:

- x86_64 MSVC all-feature compilation and tests, including the native adapter
  and the user-space peer protocol regressions;
- real IP Helper interface inventory, `GetBestRoute2` IPv4/IPv6 local route and
  source selection, and Winsock raw IPv4/IPv6 sends constrained to loopback;
- runtime-loader, native-binding, and raw-socket dependency presence with no
  static `pcap`, `pnet`, `Packet.dll`, or `wpcap.dll` link/import boundary;
- an exact `capability.missing_dependency` result when Layer 2 capture opens
  without Npcap, with no change from the selected link mode; and
- byte-identical IPv4, IPv6, and stacked-VLAN builds against fixed portable
  baselines.

The verifier retains the candidate/archive/binary hashes, exact command
results, PE imports, dependency tree, runner version, fixed frames, tests, and
an independently checked evidence manifest.

## Dedicated Npcap runner

The manual `run_npcap_live` job selects only a self-hosted runner carrying all
of these labels:

```text
self-hosted, Windows, X64, packetcraftr-npcap-1.88
```

That runner must be an administrator-controlled, disposable Windows x86_64
MSVC machine with:

- Rust 1.96.0 and the normal Visual Studio x64 build tools;
- the 64-bit Npcap 1.88 runtime installed for the machine, its `npcap` service
  running, and the SDK 1.16 ABI used by PacketcraftR's reviewed runtime loader;
- two dedicated Ethernet adapters attached only to the same isolated virtual
  or physical switch; and
- no other workload, address, bridge, forwarding service, or packet generator
  on those adapters during qualification.

The Npcap free installer is interactive and is not downloaded or silently
installed by the workflow. Npcap documents silent installation and
redistribution as OEM features, so provisioning belongs to the runner owner
under their applicable license. The workflow records and verifies the installed
DLL version and digest instead of mutating that dependency.

The job receives the two reserved adapter aliases as `client_interface` and
`peer_interface`. It assigns `10.51.1.2/24` and `fd51:1::2/64` only to the
client, temporarily sets both MTUs to 1280, and leaves the target addresses
`10.51.1.9` and `fd51:1::9` unassigned. A candidate-built peer captures on the
second adapter through `SystemCaptureProvider` and injects ARP, NDP, UDP, TCP,
ICMP, traceroute, and DNS replies through `SystemLayer2Io`. This prevents the
host stack from satisfying the target traffic internally.

The exact candidate must then pass:

- native inventory and interface-constrained IPv4/IPv6 route plans;
- Layer 2 neighbor materialization and Winsock raw Layer 3 sends;
- capture-ready exchange and finite PCAPNG capture/readback;
- byte-identical stacked-Q-in-Q/VLAN Npcap replay and capture;
- TCP/ICMP scan, terminal UDP traceroute, deterministic DNS, and all four
  bounded live-fuzz strategies;
- a real ignored-endpoint timeout, low-MTU rejection, bounded queues, joined
  cleanup, and zero peer/capture loss; and
- the archive's injected missing-dependency, incompatible-ABI, permission,
  readiness, partial-send, timeout, resource, and cleanup regressions.

The harness removes only the two addresses it added and restores the recorded
per-family MTUs in its `finally` path. It does not reconfigure unrelated
adapters, install software, enable routing, or contact a network beyond the
isolated switch.

## Dispatch and evidence

After the workflow is present on the default branch, an authorized runner owner
can dispatch it with the approved full commit and adapter aliases:

```console
gh workflow run windows-qualification.yml --ref main \
  -f expected_commit=FULL_40_CHARACTER_SHA \
  -f run_npcap_live=true \
  -f client_interface='PacketcraftR Client' \
  -f peer_interface='PacketcraftR Peer'
```

`verify-windows-live-evidence.py` generates a pass report only after the native
protocol matrix, exact frames, Npcap identity, and zero-loss accounting all
agree. A future qualification must record the job URL, artifact ID, evidence
bundle digest, candidate commit, archive digest, binary digests, and Npcap DLL
digest; the 0.2.0 waiver is not reusable as evidence of such a pass.

Vendor references:

- https://npcap.com/dist/
- https://npcap.com/guide/npcap-users-guide.html
- https://npcap.com/oem/redist
