# Cross-platform exact-byte parity qualification

The stable v0.2 gate compares one immutable source candidate on four hosted
targets:

- Ubuntu 24.04 x86_64 GNU;
- macOS 15 arm64;
- macOS 15 x86_64; and
- Windows Server 2022 x86_64 MSVC.

The workflow packages the candidate once on Linux and sends that same archive
and `SHA256SUMS` to every runner. Each runner verifies the archive commit and
checksum before extraction. It builds and tests with Rust 1.96.0 and
`--no-default-features`, so the compared behavior has no native route, capture,
or socket dependency.

## Shared corpus

[`tests/parity/manifest.json`](../tests/parity/manifest.json) is the reviewed
portable corpus. It covers exact construction of raw, Ethernet, stacked
802.1ad/802.1Q, ARP, IPv4, IPv6, Hop-by-Hop, Destination Options, Fragment,
SRH, ICMPv4/v6, TCP, UDP, padding, DNS wire data, JSON/YAML documents, and an
explicit malformed document. Two fixed fuzz seeds exercise boundary, random,
bit-flip, and malformed strategies, including a nonzero reproduction window.

The generator also discovers every hash-pinned authoritative frame and capture
fixture. It requires the complete stable capture-root set (DLT/LINKTYPE 0, 1,
12, 101, 108, 113, 228, 229, and 276) plus the unknown DLT 147 fixture. Valid
PCAP and PCAPNG files are streamed, transcoded to every representable capture
format, read again, and compared by exact format hash and normalized frame
metadata. Malformed capture seeds must end in a typed error. The external
protocol-module test is rerun under the same portable profile.

## Evidence and comparison

Run the generator against release inputs from the repository root:

```console
RELEASE_TREE="$(git rev-parse HEAD)" \
  bash scripts/build-release-inputs.sh /tmp/packetcraftr-candidate

python3 scripts/generate-parity-evidence.py \
  --candidate-directory /tmp/packetcraftr-candidate \
  --expected-commit "$(git rev-parse HEAD)" \
  --platform linux-x86_64 \
  --evidence /tmp/packetcraftr-parity-linux \
  --bundle /tmp/packetcraftr-parity-linux.tar.gz
```

`parity-evidence.json` binds the platform, candidate commit, archive checksum,
binary checksum, MSRV, feature profile, manifest checksum, required coverage,
and every normalized case to SHA-256. Its corpus digest intentionally excludes
the platform-specific executable checksum.

After collecting the four platform artifacts, the final gate is:

```console
python3 scripts/compare-parity-evidence.py \
  --artifacts-root /tmp/platform-evidence \
  --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/packetcraftr-parity-comparison \
  --bundle /tmp/packetcraftr-parity-comparison.tar.gz
```

The comparison fails for a missing/duplicate platform, candidate or manifest
drift, incomplete coverage, altered evidence, missing/extra cases, or any case
hash difference. The workflow retains all platform evidence and the comparison
for 90 days.

This gate proves portable byte, dissection, document, capture-format, external
codec, and deterministic fuzz parity. It does not replace the privileged Linux,
macOS, or Npcap live-I/O qualification procedures.
