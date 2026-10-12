# M10 original capture and hold-out evidence

The initial corpus uses original real Linux responses. Synthetic responders test
workflow behavior and do not provide OS labels. No Nmap database or comparator
supplied signatures or expectations.

| Partition | Actual stack | Artifact |
| --- | --- | --- |
| Training | Linux 7.0.0-38-generic, host kernel | [Complete capture](training-kernel-7.0.0-38-generic.json.gz) |
| Held out | Linux 7.0.0-34-generic, separately booted KVM guest | [Complete capture](held-out-kernel-7.0.0-34-generic.json.gz) |

Each run uses fresh parent-distinct source and peer network namespaces, a
1500-byte veth pair with 192.0.2.0/24 and 2001:db8::/64 addresses, actual TCP
listeners, a closed endpoint, disabled checksum offload, and immediate kernel
replies. The guest has no virtual network device; only its isolated internal
fixtures send traffic. Its initramfs contains the CLI, Python runner/runtime,
network tools, and matching kernel veth module. No module/code is bundled here.

## Freeze and evaluation

[Freeze metadata](held-out-freeze.v1.json) records the held-out kernel, source and
binary identity, twelve exercised case-runs, and raw/compressed hashes. Raw
SHA-256 is `ff3d2282d46e4fa08e4d7fec167e27d86408ff1dd467b72883800a69c4188b37`.
Held-out response bytes were not inspected during rule authoring. Metadata was
checked before reading training observations. The
[pre-evaluation signatures](signatures-before-evaluation.v1.json) then froze
seventeen predicates per family. Scale, TTL, sequence, timestamps and IDs remain
observations. The capture-stage corpus was empty; offline evaluation applies the
frozen authored signatures to those exact observations.

```sh
cargo test --locked -p packetcraftr-core --all-features \
  frozen_independent_linux -- --nocapture
```

The regression verifies the raw capture hash and frozen rule equality, then
checks independently known listener roles and Linux family labels:

| Held-out condition | Case-runs | Result |
| --- | ---: | --- |
| Suitable IPv4/IPv6, JSON/NDJSON | 4 | Linux qualified in 4; unknown 0; ambiguous 0 |
| Missing open/closed prerequisite, both families/formats | 8 | Inconclusive in 8; candidates 0 |

These are repeats of **one held-out build**, not twelve independently sampled
OS instances. This measures positive qualification and suitability for the
recorded profiles. Other-family false-positive accuracy, broad coverage,
confidence calibration, and performance are unmeasured. Do not report these
counts as general OS-identification accuracy.

## Reproduction and remaining gates

Build the all-feature CLI and run:

```sh
sudo python3 scripts/test-os-identification-native.py \
  --output target/validation/os-native.json --require-complete
```

Linux requires `ip`, `unshare`, `nsenter`, and `ethtool`. A separate kernel can be
booted with a local kernel/initramfs in a network-disabled guest and the runner's
`--source-identity` manifest supplied; the manifest must name the runner hash.
Freeze the complete artifact before authoring new signatures, partition by kernel
build/image, and evaluate after freezing the rules. Original JSON includes exact
commands, stdout/stderr, frames, status, source dirty flag/content hash, binary
hash, and kernel/architecture. Compressed artifacts use deterministic gzip.

The first artifacts are implementation-stage **dirty-source snapshots** with
explicit content/binary hashes, not immutable reviewed-revision platform
acceptance. [Final Linux validation](validation-linux.v1.json.gz) retains twelve passing
case-runs with the final binary/source content hashes, actual privilege/namespace
and libpcap version. Its raw JSON SHA-256 is
`0c7f94c34897c78a06efa0c15dc1637540c4cfc209b8994fb40dc3288ce38229`. Reviewed-revision
Linux/macOS/Windows gates, other families/configurations/intermediaries, scoped
native cases, and broader accuracy/performance remain open. Hosted loopback,
compilation, refusals and unavailable cases cannot close these gates.
