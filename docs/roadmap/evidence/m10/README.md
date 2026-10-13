# M10 original capture and hold-out evidence

Original Linux kernel captures in isolated 1500-byte veth namespaces (`192.0.2.0/24`,
`2001:db8::/64`, checksum offload disabled, immediate replies; no Nmap data).

| Partition | Actual stack | Artifact |
| --- | --- | --- |
| Training | Linux 7.0.0-38-generic, host kernel | [training-kernel-7.0.0-38-generic.json.gz](training-kernel-7.0.0-38-generic.json.gz) |
| Held out | Linux 7.0.0-34-generic, KVM guest | [held-out-kernel-7.0.0-34-generic.json.gz](held-out-kernel-7.0.0-34-generic.json.gz) |

## Freeze and evaluation

[Freeze metadata](held-out-freeze.v1.json) (raw SHA-256
`ff3d2282d46e4fa08e4d7fec167e27d86408ff1dd467b72883800a69c4188b37`) and
[pre-evaluation signatures](signatures-before-evaluation.v1.json) (17 predicates
per family) were fixed before evaluating the hold-out:

```sh
cargo test --locked -p packetcraftr-core --all-features \
  frozen_independent_linux -- --nocapture
```

| Held-out condition | Case-runs | Result |
| --- | ---: | --- |
| Suitable IPv4/IPv6, JSON/NDJSON | 4 | Linux qualified in 4; unknown 0; ambiguous 0 |
| Missing open/closed prerequisite, both families/formats | 8 | Inconclusive in 8; candidates 0 |

[Final Linux validation](validation-linux.v1.json.gz) (raw SHA-256
`0c7f94c34897c78a06efa0c15dc1637540c4cfc209b8994fb40dc3288ce38229`) retains 12
passing case-runs:

```sh
sudo python3 scripts/test-os-identification-native.py \
  --output target/validation/os-native.json --require-complete
```

These repeats come from one held-out kernel build; cross-family accuracy and
reviewed-revision Linux/macOS/Windows gates remain open.
