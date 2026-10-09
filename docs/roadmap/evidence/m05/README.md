# M5 discovery acceptance records

[Linux](linux.json) binds clean implementation and fixture revision
`e7f3e2efa7b47ba2ffa7e2818dbcc4d53eaef9e3`, independently authored scanner
corpus dataset 1.3.0, executable/source digests, actual privileged fresh
namespaces, commands, bounded output, and independently checked observations.
Documentation follows that implementation revision.

| Profile | Exercised cases | Actual typed capability refusals |
| --- | ---: | ---: |
| portable | 4 | 12 |
| default | 4 | 12 |
| layer2 | 16 | 0 |
| pcap-free | 4 | 12 |
| full-native | 16 | 0 |

All 168 CLI invocations retained their command and result. Layer2 and full-native
exercise six IPv4/IPv6 conditions under discovery-only, responder-only scan, and
scan-all follow-up, including actual router-sourced error frames. Every profile
exercises IPv4/IPv6 ordinary-socket acceptance and refusal. The independently
encoded Ethernet responder sends immediately, without an artificial reply delay.

The report remains globally `incomplete`: portable/default/pcap-free cannot
capture raw discovery. Acceptance verifies their real nonzero typed refusals;
it never calls those paths exercised. The supported-path acceptance command
exited zero, and the record contains no launcher or validation failure:

```sh
sudo -n env "PATH=$PATH" "CARGO_HOME=$HOME/.cargo" "RUSTUP_HOME=$HOME/.rustup" \
  python3 scripts/test-host-discovery-native.py \
  --reviewed-commit e7f3e2efa7b47ba2ffa7e2818dbcc4d53eaef9e3 \
  --require-complete --report target/validation/m5-acceptance/host-discovery.json
```

The user requested skipping remaining environment-dependent macOS/Windows
checks. The [reviewed host-local run](https://github.com/tyk-swe/pcr/actions/runs/37968418933)
retains failed/unavailable results at the earlier implementation revision
`2f7eaafbed809e2e5cae49b60176ec072a6f0897`; it does not close cross-platform
acceptance. macOS ARM reported fixture contradictions; Windows completed with
explicit unavailable raw paths; macOS Intel was cancelled. See
[M5's remaining native acceptance](../../m05-host-discovery.md#remaining-native-acceptance).

These records establish Linux discovery correctness in the controlled topology,
not production-network accuracy, benchmark superiority, synchronized clocks,
authenticated host identity, or broad platform parity.
