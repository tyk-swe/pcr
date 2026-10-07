# M4 acceptance records

These records bind the clean implementation and fixture revision
`8e010a0b9eac118aa13384f0b854111a73d47d76` and independently authored scanner
corpus dataset 1.1.0. Documentation-only closure follows that revision.

| Record | Scope |
| --- | --- |
| [Linux](linux.json) | Scoped selection, sockets, routes, raw correlation or explicit capability failures in five feature profiles, each in a fresh private network namespace. |
| [Linux complete native inventory](linux-eight.json) | All eight Linux native scenarios, including scoped IPv6; full-native profile. |
| [macOS ARM](macos-arm64.json), [macOS Intel](macos-x86_64.json), [Windows](windows.json) | Five-profile scoped native scenarios on disposable reviewed-native runners. |
| [Benchmark summary](benchmark.json) | Three repetitions of 88 independently provisioned IPv4/IPv6 cases: per-case outcomes, work, latency, logical retained-state charge, and measured peak process memory. |

The host records come from [reviewed-native run 37549075757](https://github.com/tyk-swe/pcr/actions/runs/37549075757).
Its full build/process reports are retained as workflow artifacts. Each checked-in
native record preserves executable digests, actual scenario commands, exit codes,
stdout/stderr, scope-path markers, isolation, and corpus identity. Large compiler
streams are replaced by their SHA-256 digests; `source_report_sha256` identifies
the original report. The benchmark summary similarly retains output digests and
metrics; it has its own summary schema rather than claiming to be the full report.
Windows checkout converts the corpus to CRLF. Its recorded byte digest therefore
differs from the LF checkout digest; the clean Git revision and JSON expectations
are identical. The recorded digest preserves the bytes actually consumed.

The v3 native reports intentionally remain globally `incomplete`: only
`scoped_ipv6_targets` was selected, and the other seven M3 scenarios remain
explicitly unavailable. Their scoped scenario must be `exercised` in every
profile. A path marked `unsupported_capability` represents an executed, typed
failure, not successful native transmission. macOS complete-header Layer 3
IPv6 remains unsupported. Linux capture-backed raw scans require Layer 2
capture; the pcap-free profile therefore reports that scan capability failure.
Windows pcap-free/full-native exercise pinned raw IPv6 UDP delivery.

Validate the records from the repository root:

```sh
python3 - <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from native_platform_evidence import validate
from validation_evidence import validate_native
root = Path('docs/roadmap/evidence/m04')
commit = '8e010a0b9eac118aa13384f0b854111a73d47d76'
for name in ('linux', 'macos-arm64', 'macos-x86_64', 'windows'):
    report = json.loads((root / (name + '.json')).read_text())
    validate(report, expected_commit=commit)
    assert not report['dirty']
    for profile in report['profiles']:
        scoped = next(s for s in profile['scenarios']
                      if s['name'] == 'scoped_ipv6_targets')
        assert scoped['status'] == 'exercised'
validate_native(json.loads((root / 'linux-eight.json').read_text()))
benchmark = json.loads((root / 'benchmark.json').read_text())
assert benchmark['commit'] == commit and not benchmark['dirty']
assert len(benchmark['cases']) == 264
assert all(case['status'] == 'exercised' and case['correct']
           for case in benchmark['cases'])
PY
```

These records close M4's scoped runtime gate. They do not close M3's broader
native inventory or establish a live Nmap differential comparison. Raw scanner
and traceroute benchmark cases use injected providers; the connect cases use
real loopback sockets. Fixture expectations, not Nmap agreement, are the oracle.
