# Tooling and consumer regressions

Run from the repository root with Python 3.10 or newer:

```sh
python3 -m unittest discover -s scripts/tests -v
python3 -O -m unittest discover -s scripts/tests -v
python3 -m compileall -q scripts examples/consumers
```

The suite uses only the standard library. It does not install packages, invoke
Cargo, contact GitHub, run Nmap, create network namespaces, send packets, or need
native privileges. External-tool and native-report behavior is mocked. Process
measurement tests launch local Python children to exercise exit codes, timeouts,
UTF-8 decoding, output limits, and POSIX descendant cleanup. The latter is skipped
on non-POSIX systems. Temporary files and local children are cleaned up.

## Suite ownership

| Module | Coverage |
| --- | --- |
| `test_script_support.py` | Bounded JSON, file validation, aliases, and atomic report publication. |
| `test_native_validation.py` | Native exchange evidence and namespace lifecycle validation. |
| `test_benchmark_validation.py` | Scanner corpus, scheduling evidence, process measurement, and report input protection. |
| `test_build_manifest.py` | Build identity, provenance, and manifest validation. |
| `test_forwarding_consumer.py` | Forwarding consumer contracts and archive consumer checks. |
| `test_release_evidence.py` | Release evidence and publication gates. |

Place new regressions in the suite that owns the behavior. Keep common loading
helpers in `support.py`; test modules should not import other test modules.
Script entrypoints and shared fixture locations are indexed in
[Codebase structure](../../docs/codebase-structure.md#tooling-index).

`support.py` loads standalone scripts without executing their CLI entrypoints.
Tests mutate retained positive fixtures and check both valid and contradictory
reports. Keep positive controls for omitted evidence, additive metadata,
pre-epoch timestamps, and incomplete measurements so validation does not become
an accidental closed-world schema. A bug fix and its regression belong to the
same change, not separate feature claims.

Optimized Python is a separate required run: safety and evidence checks must not
rely on `assert`, which disappears under `-O`. `unittest` assertion methods remain
active. CI runs this suite independently of the pinned Rust installation.

The suite does not establish Rust compilation, cross-platform native runtime
coverage, privileged namespace behavior, real decoder-oracle agreement, or
benchmark acceptance. Those checks remain in the existing validation lanes.
