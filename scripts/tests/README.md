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
