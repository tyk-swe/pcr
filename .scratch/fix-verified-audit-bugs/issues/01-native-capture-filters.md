# Correct native capture filter masks and numeric ranges

Status: ready-for-human

## Problem

Native capture compiles IPv4 broadcast filters with a byte-swapped netmask on
little-endian hosts. It also rejects numeric `portrange` operands as symbolic
names even though libpcap accepts them.

## Acceptance Criteria

- `ip broadcast` uses the correct IPv4 network mask for `/16` and `/24`
  assignments in compiled BPF behavior.
- Numeric TCP and UDP source/destination port ranges are accepted.
- Symbolic host and service operands remain rejected without name resolution.
- Tests cover compiled BPF against synthetic packet bytes and filter validation.

## References

- Spec: [`../spec.md`](../spec.md), findings 1–2.

## Comments

- Implemented on [PR #209](https://github.com/tyk-swe/pcr/pull/209); automated
  code review is complete. Reviewed native runtime evidence remains required
  before merge.
