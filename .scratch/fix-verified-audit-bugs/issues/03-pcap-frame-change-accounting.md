# Count permitted frame length changes in PCAPNG mapping

Status: ready-for-agent

## Problem

The PCAPNG frame mapper reports a frame as unchanged when its captured bytes
stay the same but its original length changes, even though the written capture
contains the new length.

## Acceptance Criteria

- `frames_changed` includes changes to captured bytes or permitted frame
  length metadata.
- An unchanged-frame control remains uncounted.
- Existing timestamp, interface, link type, and direction protections remain.
- A public contract test reads the output back and compares lengths and count.

## References

- Spec: [`../spec.md`](../spec.md), finding 6.
