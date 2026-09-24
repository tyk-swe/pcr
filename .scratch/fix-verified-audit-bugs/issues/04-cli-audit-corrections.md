# Correct DNS ports, raw timestamps, and startup command context

Status: ready-for-agent

## Problem

Three CLI behaviors lose or misreport input context: `dns-read` replaces port
53 when extra ports are configured, raw `dissect` invents the current time for
untimestamped bytes, and startup parsing can mistake a split-form global
resource preset value for the command.

## Acceptance Criteria

- `dns-read` always inspects port 53 and deduplicates additional ports.
- Raw `dissect` input retains an absent timestamp; time filters report
  `packet.timestamp_unavailable`.
- Startup errors preserve the actual command name with split and inline preset
  options in JSON and NDJSON modes.
- Process contracts cover each user-visible correction.

## References

- Spec: [`../spec.md`](../spec.md), findings 4–5 and 7.
