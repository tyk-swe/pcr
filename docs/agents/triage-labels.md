# Triage labels

Map canonical triage roles to the values used in the `Status:` line of
local issues and specs.

| Canonical role | Local status | Meaning |
| --- | --- | --- |
| `needs-triage` | `needs-triage` | Maintainer needs to evaluate the issue |
| `needs-info` | `needs-info` | Waiting on the reporter for more information |
| `ready-for-agent` | `ready-for-agent` | Fully specified and ready for an agent |
| `ready-for-human` | `ready-for-human` | Requires human implementation |
| `wontfix` | `wontfix` | Will not be actioned |

When a skill applies a triage role, set the corresponding local status.
Edit the Local status column to change the vocabulary.

Wayfinding ticket lifecycle states are defined in
[issue-tracker.md](issue-tracker.md#wayfinding-operations).
