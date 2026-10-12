# M9: TLS services and identification corpus

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Complete | [M8](m08-service-identification.md) | Broader service coverage with qualified metadata |

## Outcome and decisions

- Explicit TLS wraps numeric TCP identification without raw privileges in every
  profile. Declared SNI performs no lookup; TLS 1.2/1.3 use rustls/ring. No trust/
  hostname authentication, STARTTLS, UDP TLS, or cleartext fallback is implied.
  Handshake signatures are verified. Separate finite encrypted-byte, I/O-step,
  time, and certificate budgets include failed work.
- Presented ordered DER certificates and negotiated parameters remain
  unauthenticated observations. Application and encrypted counters stay separate;
  accepted plaintext need not reach a peer after failed flush.
- Original corpus 1.1.0 adds read-only SMTP/FTP greetings, supported observed
  hostnames, and reviewed static wildcard-version CPEs. No device types are bundled.
  Every metadata value has an observed-field or match-rule source.
- Output/v13 introduced these fields and `tls_failed`; v12 stays frozen. See
  [service controls](../service-identification.md) and
  [v13](../consumer-compatibility.md#output-family-v13).

## Completion evidence

Clean revision `5e5a41470c0c63404ca3e581067fded136eda1ce` passed closing
[CI run 38127739273](https://github.com/tyk-swe/pcr/actions/runs/38127739273)
on 2026-10-11: 4,000 case-runs, 20 profile executions across Linux x86_64,
macOS ARM/Intel, and Windows. Both IP families and JSON/NDJSON executed;
no failed, missing, or unavailable service cases. Linux also exercised all eight
isolated scenarios. [Evidence](evidence/m09/README.md) retains lossless reports,
job conclusions, integrity manifests, independent quality counts, and earlier
incomplete runs. Broader privileged macOS/Windows labs remain M3 work.

The held-out manifest was fixed at `97267ae4` before rule authorship and was
not tuned after evaluation. Its 21 independent instances include 18 eligible:
12 matched (66.67%), four unknown (22.22%), two ambiguous (11.11%). Malformed
and TLS failure fixtures stay outside that denominator with actual outcomes.
Repeated families/formats/profiles are not more independent services.

Confidence remains ordinal `claim`/`protocol`. Presented-token fidelity does not
prove implementation identity; a misleading fixture deliberately remains a claim.
No calibrated probability, production prevalence, Internet coverage, OS result,
or performance baseline is established. M9 has no remaining applicable gate;
M2/M3/M5/M7/M11 broader gates remain open.
