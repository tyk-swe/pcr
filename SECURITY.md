# Security policy

PacketcraftR handles attacker-controlled bytes and can generate live network traffic. We treat parser panics, unbounded resource use, unsafe transmission behavior, capture lifecycle races, and protocol-validation bypasses as security issues.

## Supported versions

| Version or branch | Security support |
| --- | --- |
| `main` / v0.2 prereleases | Active security fixes |
| `release/0.1` | Critical fixes only until v0.2 reaches release candidate |
| Older snapshots and unsupported forks | No upstream support |

Alpha releases are not API-stable and are not suitable as a security boundary. A supported version means that fixes are accepted; it does not mean every planned v0.2 hardening measure has landed.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's [private security advisory form](https://github.com/tyk-swe/pcr/security/advisories/new). If that form is unavailable, contact a maintainer privately through the contact method listed on the repository profile and state that the message concerns a PacketcraftR security report.

Include, when possible:

- The affected commit, version, operating system, target, and Cargo feature set.
- A minimal reproducer or packet/capture fixture that does not contain sensitive production traffic.
- The security impact and the assumptions required to trigger it.
- Whether the issue involves live transmission, privileges, native dependencies, or untrusted input.
- Logs, a backtrace, sanitizer output, or a crash artifact with secrets removed.
- Any suggested remediation and whether you plan to request coordinated disclosure credit.

We aim to acknowledge a complete report within three business days, provide an initial assessment within seven business days, and coordinate a disclosure date after a fix is available. Complex cross-platform or protocol issues can take longer; we will provide progress updates rather than silently closing the report.

## High-priority issue classes

Examples include:

- Memory-safety defects in native platform adapters or their FFI boundaries.
- Parser, dissector, PCAP/PCAPNG, expression, document, or reassembly inputs that panic, loop indefinitely, or escape configured resource limits.
- Strict validation accepting a dangerous mismatch that it claims to reject.
- Live transmission occurring during a dry plan, without required traffic-policy authorization, or without the malformed-packet opt-in.
- Layer 2 intent silently falling back to Layer 3 or resolving an off-link final host instead of its gateway.
- Capture races that miss immediate responses, leak capture tasks, or drain and discard frames.
- Spoofed packet fields being reused as trusted neighbor-resolution identity.
- Dependency vulnerabilities that are reachable in supported configurations.

Ordinary malformed-packet rejection, documented privilege failures, packet loss inherent to an overloaded capture system, and use against a network without authorization are not vulnerabilities by themselves.

## Safe research expectations

Use loopback, network namespaces, virtual machines, or an isolated lab. Set finite packet, time, queue, and memory budgets. Do not test a suspected live-transmission flaw on third-party infrastructure, public address space, or shared production networks.

Do not include credentials, private keys, personal data, or raw production captures in a report. Minimize a capture to the smallest reproducer and replace identifying addresses or payloads where doing so preserves the defect.

Good-faith research that follows these expectations is welcome. This policy does not authorize testing systems you do not own or have permission to assess.

## Release handling

Security fixes are developed privately when early disclosure would increase risk. A release advisory should identify affected versions, impact, mitigations, fixed versions, and credit when requested. Critical fixes that affect v0.1 are backported to `release/0.1` while that branch remains in its critical-fixes window.

The project does not promise embargoes requested by third parties when users are already being actively harmed, but maintainers will make a good-faith effort to coordinate a responsible release.
