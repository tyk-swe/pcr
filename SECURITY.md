# Security policy

PacketcraftR constructs, parses, captures, and transmits network traffic. Treat
reports involving malformed packet or capture input, privilege boundaries,
traffic-policy bypass, unsafe native code, resource exhaustion, or unintended
network access as potentially security-sensitive.

## Supported versions

PacketcraftR is pre-1.0. Security fixes target the default branch and the most
recent beta release when a backport is practical.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Latest `0.4.0-beta.*` release | Yes |
| Older beta and pre-beta releases | No |

## Reporting a vulnerability

Do not open a public GitHub issue or pull request with vulnerability details.
Email `mail@mail.tyk.sh` with the subject
`[PacketcraftR security] <short description>`.

Include:

- the affected version or commit and feature profile;
- operating system and architecture when native networking is involved;
- the affected component or command;
- the security impact and required attacker capabilities;
- minimal reproduction steps or a small synthetic proof of concept;
- whether the issue is already public or has a disclosure deadline;
- a safe way to contact you.

Do not attach production captures, credentials, private addresses, or sensitive
payloads to the initial report. Describe the material and ask for a secure
transfer method if it is necessary for reproduction.

Maintainers aim to acknowledge a report within three business days, provide an
initial triage within seven business days, and send updates at least weekly
while remediation is active. Actual remediation and disclosure timing depend
on severity, platform coverage, and release risk.

## Coordinated disclosure

Please allow maintainers reasonable time to reproduce, patch, test supported
feature profiles and platforms, and prepare release guidance before public
disclosure. The project will credit reporters who request credit and will avoid
publishing exploit details before users have a reasonable opportunity to
upgrade.

Ordinary correctness bugs without a security impact belong in the public issue
tracker. When uncertain, report privately first.
