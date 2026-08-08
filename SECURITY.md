# Security policy

Treat malformed packet or capture input, privilege-boundary failures,
traffic-policy bypasses, unsafe native code, resource exhaustion, and
unintended network access as potentially security-sensitive.

## Supported versions

Security fixes target `main` and, when practical, the latest `0.4.x` release.
Older and beta releases are unsupported.

## Reporting a vulnerability

Do not open a public issue or pull request. Email `mail@mail.tyk.sh` with the
subject `[PacketcraftR security] <short description>` and include:

- the affected version or commit, feature profile, component, and command;
- operating system and architecture for native-networking issues;
- the impact and required attacker capabilities;
- minimal reproduction steps or a small synthetic proof of concept;
- any existing public disclosure or deadline; and
- a safe contact method.

Do not attach production captures, credentials, private addresses, or sensitive
payloads to the initial report. Describe the material and request a secure
transfer method if it is required for reproduction.

Maintainers aim to acknowledge reports within three business days, provide
initial triage within seven business days, and send weekly updates while work
is active. Remediation timing depends on severity, platform coverage, and
release risk.

## Coordinated disclosure

Allow reasonable time to reproduce, patch, test supported profiles and
platforms, and prepare release guidance. The project will credit reporters who
request credit and will not publish exploit details before users have a
reasonable opportunity to upgrade.

Report ordinary correctness bugs publicly. When the security impact is
uncertain, report privately first.
