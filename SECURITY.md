# Security policy

Treat malformed packet or capture input, privilege-boundary failures,
traffic-policy bypasses, unsafe native code, resource exhaustion, and
unintended network access as potentially security-sensitive.

## Supported versions

Security fixes target `main` and the latest published release, currently the
`0.5.0-beta.x` line. Older releases, stable or beta, are unsupported.

## Dependency advisories

An unresolved advisory fails `cargo deny check` in CI. `deny.toml` is the
enforced policy and carries no exceptions today. Do not add an `ignore` entry
without a dated remediation plan in the pull request that adds it; the entry
has no automatic expiry, so the date has to be policed by hand.

## Reporting a vulnerability

Do not open a public issue or pull request. Email `mail@mail.tyk.sh` with the
subject `[PacketcraftR security] <short description>` and include:

- the affected version or commit, feature profile, component, and command, plus
  the operating system and architecture for native-networking issues;
- the impact and required attacker capabilities;
- minimal reproduction steps or a small synthetic proof of concept;
- any existing public disclosure or deadline, and a safe contact method.

Do not attach production captures, credentials, private addresses, or sensitive
payloads to the initial report. Describe the material and request a secure
transfer method if it is required for reproduction.

Maintainers aim to acknowledge reports within three business days, provide
initial triage within seven business days, and send weekly updates while work
is active. Remediation timing depends on severity, platform coverage, and
release risk.

## Response and disclosure

Allow time to reproduce, patch, test supported profiles and platforms, and
prepare release guidance. The project credits reporters who request it and
does not publish exploit details before users have a reasonable opportunity to
upgrade.

Report ordinary correctness bugs publicly. When the security impact is
uncertain, report privately first.
