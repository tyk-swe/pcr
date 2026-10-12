# Security policy

Malformed packet/capture input, privilege failures, traffic-policy bypasses,
unsafe native code, resource exhaustion, and unintended network access may be
security-sensitive.

## Supported versions

Security fixes target `main` and the latest published release, currently
**0.5.0-beta.3**. Older releases are unsupported.

## Dependency advisories

`deny.toml` is the enforced dependency policy; unresolved advisories fail CI and
there are no advisory exceptions. Any new `ignore` entry needs a dated remediation
plan in its PR. Exceptions have no automatic expiry and must be reviewed manually.
Duplicate-version skips name the dependencies requiring them.

## Reporting a vulnerability

Email `mail@mail.tyk.sh` privately with subject
`[PacketcraftR security] <short description>` and include:

- Version/commit, feature profile, component, and command; OS/architecture for native issues.
- Impact, attacker requirements, and a minimal synthetic reproduction.
- Any disclosure deadline and a safe contact method.

Keep production captures, credentials, private addresses, and sensitive payloads
out of the initial report. Request a secure transfer method if reproduction needs
them. Use public issues for ordinary correctness bugs; report privately when the
security impact is uncertain.

## Response and disclosure

Maintainers aim to acknowledge reports within three business days, triage within
seven, and send weekly updates while work is active. Remediation depends on
severity, platform coverage, and release risk. Allow time to reproduce, patch,
test, and prepare upgrade guidance. Reporters may request credit; exploit details
are withheld until users have a reasonable opportunity to upgrade.
