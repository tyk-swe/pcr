# Security policy

## Supported versions

Security fixes are provided for the latest published minor line. During 0.3 qualification, fixes that preserve the frozen public contract are released as patches. A required breaking security fix produces 0.4 and restarts qualification. Version 1.0 will not be promoted with an open P0/P1 defect.

## Reporting

Report vulnerabilities privately through GitHub Security Advisories for `tyk-swe/pcr`. Include the affected version and target, operation ID if relevant, exact error code, reproduction using non-sensitive test traffic, and whether transmission or capture cleanup occurred. Do not open a public issue containing an exploitable defect, credentials, private packet evidence, or target information.

PacketcraftR performs raw network operations. A surprising packet on an unauthorized network is not an acceptable reproduction. Use an isolated namespace, virtual machine, or lab you control.

## Security properties and limits

PacketcraftR validates bounded inputs and traffic policy before active side effects where information is available, but it cannot determine whether an operator has legal authorization. Promiscuous unfiltered capture and unlimited active rate remain deliberate expert defaults and emit warnings. Operating-system permissions, libpcap/Npcap integrity, shell history, output-file handling, and local endpoint security remain the operator's responsibility.

The program has no telemetry, cloud service, account, database, persistent history, or automatic updater. Verify release checksums, GitHub build/SBOM attestations, and the target-specific SBOM before deploying a binary.
