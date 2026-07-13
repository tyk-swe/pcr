# Third-party notices

PacketcraftR is distributed under AGPL-3.0-only. Its Rust dependency graph includes software under compatible open-source licenses. The authoritative target-specific dependency inventory and license identifiers are in the CycloneDX SBOM shipped with each release artifact and in `Cargo.lock`.

Native capture uses the operating system's libpcap or a separately installed Npcap runtime. Npcap is not distributed in PacketcraftR archives and has its own license terms. Obtain Npcap 1.88 only from the official Npcap project.

Before redistribution, run `cargo deny check` and inspect the release SBOM for the exact target. This notice does not replace any dependency's license text or attribution requirements.
