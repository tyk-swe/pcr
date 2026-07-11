# Installation and GitHub Release artifacts

PacketcraftR is distributed from the
[source repository](https://github.com/tyk-swe/pcr) and its
[GitHub Releases](https://github.com/tyk-swe/pcr/releases) only. The workspace
packages set `publish = false`; there is no public Rust package-registry or
hosted API-documentation release channel.

The version in Cargo metadata identifies the matching `vVERSION` GitHub
Release. Its Release page, tag, notes, attached checksum, and workspace archive
are the authority. A locally assembled archive is not an upstream release, even
when its bytes happen to match.

## Install an exact source checkout

Install Rust 1.96, clone the repository, and select a reviewed commit. The
portable install excludes every native route/capture/transmission adapter:

```console
git clone https://github.com/tyk-swe/pcr.git
cd pcr
git checkout COMMIT_OR_RELEASE_TAG
cargo install --locked --path . --no-default-features
packetcraftr --version
```

`cargo install --path` places the binary in Cargo's configured binary directory
(normally `$HOME/.cargo/bin`, or `%USERPROFILE%\.cargo\bin` on Windows). Use
`--root PATH` to select another prefix. The install is a local build from the
checked-out workspace; it does not publish or download a PacketcraftR package
from a registry.

For passive routes or live I/O, replace `--no-default-features` with the minimum
reviewed feature set from the [platform matrix](platform-support.md). Enabling a
feature does not install libpcap/Npcap, grant device access, or grant raw-socket
privilege.

## Release asset contract

Each PacketcraftR Release provides:

- `packetcraftr-workspace-VERSION.tar.gz`, the complete buildable workspace;
- `SHA256SUMS`, containing the SHA-256 digest of every attached distributable;
  and
- Release notes naming the source commit, Rust MSRV, qualified targets/features,
  remaining prerelease gates or stable limitations, and any additional platform
  binary archives.

The extracted workspace contains `RELEASE-METADATA.toml`. Its version and tag
must match the selected asset and its `commit` must match the commit resolved by
the GitHub tag. The value is substituted by `git archive`; the tracked
`$Format` placeholder is not valid release evidence by itself.

Do not guess a binary-archive name or edit a URL from another version. If the
Release has a platform binary, select the exact target named in its notes and
verify it with the same checksum file. Otherwise install from the workspace
archive.

Maintainers assemble and verify those two deterministic inputs from a clean
commit with:

```console
bash scripts/verify-release-archive.sh --output-dir dist
(cd dist && sha256sum --check SHA256SUMS)
```

The verifier assembles the workspace twice and rejects any byte difference
before it retains an output. This is preparation only: it does not create a tag,
upload an asset, or publish a package.

On Linux or macOS, after choosing a published version:

```console
version=VERSION
base="https://github.com/tyk-swe/pcr/releases/download/v${version}"
curl --fail --location --remote-name "${base}/packetcraftr-workspace-${version}.tar.gz"
curl --fail --location --remote-name "${base}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar --extract --gzip --file "packetcraftr-workspace-${version}.tar.gz"
cd "packetcraftr-workspace-${version}"
cargo install --locked --path . --no-default-features
```

macOS also provides `shasum -a 256` when `sha256sum` is unavailable; compare its
lowercase digest exactly with the matching `SHA256SUMS` entry before extraction.

On Windows PowerShell:

```powershell
$Version = 'VERSION'
$Base = "https://github.com/tyk-swe/pcr/releases/download/v$Version"
$Archive = "packetcraftr-workspace-$Version.tar.gz"
Invoke-WebRequest "$Base/$Archive" -OutFile $Archive
Invoke-WebRequest "$Base/SHA256SUMS" -OutFile SHA256SUMS
$Expected = ((Select-String -Path SHA256SUMS -Pattern "  $([regex]::Escape($Archive))$").Line -split '\s+')[0].ToLower()
$Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLower()
if ($Actual -ne $Expected) { throw 'PacketcraftR archive checksum mismatch' }
tar -xzf $Archive
Set-Location "packetcraftr-workspace-$Version"
cargo install --locked --path . --no-default-features
```

Stop if the checksum file is absent, the selected asset has no entry, the
digest differs, or the Release tag/notes do not identify the expected source.
Never replace a failed verification with a checksum copied from an unrelated
build or discussion.

The same procedure is exercised after publication by the manually dispatched
`Release artifact / ...` CI matrix. Those Linux x86_64, macOS arm64/x86_64,
and Windows x86_64 MSVC jobs start without a repository checkout, download the
two assets from the GitHub Release, resolve the tag through the GitHub API,
validate embedded metadata, install the portable CLI, compare the frozen
CLI/schema contract, and execute all 14 documented command workflows.

## API and contract reference

The workspace archive carries the versioned beta API evidence:

- [`docs/public-api.md`](public-api.md), the human-facing v0.2 Rust façade
  contract;
- [`api/packetcraftr-v0.2-beta.txt`](../api/packetcraftr-v0.2-beta.txt), the
  rustdoc-derived item/signature baseline and embedded SHA-256 digest;
- [`docs/cli-contract.md`](cli-contract.md) plus the CLI help/schema goldens; and
- the packet/output schemas under [`schemas/`](../schemas/README.md).

From an extracted archive, generate the browsable reference with the pinned
toolchain and verify that its surface matches the shipped baseline:

```console
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
python3 scripts/check-public-api.py
```

Open `target/doc/packetcraftr/index.html` locally. The comparison is the
auditable link between generated documentation and the frozen façade; a Release
must not substitute documentation generated from another commit.
