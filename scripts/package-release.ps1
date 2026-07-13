param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Sbom
)

$ErrorActionPreference = "Stop"
$Name = "packetcraftr-$Version-$Target"
$Stage = Join-Path "dist" $Name
$Archive = Join-Path "dist" "$Name.zip"

if (-not (Test-Path $Binary -PathType Leaf)) { throw "binary not found: $Binary" }
if (-not (Test-Path $Sbom -PathType Leaf)) { throw "SBOM not found: $Sbom" }
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force (Join-Path $Stage "schemas") | Out-Null
Copy-Item $Binary (Join-Path $Stage "packetcraftr.exe")
Copy-Item README.md, LICENSE, THIRD_PARTY_NOTICES.md $Stage
Copy-Item schemas/packetcraftr.packet.v1.schema.json (Join-Path $Stage "schemas")
Copy-Item schemas/packetcraftr.output.v2.schema.json (Join-Path $Stage "schemas")
Copy-Item $Sbom (Join-Path $Stage "packetcraftr-$Target.cdx.json")

$Checksums = Get-ChildItem -File -Recurse $Stage | Sort-Object FullName | ForEach-Object {
    $Relative = [IO.Path]::GetRelativePath($Stage, $_.FullName).Replace('\', '/')
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant(), $Relative
}
Set-Content -Encoding ascii (Join-Path $Stage "SHA256SUMS") $Checksums
if (Test-Path $Archive) { Remove-Item -Force $Archive }
Compress-Archive -Path $Stage -DestinationPath $Archive
$ArchiveHash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
Set-Content -Encoding ascii "$Archive.sha256" "$ArchiveHash  $Name.zip"
