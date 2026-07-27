param(
    [string]$Scratch = 'J:\libprospero-publisher-boundary',
    [string]$TemplateRoot = 'J:\libprospero-differential\app-smoke',
    [string]$PublishingTools = 'C:\SCE\Prospero\Tools\Publishing Tools\bin\prospero-pub-cmd.exe',
    [string]$ContentId = 'IV0002-NPXS45193_00-PLAYGOGAMESAMPLE',
    [string]$Passcode = '00000000000000000000000000000000',
    [int]$TinyFileCount = 400,
    [int]$CompressibleFileCount = 0,
    [int]$CompressibleFileSize = 1048576,
    [int]$HybridFileCount = 0,
    [int]$HybridFileSize = 1048576,
    [string]$ProtectedNpbindRoot = '',
    [switch]$SkipEdgeFiles
)

$ErrorActionPreference = 'Stop'
if ($TinyFileCount -lt 0) {
    throw 'TinyFileCount must be non-negative.'
}
if ($CompressibleFileCount -lt 0) {
    throw 'CompressibleFileCount must be non-negative.'
}
if ($CompressibleFileSize -lt 0) {
    throw 'CompressibleFileSize must be non-negative.'
}
if ($HybridFileCount -lt 0) {
    throw 'HybridFileCount must be non-negative.'
}
if ($HybridFileSize -lt 0) {
    throw 'HybridFileSize must be non-negative.'
}
$source = Join-Path $Scratch 'source'
$manifest = Join-Path $Scratch 'manifest'
$nativePackage = Join-Path $Scratch 'native.pkg'
$managedOutput = Join-Path $Scratch 'managed'
$nativeInner = Join-Path $Scratch 'native-inner'
$managedInner = Join-Path $Scratch 'managed-inner'
$nativeOuter = Join-Path $Scratch 'native-outer'
$managedOuter = Join-Path $Scratch 'managed-outer'
$nativeInnerImage = Join-Path $Scratch 'native-inner.pfs'
$managedInnerImage = Join-Path $Scratch 'managed-inner.pfs'
$nativeTemp = Join-Path $Scratch 'native-tmp'
$project = Join-Path $PSScriptRoot '..\src\PprPfsKrakenTool\PprPfsKrakenTool.csproj'

foreach ($path in @(
    $source, $manifest, $managedOutput, $nativeInner, $managedInner,
    $nativeOuter, $managedOuter, $nativeTemp)) {
    [IO.Directory]::CreateDirectory($path) | Out-Null
}
[IO.Directory]::CreateDirectory((Join-Path $source 'data\many')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'data\compressed')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'data\hybrid')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'data\empty-included')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'data\excluded-dir')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'sce_sys')) | Out-Null

Copy-Item -LiteralPath (Join-Path $TemplateRoot 'sce_sys\param.json') `
    -Destination (Join-Path $source 'sce_sys\param.json') -Force
Copy-Item -LiteralPath (Join-Path $TemplateRoot 'sce_sys\icon0.png') `
    -Destination (Join-Path $source 'sce_sys\icon0.png') -Force
if ($ProtectedNpbindRoot) {
    foreach ($relative in @('uds\npbind.dat', 'trophy2\npbind.dat')) {
        $inputPath = Join-Path $ProtectedNpbindRoot $relative
        if (!(Test-Path -LiteralPath $inputPath -PathType Leaf)) {
            throw "Protected npbind input is missing: $inputPath"
        }
        $outputPath = Join-Path (Join-Path $source 'sce_sys') $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outputPath)) | Out-Null
        Copy-Item -LiteralPath $inputPath -Destination $outputPath -Force
    }
}

function New-PatternFile([string]$Path, [int]$Length, [uint32]$Seed) {
    $bytes = [byte[]]::new($Length)
    $state = $Seed
    for ($i = 0; $i -lt $Length; $i++) {
        $state = $state -bxor ($state -shl 13)
        $state = $state -bxor ($state -shr 17)
        $state = $state -bxor ($state -shl 5)
        $bytes[$i] = [byte]($state -band 0xff)
    }
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function New-CompressibleFile([string]$Path, [int]$Length, [uint32]$Seed) {
    $pattern = [byte[]]::new(65536)
    for ($i = 0; $i -lt $pattern.Length; $i++) {
        # A per-file periodic byte stream: highly compressible, but not byte-identical
        # between files, so that the test exercises Kraken rather than whole-file dedup.
        $pattern[$i] = [byte](($i * 13 + ($i -shr 7) + $Seed) -band 0xff)
    }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $remaining = $Length
        while ($remaining -gt 0) {
            $count = [Math]::Min($remaining, $pattern.Length)
            $stream.Write($pattern, 0, $count)
            $remaining -= $count
        }
    }
    finally {
        $stream.Dispose()
    }
}

function New-HybridFile([string]$Path, [int]$Length, [int]$Seed) {
    $compressible = [byte[]]::new(131072)
    for ($i = 0; $i -lt $compressible.Length; $i++) {
        $compressible[$i] = [byte](($i * 29 + ($i -shr 8) + $Seed) -band 0xff)
    }
    $randomChunk = [byte[]]::new(131072)
    $random = [Random]::new($Seed)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $remaining = $Length
        $chunkIndex = 0
        while ($remaining -gt 0) {
            if (($chunkIndex -band 1) -eq 0) {
                $chunk = $compressible
            }
            else {
                $random.NextBytes($randomChunk)
                $chunk = $randomChunk
            }
            $count = [Math]::Min($remaining, $chunk.Length)
            $stream.Write($chunk, 0, $count)
            $remaining -= $count
            $chunkIndex++
        }
    }
    finally {
        $stream.Dispose()
    }
}

$sizes = if ($SkipEdgeFiles) { @() } else {
    @(0, 1, 7, 8, 15, 16, 31, 32, 63, 64,
        65535, 65536, 65537, 131071, 131072, 131073,
        262143, 262144, 262145, 524288)
}
foreach ($size in $sizes) {
    New-PatternFile (Join-Path $source ('data\edge-{0:D6}.bin' -f $size)) $size `
        ([uint32](2654435769 -bxor [uint32]$size))
}
for ($i = 0; $i -lt $TinyFileCount; $i++) {
    New-PatternFile (Join-Path $source ('data\many\tiny-{0:D3}.bin' -f $i)) `
        (($i % 33) + 1) ([uint32](0x10203040 + $i))
}
for ($i = 0; $i -lt $CompressibleFileCount; $i++) {
    New-CompressibleFile `
        (Join-Path $source ('data\compressed\packed-{0:D5}.bin' -f $i)) `
        $CompressibleFileSize ([uint32](0x31415926 + $i * 977))
}
for ($i = 0; $i -lt $HybridFileCount; $i++) {
    New-HybridFile `
        (Join-Path $source ('data\hybrid\mixed-{0:D5}.bin' -f $i)) `
        $HybridFileSize (0x12340000 + $i * 101)
}

$longDirectory = Join-Path $source ('data\' + ('d' * 120))
[IO.Directory]::CreateDirectory($longDirectory) | Out-Null
New-PatternFile (Join-Path $longDirectory (('n' * 100) + '.bin')) 257 0x55667788
[IO.File]::WriteAllText(
    (Join-Path $source 'data\excluded.tmp'),
    'must not be packaged',
    [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText(
    (Join-Path $source 'data\excluded-dir\hidden.bin'),
    'must not be packaged',
    [Text.UTF8Encoding]::new($false))

$sourceXml = [Security.SecurityElement]::Escape([IO.Path]::GetFullPath($source))
$gp5 = @"
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<psproject fmt="gp5" version="1000">
  <volume>
    <volume_type>prospero_app</volume_type>
    <package passcode="$Passcode"/>
    <chunk_info chunk_count="1" scenario_count="1">
      <chunks><chunk id="0" label="Chunk #0"/></chunks>
      <scenarios default_id="0"><scenario id="0" type="playmode" initial_chunk_count="1" label="Scenario #0">0</scenario></scenarios>
    </chunk_info>
  </volume>
  <rootdir src_path="$sourceXml"
    dir_exclude="excluded-dir"
    file_exclude="*.tmp;*.gp5;*.esbak;pfs-version.dat"/>
</psproject>
"@
$gp5Path = Join-Path $manifest 'boundary.gp5'
[IO.File]::WriteAllText($gp5Path, $gp5, [Text.UTF8Encoding]::new($false))

& $PublishingTools img_create --oformat nwonly --tmp_path $nativeTemp `
    --no_progress_bar $gp5Path $nativePackage
if ($LASTEXITCODE -ne 0) { throw "Publishing Tools build failed: $LASTEXITCODE" }

dotnet run --configuration Release --project $project -- build-pkg `
    $manifest $managedOutput $ContentId app $Passcode - - - - deterministic
if ($LASTEXITCODE -ne 0) { throw "LibProsperoPkg build failed: $LASTEXITCODE" }
$managedPackage = Get-ChildItem -LiteralPath $managedOutput -Filter '*.pkg' |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -eq $managedPackage) { throw 'Managed package was not created.' }

& $PublishingTools img_info $nativePackage
if ($LASTEXITCODE -ne 0) { throw "Publishing Tools rejected its native package: $LASTEXITCODE" }
& $PublishingTools img_info $managedPackage.FullName
if ($LASTEXITCODE -ne 0) { throw "Publishing Tools rejected the managed package: $LASTEXITCODE" }

function Test-PublisherPfsReadable([string]$Package) {
    $verifyOutput = @(
        & $PublishingTools img_verify --passcode $Passcode --format_check on `
            --integrity_check on --no_progress_bar $Package 2>&1 |
            ForEach-Object { $_.ToString() }
    )
    $verifyText = $verifyOutput -join "`n"
    # The intentionally minimal fixture is not submission-complete, so img_verify may return 1.
    # What matters here is that the native reader opens PFS, traverses the directory tree and
    # reaches both package CRC ranges instead of stopping at the crypto/layout boundary.
    if ($verifyText -match 'Could not open or read package\(pfs\) file' -or
        $verifyText -notmatch 'Checking directory tree' -or
        $verifyText -notmatch 'Checking crc') {
        $verifyOutput | Write-Output
        throw "Publishing Tools could not fully traverse the package PFS: $Package"
    }
}

Test-PublisherPfsReadable $nativePackage
Test-PublisherPfsReadable $managedPackage.FullName

dotnet run --configuration Release --project $project -- check-pkg-entry-digests `
    $managedPackage.FullName $Passcode
if ($LASTEXITCODE -ne 0) { throw "Managed CNT entry-digest validation failed: $LASTEXITCODE" }

dotnet run --configuration Release --project $project -- extract-pkg-inner `
    $nativePackage $nativeInner $Passcode
if ($LASTEXITCODE -ne 0) { throw "Native package extraction failed: $LASTEXITCODE" }
dotnet run --configuration Release --project $project -- extract-pkg-inner `
    $managedPackage.FullName $managedInner $Passcode
if ($LASTEXITCODE -ne 0) { throw "Managed package extraction failed: $LASTEXITCODE" }

dotnet run --configuration Release --project $project -- extract-pkg-outer `
    $nativePackage $nativeOuter $Passcode | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Native outer-PFS extraction failed: $LASTEXITCODE" }
dotnet run --configuration Release --project $project -- extract-pkg-outer `
    $managedPackage.FullName $managedOuter $Passcode | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Managed outer-PFS extraction failed: $LASTEXITCODE" }

foreach ($layout in @(
    (Join-Path $nativeOuter 'uroot\naps_pkg_layout.dat'),
    (Join-Path $managedOuter 'uroot\naps_pkg_layout.dat'))) {
    $summary = @(
        dotnet run --configuration Release --project $project -- summary-naps $layout
    )
    if ($LASTEXITCODE -ne 0) { throw "NAPS summary failed: $layout" }
    if ($summary -notcontains 'outer-cmac-nonzero=0') {
        $summary | Write-Output
        throw "The default Publishing Tools profile emitted keyed NAPS outer-block tags: $layout"
    }
}

function Get-TreeHashes([string]$Root) {
    $result = @{}
    $rootPrefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse) {
        $relative = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        $result[$relative] = '{0}:{1}' -f $file.Length, (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash
    }
    return $result
}

$nativeHashes = Get-TreeHashes $nativeInner
$managedHashes = Get-TreeHashes $managedInner
$allPaths = @($nativeHashes.Keys + $managedHashes.Keys) | Sort-Object -Unique
$differences = foreach ($path in $allPaths) {
    if ($nativeHashes[$path] -ne $managedHashes[$path]) {
        [pscustomobject]@{
            Path = $path
            Native = $nativeHashes[$path]
            Managed = $managedHashes[$path]
        }
    }
}
if ($differences.Count -ne 0) {
    $differences | Format-Table -AutoSize
    throw "Inner trees differ in $($differences.Count) path(s)."
}
if ($nativeHashes.ContainsKey('data/excluded.tmp') -or
    $nativeHashes.ContainsKey('data/excluded-dir/hidden.bin')) {
    throw 'GP5 exclusion masks were not applied.'
}

dotnet run --configuration Release --project $project -- dump-pkg-inner `
    $nativePackage $nativeInnerImage $Passcode | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Native inner-image dump failed: $LASTEXITCODE" }
dotnet run --configuration Release --project $project -- dump-pkg-inner `
    $managedPackage.FullName $managedInnerImage $Passcode | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Managed inner-image dump failed: $LASTEXITCODE" }

$nativeDirectories = @(
    dotnet run --configuration Release --project $project -- list-dirs $nativeInnerImage |
        Sort-Object -Unique
)
if ($LASTEXITCODE -ne 0) { throw "Native directory listing failed: $LASTEXITCODE" }
$managedDirectories = @(
    dotnet run --configuration Release --project $project -- list-dirs $managedInnerImage |
        Sort-Object -Unique
)
if ($LASTEXITCODE -ne 0) { throw "Managed directory listing failed: $LASTEXITCODE" }
$directoryDifferences = Compare-Object $nativeDirectories $managedDirectories
if ($null -ne $directoryDifferences) {
    $directoryDifferences | Format-Table -AutoSize
    throw 'Extracted inner directory trees differ.'
}
if ($nativeDirectories -notcontains 'data/empty-included') {
    throw 'The included empty directory was not preserved.'
}

Write-Output (
    ("Publisher differential test passed: {0} identical inner files, {1} identical directories; " +
    "tiny={2}; compressed={3} files x {4} bytes; hybrid={5} files x {6} bytes; " +
    "protected-npbind={7}; img-verify-pfs=passed; naps-cmac=disabled; " +
    "native={8}; managed={9}") -f
    $nativeHashes.Count, $nativeDirectories.Count, $TinyFileCount,
    $CompressibleFileCount, $CompressibleFileSize, $HybridFileCount, $HybridFileSize,
    [bool]$ProtectedNpbindRoot, $nativePackage, $managedPackage.FullName)
