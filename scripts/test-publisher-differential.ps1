param(
    [string]$Scratch = 'J:\libprospero-publisher-boundary',
    [string]$TemplateRoot = 'J:\libprospero-differential\app-smoke',
    [string]$PublishingTools = 'C:\SCE\Prospero\Tools\Publishing Tools\bin\prospero-pub-cmd.exe',
    [string]$ContentId = 'IV0002-NPXS45193_00-PLAYGOGAMESAMPLE',
    [string]$Passcode = '00000000000000000000000000000000',
    [int]$TinyFileCount = 400
)

$ErrorActionPreference = 'Stop'
if ($TinyFileCount -lt 0) {
    throw 'TinyFileCount must be non-negative.'
}
$source = Join-Path $Scratch 'source'
$manifest = Join-Path $Scratch 'manifest'
$nativePackage = Join-Path $Scratch 'native.pkg'
$managedOutput = Join-Path $Scratch 'managed'
$nativeInner = Join-Path $Scratch 'native-inner'
$managedInner = Join-Path $Scratch 'managed-inner'
$nativeInnerImage = Join-Path $Scratch 'native-inner.pfs'
$managedInnerImage = Join-Path $Scratch 'managed-inner.pfs'
$nativeTemp = Join-Path $Scratch 'native-tmp'
$project = Join-Path $PSScriptRoot '..\src\PprPfsKrakenTool\PprPfsKrakenTool.csproj'

foreach ($path in @($source, $manifest, $managedOutput, $nativeInner, $managedInner, $nativeTemp)) {
    [IO.Directory]::CreateDirectory($path) | Out-Null
}
[IO.Directory]::CreateDirectory((Join-Path $source 'data\many')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'data\empty-included')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'data\excluded-dir')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $source 'sce_sys')) | Out-Null

Copy-Item -LiteralPath (Join-Path $TemplateRoot 'sce_sys\param.json') `
    -Destination (Join-Path $source 'sce_sys\param.json') -Force
Copy-Item -LiteralPath (Join-Path $TemplateRoot 'sce_sys\icon0.png') `
    -Destination (Join-Path $source 'sce_sys\icon0.png') -Force

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

$sizes = @(0, 1, 7, 8, 15, 16, 31, 32, 63, 64,
    65535, 65536, 65537, 131071, 131072, 131073,
    262143, 262144, 262145, 524288)
foreach ($size in $sizes) {
    New-PatternFile (Join-Path $source ('data\edge-{0:D6}.bin' -f $size)) $size `
        ([uint32](2654435769 -bxor [uint32]$size))
}
for ($i = 0; $i -lt $TinyFileCount; $i++) {
    New-PatternFile (Join-Path $source ('data\many\tiny-{0:D3}.bin' -f $i)) `
        (($i % 33) + 1) ([uint32](0x10203040 + $i))
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

dotnet run --configuration Release --project $project -- extract-pkg-inner `
    $nativePackage $nativeInner $Passcode
if ($LASTEXITCODE -ne 0) { throw "Native package extraction failed: $LASTEXITCODE" }
dotnet run --configuration Release --project $project -- extract-pkg-inner `
    $managedPackage.FullName $managedInner $Passcode
if ($LASTEXITCODE -ne 0) { throw "Managed package extraction failed: $LASTEXITCODE" }

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
    "Publisher differential test passed: {0} identical inner files, {1} identical directories; native={2}; managed={3}" -f
    $nativeHashes.Count, $nativeDirectories.Count, $nativePackage, $managedPackage.FullName)
