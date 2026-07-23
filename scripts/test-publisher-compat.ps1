param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Package,
    [string]$Passcode = '00000000000000000000000000000000',
    [string]$PublishingTools = 'C:\SCE\Prospero\Tools\Publishing Tools\bin\prospero-pub-cmd.exe'
)

$ErrorActionPreference = 'Stop'
$packagePath = [IO.Path]::GetFullPath($Package)
if (-not [IO.File]::Exists($packagePath)) { throw "Package not found: $packagePath" }
if (-not [IO.File]::Exists($PublishingTools)) { throw "Publishing Tools not found: $PublishingTools" }

$project = Join-Path $PSScriptRoot '..\src\PprPfsKrakenTool\PprPfsKrakenTool.csproj'
$work = Join-Path ([IO.Path]::GetTempPath()) ('libprospero-publisher-check-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null

dotnet run --configuration Release --project $project -- inspect-pkg $packagePath
if ($LASTEXITCODE -ne 0) { throw "LibProsperoPkg inspect failed: $LASTEXITCODE" }

$outer = Join-Path $work 'outer'
dotnet run --configuration Release --project $project -- extract-pkg-outer $packagePath $outer $Passcode
if ($LASTEXITCODE -ne 0) { throw "LibProsperoPkg outer extraction failed: $LASTEXITCODE" }

$layout = Join-Path $outer 'uroot\naps_pkg_layout.dat'
if ([IO.File]::Exists($layout)) {
    dotnet run --configuration Release --project $project -- roundtrip-naps $layout (Join-Path $work 'naps.roundtrip.dat')
    if ($LASTEXITCODE -ne 0) { throw "NAPS round-trip failed: $LASTEXITCODE" }
}

& $PublishingTools img_info $packagePath
if ($LASTEXITCODE -ne 0) { throw "Publishing Tools format inspection failed: $LASTEXITCODE" }

& $PublishingTools img_verify --passcode $Passcode --format_check on --integrity_check on --no_progress_bar $packagePath
if ($LASTEXITCODE -ne 0) { throw "Publishing Tools verification failed: $LASTEXITCODE" }

Write-Output "Publisher compatibility passed. Artifacts: $work"
