param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('SourcePath', 'InnerImage')]
    [string]$SourceFolder,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$OutputPath,

    [ValidateRange(-4, 9)]
    [int]$Level = 8,

    [ValidateRange(0, [long]::MaxValue)]
    [long]$MinimumFileSize = 0,

    [string[]]$Exclude = @(),

    [ValidateSet('fast', 'compact', 'raw')]
    [string]$ReadProfile = 'fast',

    [ValidateRange(0, [long]::MaxValue)]
    [long]$RawSmall,

    [string[]]$RawInner = @(),

    [ValidateRange(0, 100)]
    [int]$MinimumSavingsPercent,

    [bool]$RawMetadata,

    [switch]$OnlyIfSmaller
)

$ErrorActionPreference = 'Stop'
if ([IO.Path]::GetExtension($OutputPath) -ine '.phuc') {
    throw 'A PHUC container must use the .phuc extension.'
}

$project = Join-Path $PSScriptRoot '..\src\PprPfsKrakenTool\PprPfsKrakenTool.csproj'
$builderArguments = @(
    'run', '--configuration', 'Release', '--project', $project, '--',
    'build-phuc', $SourceFolder, $OutputPath,
    '--level', $Level,
    '--min-size', $MinimumFileSize,
    '--only-if-smaller', $OnlyIfSmaller.IsPresent,
    '--read-profile', $ReadProfile
)
if ($Exclude.Count -gt 0) {
    $builderArguments += @('--exclude', ($Exclude -join ';'))
}
if ($PSBoundParameters.ContainsKey('RawSmall')) {
    $builderArguments += @('--raw-small', $RawSmall)
}
if ($RawInner.Count -gt 0) {
    $builderArguments += @('--raw-inner', ($RawInner -join ';'))
}
if ($PSBoundParameters.ContainsKey('MinimumSavingsPercent')) {
    $builderArguments += @('--min-savings-percent', $MinimumSavingsPercent)
}
if ($PSBoundParameters.ContainsKey('RawMetadata')) {
    $builderArguments += @('--raw-metadata', $RawMetadata)
}

dotnet @builderArguments

if ($LASTEXITCODE -ne 0) {
    throw "PHUC builder failed with exit code $LASTEXITCODE"
}
