param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$SourceFolder,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$OutputPath,

    [ValidateSet('ppr', 'classic')]
    [string]$Layout = 'ppr',

    [Alias('Method')]
    [ValidateSet('none', 'zlib', 'kraken')]
    [string]$Compression = 'kraken',

    [ValidateRange(-4, 9)]
    [int]$Level = 8,

    [ValidateRange(0, [long]::MaxValue)]
    [long]$MinimumFileSize = 0,

    [string[]]$Exclude = @('sce_sys/**'),

    [switch]$OnlyIfSmaller,

    [switch]$Classic
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot '..\src\PprPfsKrakenTool\PprPfsKrakenTool.csproj'
$selectedLayout = if ($Classic.IsPresent) { 'classic' } else { $Layout }

if ($Compression -eq 'zlib' -and $Level -lt 0) {
    throw 'Zlib level must be in the range 0..9.'
}

dotnet run --configuration Release --project $project -- `
    build $SourceFolder $OutputPath `
    --layout $selectedLayout `
    --compression $Compression `
    --level $Level `
    --min-size $MinimumFileSize `
    --exclude ($Exclude -join ';') `
    --only-if-smaller $OnlyIfSmaller.IsPresent

if ($LASTEXITCODE -ne 0) {
    throw "PFS builder failed with exit code $LASTEXITCODE"
}
