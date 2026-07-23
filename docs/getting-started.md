# Getting Started

## Prerequisites

- **.NET 9 SDK** or newer. Verify with:

  ```bash
  dotnet --version
  ```

- A C# 13 capable toolchain (included with the .NET 9 SDK).

## Project layout

```
LibProsperoPKG/
├── README.md
├── NOTICE
├── docs/
└── src/
    └── LibProsperoPkg/
        ├── LibProsperoPkg.csproj
        ├── ProsperoPackageBuilder.cs   high-level entry point
        ├── PKG/                         container build/read/write, signing, DDS, FIH
        ├── PFS/                         inner PFS layout, AES-XTS, PFSC compression
        ├── GP5/                         GP5 project model
        ├── Keys/                        publishing key access
        ├── PlayGo/                      PlayGo / "about" helper file generators
        └── Util/                        crypto, keys, and shared helpers
```

## Building the library

```bash
cd LibProsperoPKG/src/LibProsperoPkg
dotnet build -c Release
```

The output is `bin/Release/net9.0/LibProsperoPkg.dll`.

## Building a PPR-PFS image with per-file Kraken compression

The PowerShell wrapper creates a plaintext PFS version-2 image and stores eligible regular files
as PFSC version-2 Kraken containers. By default `sce_sys/**` is excluded, matching the observed
publisher image policy. Excluded paths remain in the filesystem as raw files; they are not omitted.
The wrapper also uses the publisher layout found in the reference image: block 1 is the inode bitmap,
the inode table starts at block 2, and inode 0 is the user root (there is no `uroot` or
`flat_path_table` wrapper).

```powershell
.\scripts\build-kraken-pfs.ps1 C:\input\app C:\output\app-kraken.pfs
```

Add exclusions as relative-path globs. `*` stays within one directory component and `**` crosses
directories:

```powershell
.\scripts\build-kraken-pfs.ps1 C:\input\app C:\output\app-kraken.pfs `
    -Exclude 'sce_sys/**','cache/**','movies/intro.mp4'
```

Use `-OnlyIfSmaller` to leave a file raw when the complete PFSC container is not smaller than its
source. The default deliberately keeps PFSC metadata overhead for small files because that matches
publisher output.

Unlike the generic package-layout helper, this standalone builder does not silently remove outer-PKG
metadata names or `.dds` files. Every source file is included; compression globs decide only whether
its inode contains a PFSC v2 stream or raw bytes.

### Building a ShadowMount PHUC hybrid image

Use the dedicated profile to put a normal game PFS inside a publisher-layout outer `pfs` container.
ShadowMount gives only the outer `pfs_image.dat` vnode a private vector containing the required
`ppr_pfs` handlers:

```powershell
.\scripts\build-phuc.ps1 C:\input\app C:\output\app.phuc

# Or reuse a ready inner PFS image:
.\scripts\build-phuc.ps1 C:\input\pfs_image.dat C:\output\app.phuc

# Prefer minimum image size, or remove Kraken decode work entirely:
.\scripts\build-phuc.ps1 C:\input\app C:\output\compact.phuc -ReadProfile compact
.\scripts\build-phuc.ps1 C:\input\app C:\output\raw.phuc -ReadProfile raw
```

For a folder, the builder first creates an uncompressed inner PFS. If the first argument is an
existing file, it validates that ready PS5 PFS v2 image and uses it directly (a hard link is used when
possible, otherwise it is copied into staging). The outer layer follows the reference PHUC layout: block 1
is the inode bitmap, the inode table begins at block 2, and inode 0 is the root (no `uroot` or
`flat_path_table`). That root contains exactly one `pfs_image.dat`,
compressed as a PFSC version-2 Kraken stream with 128 KiB blocks. Validation also checks the
direct and indirect block maps, logical inode sizes, offset-table boundaries, encoder identifier,
fixed PFSC v2 header fields, and the 256 KiB Kraken pairing used by the hardware path: the first
128 KiB chunk is seeded and the second is a seedless continuation (`C000 -> 4000 -> C000`).
Existing containers can be checked with the tool's `verify-phuc <image.phuc>` command.
No routing marker is required; ShadowMount opens `pfs_image.dat` as native PFS before installing
its private PFS/PPR vector.

`fast` is the default runtime-oriented profile. When the input is a folder, the inner builder places
`eboot.bin`, `sce_module/**`, `sce_sys/**`, and small files first so their extents are adjacent. The
outer PFSC writer then stores inner metadata and those latency-sensitive extents as raw 256 KiB
groups. Other groups use Kraken only if the encoded pair saves at least 12%, avoiding decoder and
I/O-controller setup for negligible gains. The boundaries remain ordinary PFSC v2 stored entries, so
raw and Kraken groups can coexist in one `pfs_image.dat`.

`compact` restores the former size-oriented policy. `raw` keeps the compressed inode and PFSC v2
header/table required by private `ppr_pfs` routing, but stores all groups, minimizing decode latency at
the cost of image size and device I/O. Tune the default with `-RawSmall <bytes>`,
`-RawInner 'pattern1','pattern2'`, `-RawMetadata $false`, or `-MinimumSavingsPercent <0..100>`.
For a ready inner image the builder can still identify its metadata and file extents, but cannot
reorder files already laid out on disk.

## Referencing the library

From another project, reference either the compiled assembly or the
project directly:

```xml
<ItemGroup>
  <ProjectReference Include="..\LibProsperoPKG\src\LibProsperoPkg\LibProsperoPkg.csproj" />
</ItemGroup>
```

## Preparing an application folder

The builder consumes a folder that already contains the standard PS5 layout:

- `sce_sys/` — system metadata directory (must be present). When `param.json` is missing and
  `GenerateParamJsonIfMissing` is left `true`, a minimal one is generated from the build options.
- The application executable (`eboot.bin`) and any data files.

## Building your first package

```csharp
using LibProsperoPkg;

var options = new ProsperoBuildOptions
{
    Mode         = ProsperoPackageMode.Application,
    OutputFormat = ProsperoOutputFormat.DebugImage,
    SourceFolder = "/path/to/prepared/app",
    OutputFolder = "/path/to/output",
    ContentId    = "UP9000-PPSA00000_00-PROSPERO00000000",
    TitleId      = "PPSA00000",
    Title        = "My PS5 Application",
    Version      = "01.00",
    // Enable for byte-identical debug/regression builds:
    // DeterministicBuild = true,
};

var result = ProsperoPackageBuilder.Build(options, Console.WriteLine);
Console.WriteLine(result.OutputPath);
```

## Notes on content identifiers

- **Content ID** is 36 characters: `XXYYYY-XXXXYYYYY_00-ZZZZZZZZZZZZZZZZ`.
  Validate with `ProsperoPackageBuilder.IsValidContentId` or compose one with
  `ProsperoPackageBuilder.ComposeContentId(publisher, titleId, label)`.
- **Title ID** is 9 characters (for example `PPSA00000`). Validate with
  `ProsperoPackageBuilder.IsValidTitleId`.
- **Passcode** is exactly 32 characters and defaults to all zeroes.
