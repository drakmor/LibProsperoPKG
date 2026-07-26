# API Overview

This document summarizes the public surface of LibProsperoPkg, grouped by namespace. Every
public type and member carries XML documentation, so IntelliSense and the generated
documentation file are the authoritative reference; this page is the orientation map.

---

## `LibProsperoPkg` — high-level builder

### `ProsperoPackageBuilder` (static)

The primary entry point.

| Member | Purpose |
|---|---|
| `Build(ProsperoBuildOptions, Action<string>?)` | Build a package from a prepared folder. Returns `ProsperoBuildResult`. |
| `BuildInnerPfsLayout(...)` | Lay a folder out into a plaintext inner-PFS image. |
| `BuildInnerImage(...)` | Run the full inner-image pipeline (plaintext / encrypted / zlib-compressed / Kraken-compressed). |
| `EncryptPfsImage(...)` | AES-XTS-encrypt a prepared plaintext inner-PFS image in place. |
| `IsValidContentId` / `IsValidTitleId` | Validate identifiers. |
| `ComposeContentId(publisher, titleId, label)` | Build a well-formed 36-char content id. |
| `VolumeTypeForMode` / `IsDlcMode` | Map a `ProsperoPackageMode` to volume metadata. |
| `KeysAvailable` | Reports whether publishing key material is available. |

### Supporting types

- **`ProsperoBuildOptions`** — the build description: `Mode`, `OutputFormat`, `SourceFolder`,
  `OutputFolder`, `ContentId`, optional `PrimaryId`, `Passcode`, `Title`, `TitleId`, `Version`,
  `GenerateParamJsonIfMissing`, `CompressInnerImage`, `InnerCompression`, `UsePublisherPprNaps`
  (default true), and optional 16-byte `NapsOuterBlockCmacKey` for profiles that explicitly
  enable keyed outer-block CMAC. Publishing Tools 2.79 debug/AC leaves it disabled by default.
  The builder derives the `sc2 estimate` `pfs-image-key` from `PrimaryId` (falling back to
  `ContentId`), `Passcode`, and the effective 16-byte PFS image seed. `NapsPfsImageSeed`
  fixes that seed; `NapsPfsImageKey` is an optional expected 32-byte known-answer vector.
  Raw `pfs_image_seed.bin` and `pfs_image_key.bin` sidecars provide the same optional values.
  `NapsPfsImageSeed` also becomes the outer-PFS
  superblock `+0x370` seed; an explicit `OuterPfsSeed` must contain the same bytes.
  The builder generates the protected 0x800-byte CNT `IMAGE_KEY` and complete 0xB80-byte
  `ENTRY_KEYS` locally. `PublisherImageKey` and `PublisherEntryKeys` remain optional verbatim
  overrides, with `pkg_image_key.bin` and `pkg_entry_keys.bin` as their sidecar fallbacks.
  `LicenseProvider` accepts already-issued decrypted AC/AL RIF/license records from an
  application-defined backend or console bridge; returned bytes are validated before CNT encryption.
- **`ProsperoBuildResult`** — `OutputPath` and a list of non-fatal `Warnings`.
- **`ProsperoPackageMode`** — `Application`, `Homebrew`, `AdditionalContentData`,
  `AdditionalContentNoData`.
- **`ProsperoOutputFormat`** — `MetadataContainer` (`\x7FCNT` only),
  `DebugImage` (`\x7FFIH`, the default), or provider-backed `RetailImage` (`\x7FFIH`,
  signed byte `0x80`).
- **`InnerImageForm`** — `Plaintext`, `Encrypted`, `Compressed` (zlib PFSC),
  `KrakenCompressed` (PFSv3 Kraken, the `nwonly` codec).
- **`ProsperoInnerCompression`** (in `LibProsperoPkg.PKG`) — `None`, `Zlib` (installable inner
  image), `Kraken` (`nwonly` inner image). Set on `ProsperoBuildOptions.InnerCompression`
  / `ProsperoPkgBuildProperties.InnerCompression`; takes precedence over the legacy
  `CompressInnerImage` bool when non-`None`.

---

## `LibProsperoPkg.PKG` — container, signing, finalization

| Type | Purpose |
|---|---|
| `ProsperoPkgBuilder` | Build the outer PFS + `\x7FCNT` metadata container. |
| `ProsperoPkgReader` | `DetectType(path/stream)` and `Read(path/stream)` for existing packages. |
| `ProsperoPackageArchive` | High-level finalized-package reader. `DecryptOuterPfs` verifies/decrypts the outer image; `ExtractOuterFiles` extracts its files; `DecodeInnerPfs` resolves and decompresses NAPS into the logical PPR-PFS image; `ExtractInnerFiles` performs the full package-to-files operation. The `DecryptOuterPfs(package, output, passcode)` and `DecodeInnerPfs(package, output, passcode)` overloads are file-backed and support images larger than a managed array; high-level extraction uses that bounded-memory path automatically. |
| `ProsperoPublishingSidecar` | Loads conventional protected publisher inputs next to the host executable. `ReadPublisherEntryKeys`, `ReadPublisherImageKey`, `TryReadNapsMeta18`, and `ExportReusableInputs` preserve raw `pkg_entry_keys.bin`, `pkg_image_key.bin`, and SI `naps_meta_18.dat` from an existing package for an exact rebuild. These are optional overrides: fresh `ENTRY_KEYS` and `IMAGE_KEY` values are generated locally. A PFS-image key cannot be recovered from a package alone because the passcode is absent, but is derived locally during a build. |
| `IProsperoLicenseProvider` / `ProsperoLicenseArtifacts` | Provider boundary for backend/SDK/console-issued decrypted `license.dat` and `license.info`. `ProsperoDirectoryLicenseProvider` loads the conventional two-file representation. The builder validates size, `RIF\0`, content id and entitlement key, then applies the normal volume-specific CNT entry encryption. |
| `ProsperoCntEntryPolicy` | Central publisher policy for CNT flags, key index and fixed-entry naming. It distinguishes GD `license.info` key index 2 from AC/AL index 4 and applies key index 3 to protected NP/self/image/delta/reserved records. |
| `ProsperoPkgWriter` | Low-level container writer (`ProsperoPkgWriterEntry`, `ProsperoPkgWriterOptions`). |
| `ProsperoFihBuilder` | File-backed wrapping of `\x7FCNT` into a finalized `\x7FFIH` image. Debug SI can be produced through a stream factory. Standard Retail uses `IProsperoRetailFinalizationProvider` and refuses incomplete 0x80 output. |
| `IProsperoRetailFinalizationProvider` | Trusted standard-Retail boundary: produces the 0x300-byte FIH material and the 0x180-byte CNT-header authentication result. FGC/Flexible Content is intentionally a separate profile. |
| `ProsperoFlexibleContentFinalizer` | Dependency-free FGC finalization of publisher-created PFS metadata, FIH and standalone CNT files. `ProsperoFlexibleContentFinalizationOptions` supplies the manifest, token, passcode and matching partner RSA-3072 private key; the result returns the finalized superblock/FIH digests and resolved superblock offset. |
| `ProsperoPkgSigner` | RSA-3072 metadata signing and EKPFS/PFS key derivation. |
| `ProsperoNapsLayout` | PS5 `naps_pkg_layout.dat` (`PackageLayout_NAPS`) decoder and serializer for the `nwonly` streaming layout. `Parse`/`DecodeHeader`, `BuildLayout`, per-section `Encode*`/`Decode*` helpers, strict document validation, and `SectionMap`. Normal CblockInfo entries expose run/terminal discrimination and the confirmed ric/publisher bit fields. |
| `ProsperoImageDigests` | PS5 finalized-image / CNT digest algorithms (single primitive: **SHA3-256**). `FIH+0x30` is the plaintext-superblock digest; `FIH+0x70` and `+0xD0` are the distinct GeneralDigests Game and Target values. Also computes fixed-info, body, per-entry, package, CNT-rollup, content/header/system/playgo/target and NAPS-layout digests. |
| `ProsperoDdsEncoder` | Re-encode `sce_sys` icon/picture images to BC7 DDS. |

### Read model

- **`ProsperoPkg`** — `Type` (`ProsperoPkgType`), `Header` (`ProsperoPkgHeader?`), `Entries`
  (`IReadOnlyList<ProsperoPkgEntry>`), `Fih` (`ProsperoFihHeader?`).
- **`ProsperoPkgHeader`** — `Magic`, `Flags`, `EntryCount`, `EntryTableOffset`, `BodyOffset`,
  `BodySize`, `ContentId`, `DrmType`, `ContentType`.
- **`ProsperoPkgEntry`** — `Id` (`ProsperoEntryId`), `DataOffset`, `DataSize`, `Name`, and the
  raw header fields.
- **`ProsperoFihHeader`** — `SignedByte` (0x00 debug / 0x80 retail), `PfsImageOffset`,
  `PfsImageSize`, `EmbeddedCntOffset`.

### Build properties

- **`ProsperoPkgBuildProperties`** and **`ProsperoVolumeType`** drive the low-level builder. The
  publisher path is selected by `UsePublisherPprNaps`; `NapsOuterBlockCmacKey` supplies the separate
  publishing CMAC input only for a profile that explicitly enables keyed NAPS outer-block tags.
  It is not required for the verified Publishing Tools 2.79 debug/AC profile, whose tags are zero.
  `PrimaryId` selects the identity used by publisher `ENTRY_KEYS` index 1 and the PFS-image-key
  KDF; it defaults to `ContentId`. `NapsPfsImageSeed` fixes the seed used by the built-in streaming `obcc`
  generator. `NapsPfsImageKey` is an optional expected value; the actual key is derived locally.
  The native 0x800-byte `IMAGE_KEY` is generated as
  `RSA3072(pfs-image-key)[0x180] || SHAKE128(SHA3-256(pfs-image-key), 0x680)`;
  `PublisherImageKey` can still preserve an existing blob verbatim.
  `LicenseProvider` supplies already-issued RIF/license records when they are not stored beside
  the source GP5.
  Set
  `DeterministicBuild` to derive repeatable seeds and RSA padding for byte-identical debug/test
  packages; the default mode retains cryptographic randomness.
- **`ProsperoPkgLayout`** and **`ProsperoEntryId`** describe the container layout and entry ids.

---

## `LibProsperoPkg.PFS` — filesystem image

| Type | Purpose |
|---|---|
| `ProsperoPfsLayout` | Build a plaintext inner-PFS image from a folder. `BuildFromFolder`, `VerifyRoundTrip`. `FileCompression` selects `None`, classic PFSC `Zlib`, or PFSC v2 `Kraken`; `CompressionLevel` controls zlib (0..9) or Kraken (-4..9), and `CompressionExcludePatterns` controls raw-file path globs. `UsePublisherPprLayout` selects the direct inode-0 root, inode bitmap at block 1, and inode table at block 2; false retains the classic super-root/FPT layout. `OptimizeFileLayoutForReadSpeed` orders latency-sensitive and small files first. |
| `ProsperoPs5InnerImageAssembler` | Specialized publisher `nwonly` data-first inner-image assembler. `Build`/`BuildFromFsTree` return compatibility in-memory images; `BuildToFile`/`BuildFromFsTreeToFile` write the physical image directly to disk. `ProsperoPs5InnerImageResult.OpenImage` abstracts the two result forms and preserves placement/compression metadata for NAPS and SI generation. |
| `PfsReader` | Reads classic and publisher PPR-PFS images. Publisher mode `0x10` uses 0xA8-byte direct-offset inodes whose `+0x60` field is an absolute logical data offset. `File.CopyTo` and `ReadAllBytes` expose file payloads without requiring filesystem extraction. |
| `ProsperoPfsImage` | AES-XTS encrypt/decrypt a PFS image. `EncryptInPlace`, `VerifyRoundTrip`. |
| `ProsperoOuterPfsImage` | AES-XTS encrypt/decrypt the PS5 nwonly **outer** finalized-image PFS (whole 0x10000 block = one XTS unit; sector = block index, or `0x800000000000 | index` for signed blocks; superblock block left plaintext). `Transform` supports both in-memory spans and distinct input/output streams with bounded one-block memory; `EncryptInPlace`/`DecryptInPlace` are key- or content-id/passcode-driven. Decrypt and re-encrypt round-trip byte-for-byte. |
| `ProsperoOuterPfsSignature` | PS5 nwonly outer-PFS signing primitives. `ComputeBlockHash` (plain SHA3-256 per-block/dinode hash), `ComputeSuperblockIcv`/`WriteSuperblockIcv` (`SHA3-256(superblock[0:0x5a0])` with the `icv` field zeroed), `BlockSector(index, signed)` (the bit-47 signed-block sector flag). |
| `ProsperoOuterPfsBuilder` | PS5 nwonly outer-PFS **structure generator**: assembles the data-first plaintext outer image from its files (`pfs_image.dat`, `naps_pkg_layout.dat`) — inode table with per-block SHA3 hashes, super-root/uroot dirents, the `\x7fFLT` inode_flat_path_table (custom reduced-Keccak path hash), and the signed superblock (+`icv`). `BuildPlaintext`, `Encrypt`, `BuildEncrypted`, `BuildForPackage`, and bounded-memory `BuildForPackageToFile`. Signed files use 12 direct blocks, `ib[0]` single indirect, and `ib[1]` double indirect (about 202.3 GiB per inode). Types: `ProsperoOuterFile`, `ProsperoOuterFileSource`, `ProsperoOuterPfsBuildParameters`, `ProsperoOuterPfsBuildResult`, `ProsperoOuterPackageFileResult`. |
| `ProsperoPublisherPprBuilder` | Publisher artifact pipeline from a source folder through relocated direct-offset PPR-PFS (`mode 0x18`, superblock at logical 0x400000), NAPS, data-first outer PFS and AES-XTS. `Build` is the compatibility in-memory API; `BuildFileBacked` streams the logical/NAPS/outer layers to files and returns `ProsperoPublisherPprFileBuildResult`. Both return publisher `imagedigs.dat` metadata and the logical digest and validate the reverse path. |
| `ProsperoPfsKeys` | PFS-image key derivation using SHA3-256. `DeriveEkpfs(contentId, passcode)`, `DerivePublisherPfsImageKey(primaryId, passcode, seed)`, `BuildPublisherImageKey(pfsImageKey)`, `DeriveImageEncryptionKeys(ekpfs, seed)` → `(tweakKey, dataKey)`, overload `DeriveImageEncryptionKeys(contentId, passcode, seed)` → `(tweakKey, dataKey)`, `DeriveImageSignKey(ekpfs, seed)`. |
| `ProsperoPfsc` | PFSC block compression. `PackFile`, `Unpack`, `IsPfsc`. |

Each carries an options/result record pair (`ProsperoPfsLayoutOptions`/`Result`,
`ProsperoPfsImageOptions`/`Result`, `ProsperoPfscOptions`/`Result`).

### `LibProsperoPkg.PFS.Compression` — PS5 Kraken codecs

The PS5 compression-file (`PFSC` v3) codec used by the `nwonly` path.

| Type | Purpose |
|---|---|
| `ProsperoCompressedPfsImage` | Public façade for the inner-image use of the codec — packs/unpacks a whole PFS image as a self-describing `PFSC` v3 container. `Pack`/`PackStored`/`PackFile`, `Unpack`/`UnpackFile`, detection helpers, `ValidateRoundTrip`; returns `ProsperoCompressedPfsImageResult` (raw/encoded sizes, block + stored counts, gain %). The codec the builder's `ProsperoInnerCompression.Kraken` option uses. |
| `CompressedPfsFileWriter` | Produce a PFSv3 `PFSC` container. `WriteCompressed(payload, level, blockSize, useHuffmanArrays=true)` (Kraken with default-on Huffman entropy arrays, per-block stored fallback) / `WriteStored(payload)`. |
| `ProsperoNapsImage` | Resolves publisher NAPS fidx/U2C/CblockInfo tables into `ProsperoNapsPlan`/`ProsperoNapsSpan` and reconstructs the complete logical inner PPR-PFS stream with `BuildPlan` and `Decompress`. `Pack` is the inverse monotonic Kraken/stored writer; its stream overload processes one 256-KiB block and returns `ProsperoNapsFileBuildResult`. `ComputeOuterBlockDigest` implements the optional SHA3/reverse/AES-CMAC tag chain. |
| `ProsperoAfidMap` | Extracts exact path-to-AFID assignments from a decrypted PPR-PFS image and saves/loads the stable TSV sidecar. Supplying the result as `ProsperoBuildOptions.PublisherAfidAssignments` (or CLI `build-pkg ... afid=<map.tsv>`) preserves sparse `-1` slots, 256-KiB zero extents, FIDX boundaries, NAPS dedup records, and SI integrity geometry. |
| `CompressedPfsFile` | Parse a PFSv3 `PFSC` container. `Parse`, detection helpers, `VerifyFileDigest`, and `Decompress()` (drives `KrakenDecoder` for a full byte-exact decode). |
| `Oodle.KrakenDecoder` | Internal newLZ (Kraken) decoder: raw + Huffman literal/cmd/offset/length arrays, post-seed excess framing with length escapes, both literal models, multi-chunk and multi-block. Decodes two embedded reference vectors and checks SHA3-256. |
| `Oodle.KrakenHuffmanArrayEncoder` | Internal Huffman entropy-array encoder (chunk type 2, 3-stream split, K.3 length-limit) — the inverse of the decoder's array path; Huffman-codes each chunk's literal/command/length streams. Output round-trips through `KrakenDecoder` byte-for-byte. |
| `PprPfsKraken` | Streaming writer/reader for the distinct per-file PFSC v2 layout consumed by `ppr_pfs`: algorithm 2, 128 KiB table entries grouped into seeded/seedless 256 KiB Kraken requests, absolute low-48-bit boundaries and high-bit Kraken/stored flags. `PprPfsKrakenWriteOptions` can force selected ranges to stored groups and reject compression below a minimum saving. `PackFile`, `Write`, `UnpackFile`, `Unpack`. |
| `PprPfsReadOptimizer` | Inspects a ready inner PFS and produces merged, 256 KiB-aligned raw ranges for metadata, small files, and path patterns. The plan can be passed to `PprPfsKrakenWriteOptions.RawRanges` when building a PHUC outer layer. |
| `PfsDigest` | SHA3-256 helpers for the per-block hashes and the `@0x28` file digest. |
| `PfsShuffle` | The 13 pre-compression SoA de-interleave (shuffle/deshuffle) transforms. |

---

## `LibProsperoPkg.GP5` — project model

- **`Gp5Creator`** — `FromFolder(...)` / `FromFolderExplicit(...)` build a `Gp5Project` from a
  folder.
- **`Gp5Project`** — the GP5 document model, with both the "normal" (`rootdir`-walked) and
  "flat" (`files`/`folders`-listed) layouts represented via `Gp5Layout`. Elements:
  `Gp5Volume`, `Gp5Package`, `Gp5ChunkInfo`, `Gp5Chunks`, `Gp5Chunk`, `Gp5Scenarios`, `Gp5Scenario`,
  `Gp5RootDir`, `Gp5File`, `Gp5Dir`.
  The model preserves AL entitlement/date fields, PlayGo language/layer attributes,
  per-file chunk/content-config/compression settings, implicit source paths, and recursive
  overlay/virtual directories.

---

## `LibProsperoPkg.Keys` — publishing key access

- **`ProsperoKeys`** — exposes the wired-in PS5 publishing key material (`IsAvailable` and the
  individual key accessors). Used by the signer and the package builder.

---

## `LibProsperoPkg.PlayGo` — auxiliary file generators

- **`ProsperoPlayGo`** — generates the auxiliary `sce_sys` files (`about/right.sprx`,
  `playgo-chunk.dat`, `playgo-manifest.xml`) that the builder injects into the inner PFS so the
  produced file set is complete.

---

## `LibProsperoPkg.Content` — content file codecs

- **`ProsperoUcp`** — reads, builds, validates, verifies, and repairs UCP archives
  (`trophy2/*.ucp`, `uds/*.ucp`). `IsUcp`, `Read`, `Build`, `BuildFromDirectory`, `Validate`,
  `VerifyDigest`, and `WithRepairedDigest`.
- **`ProsperoFself`** — parses SELF containers and generates a fake-self from a 64-bit ELF.
  `IsSelf`, `IsElf`, `Parse`, `Validate`, and `MakeFself` (with `FselfOptions` for app and firmware
  version, an optional authority id, and optional synthesized PRX `.sceversion` data).
  `TryGetSdkVersion` and `TryGetSceVersionRecord` inspect either an ELF section or the publisher
  trailer after SELF `FileSize`. `MakeFself` requires the program-header table at ELF offset `0x40`
  and rejects header/metadata sizes that cannot be represented by the 16-bit SCE fields. The read
  model exposes `SelfImage`, `SelfSegment`, and `SelfExtInfo`.
