using LibProsperoPkg;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using LibProsperoPkg.PKG;
using LibProsperoPkg.Util;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;

namespace PprPfsKrakenTool;

internal static class Program
{
    private sealed class PhucReadProfile
    {
        public required string Name { get; init; }
        public required bool KeepMetadataRaw { get; init; }
        public required bool ForceAllRaw { get; init; }
        public required long SmallFileRawThreshold { get; init; }
        public required int MinimumSavingsPercent { get; init; }
        public required IReadOnlyCollection<string> RawPatterns { get; init; }
        public required bool OptimizeInnerLayout { get; init; }
    }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "-h" or "--help")
            {
                PrintUsage();
                return 0;
            }

            return args[0].ToLowerInvariant() switch
            {
                "build" => BuildPfs(args),
                "build-phuc" => BuildPhuc(args),
                "build-publisher-artifacts" => BuildPublisherArtifacts(args),
                "build-pkg" => BuildPackage(args),
                "pack" => PackFile(args),
                "unpack" => UnpackFile(args),
                "list" => ListPfs(args),
                "inspect-file" => InspectPfsFile(args),
                "verify-phuc" => VerifyPhuc(args),
                "verify" => VerifyFolder(args),
                "inspect-naps" => InspectNaps(args),
                "dump-naps" => DumpNaps(args),
                "plan-naps" => PlanNaps(args),
                "decompress-naps" => DecompressNaps(args),
                "pack-naps" => PackNaps(args),
                "roundtrip-naps" => RoundTripNaps(args),
                "inspect-pkg" => InspectPackage(args),
                "extract-pkg-outer" => ExtractPackageOuter(args),
                "dump-pkg-outer" => DumpPackageOuter(args),
                "check-pkg-imagedigs" => CheckPackageImageDigests(args),
                "extract-pkg-inner" => ExtractPackageInner(args),
                "extract-pkg-cnt" => ExtractPackageCnt(args),
                "selftest" => SelfTest(args),
                _ => throw new ArgumentException($"Unknown command: {args[0]}")
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("error: " + exception.Message);
            return 1;
        }
    }

    private static int InspectNaps(string[] args)
    {
        if (args.Length != 2) throw new ArgumentException("inspect-naps requires <naps_pkg_layout.dat>.");
        NapsLayoutDocument document = ProsperoNapsLayout.Parse(File.ReadAllBytes(args[1]));
        Console.WriteLine($"files={document.Counts.NumFiles} compression={document.Counts.CompressionType} keys={document.Counts.NumKeys}");
        Console.WriteLine($"ublocks={document.Counts.UBlockCount} outer={document.Counts.NumOuterBlocks} cblockInfo={document.Counts.NumCblockInfo}");
        Console.WriteLine($"layout-size=0x{document.Map.TotalSize:x} footer={document.TrailingZeroBytes}");
        return 0;
    }

    private static int BuildPackage(string[] args)
    {
        if (args.Length is < 5 or > 7)
            throw new ArgumentException(
                "build-pkg requires <source-dir> <output-dir> <content-id> <app|ac|al> [passcode] [naps-cmac-key-hex].");
        ProsperoPackageMode mode = args[4].ToLowerInvariant() switch
        {
            "app" => ProsperoPackageMode.Application,
            "ac" => ProsperoPackageMode.AdditionalContentData,
            "al" => ProsperoPackageMode.AdditionalContentNoData,
            _ => throw new ArgumentException("Package mode must be app, ac, or al."),
        };
        byte[]? cmac = args.Length == 7 ? Convert.FromHexString(args[6]) : null;
        var result = ProsperoPackageBuilder.Build(
            new ProsperoBuildOptions
            {
                SourceFolder = args[1],
                OutputFolder = args[2],
                ContentId = args[3],
                TitleId = args[3].Substring(7, 9),
                Mode = mode,
                Passcode = args.Length >= 6 ? args[5] : new string('0', 32),
                UsePublisherPprNaps = true,
                NapsOuterBlockCmacKey = cmac,
            },
            Console.WriteLine);
        Console.WriteLine(result.OutputPath);
        foreach (string warning in result.Warnings) Console.WriteLine("warning: " + warning);
        return 0;
    }

    private static int DumpNaps(string[] args)
    {
        if (args.Length != 2) throw new ArgumentException("dump-naps requires <naps_pkg_layout.dat>.");
        NapsLayoutDocument document = ProsperoNapsLayout.Parse(File.ReadAllBytes(args[1]));
        for (int i = 0; i < document.FileOffsets.Count; i++)
            Console.WriteLine($"file[{i}] type=0x{document.FileOffsets[i].Type:x2} uoff=0x{document.FileOffsets[i].UncompressedOffsetStart:x}");
        for (int i = 0; i < document.CblockInfos.Count; i++)
        {
            NapsCblockInfoEntry c = document.CblockInfos[i];
            Console.WriteLine(c.IsRunBase
                ? $"cbi[{i}] run end=0x{c.CoffsetEndMod256K:x} tweak=0x{c.TweakIdxStart:x} key={c.KeyTableIdx} base=0x{c.CoffsetStart256K:x}"
                : $"cbi[{i}] block coff=0x{c.CoffsetStartMod256K:x} uoff=0x{c.UoffsetStart:x} clen=0x{c.ClenEvenMinus1 + 1:x} even={c.Even} odd={c.Odd} kde={c.KdePredictor} shuffle={c.ShuffleIdx}");
        }
        return 0;
    }

    private static int PlanNaps(string[] args)
    {
        if (args.Length != 2) throw new ArgumentException("plan-naps requires <naps_pkg_layout.dat>.");
        NapsLayoutDocument document = ProsperoNapsLayout.Parse(File.ReadAllBytes(args[1]));
        ProsperoNapsPlan plan = ProsperoNapsImage.BuildPlan(document);
        foreach (ProsperoNapsSpan span in plan.Spans)
        {
            Console.WriteLine(
                $"span[{span.Index}] cbi={span.CblockInfoIndex} "
                + $"stored=0x{span.StoredOffset:x}+0x{span.CompressedLength:x} "
                + $"logical=0x{span.UncompressedOffset:x}+0x{span.UncompressedLength:x} "
                + $"first=0x{span.FirstChunkCompressedLength:x} "
                + $"tweak={span.TweakIndex} key={span.KeyTableIndex} "
                + $"even={span.Even} odd={span.Odd}");
        }
        Console.WriteLine($"logical-size=0x{plan.UncompressedSize:x} files={plan.Files.Count} spans={plan.Spans.Count}");
        return 0;
    }

    private static int DecompressNaps(string[] args)
    {
        if (args.Length != 4)
            throw new ArgumentException("decompress-naps requires <pfs_image.dat> <naps_pkg_layout.dat> <output>.");
        NapsLayoutDocument document = ProsperoNapsLayout.Parse(File.ReadAllBytes(args[2]));
        using var source = File.OpenRead(args[1]);
        using var output = File.Create(args[3]);
        ProsperoNapsImage.Decompress(source, document, output);
        Console.WriteLine($"decompressed 0x{output.Length:x} bytes");
        return 0;
    }

    private static int PackNaps(string[] args)
    {
        if (args.Length is < 4 or > 5)
            throw new ArgumentException("pack-naps requires <logical-pfs> <pfs_image.dat> <naps_pkg_layout.dat> [cmac-key-hex].");
        byte[]? cmacKey = args.Length == 5 ? Convert.FromHexString(args[4]) : null;
        ProsperoNapsBuildResult result = ProsperoNapsImage.Pack(
            File.ReadAllBytes(args[1]),
            new ProsperoNapsBuildOptions { OuterBlockCmacKey = cmacKey });
        File.WriteAllBytes(args[2], result.PackedImage);
        File.WriteAllBytes(args[3], result.LayoutBytes);
        Console.WriteLine(
            $"packed logical=0x{result.LogicalSize:x} physical=0x{result.PackedImage.Length:x} "
            + $"compressed-spans={result.CompressedSpanCount} stored-spans={result.StoredSpanCount}");
        return 0;
    }

    private static int RoundTripNaps(string[] args)
    {
        if (args.Length != 3) throw new ArgumentException("roundtrip-naps requires <input> <output>.");
        byte[] original = File.ReadAllBytes(args[1]);
        NapsLayoutDocument document = ProsperoNapsLayout.Parse(original);
        byte[] rebuilt = ProsperoNapsLayout.BuildLayout(document);
        File.WriteAllBytes(args[2], rebuilt);
        if (!original.AsSpan().SequenceEqual(rebuilt))
            throw new InvalidDataException("NAPS parse/build result is not byte-exact.");
        Console.WriteLine($"byte-exact: {rebuilt.Length} bytes");
        return 0;
    }

    private static int InspectPackage(string[] args)
    {
        if (args.Length != 2) throw new ArgumentException("inspect-pkg requires <package.pkg>.");
        ProsperoPkg package = ProsperoPkgReader.Read(args[1]);
        ProsperoPackageMap map = ProsperoPackageArchive.Inspect(args[1]);
        Console.WriteLine($"type={package.Type} content-id={package.Header?.ContentId}");
        Console.WriteLine($"outer=0x{map.OuterPfsOffset:x}+0x{map.OuterPfsSize:x} superblock={map.OuterSuperblockIndex}");
        Console.WriteLine($"cnt=0x{map.CntOffset:x}+0x{map.CntSize:x} supplement=0x{map.SupplementSize:x} entries={package.Entries.Count}");
        foreach (ProsperoPkgEntry entry in package.Entries)
            Console.WriteLine(
                $"entry=0x{entry.RawId:x4} flags=0x{entry.Flags1:x8}/0x{entry.Flags2:x8} " +
                $"offset=0x{entry.DataOffset:x} size=0x{entry.DataSize:x} name={entry.Name ?? "-"}");
        return 0;
    }

    private static int ExtractPackageOuter(string[] args)
    {
        if (args.Length is < 3 or > 4) throw new ArgumentException("extract-pkg-outer requires <package.pkg> <output-dir> [passcode].");
        string passcode = args.Length == 4 ? args[3] : new string('0', 32);
        IReadOnlyList<string> files = ProsperoPackageArchive.ExtractOuterFiles(args[1], args[2], passcode);
        Console.WriteLine($"extracted {files.Count} outer-PFS files");
        return 0;
    }

    private static int DumpPackageOuter(string[] args)
    {
        if (args.Length is < 3 or > 4)
            throw new ArgumentException("Usage: dump-pkg-outer <package.pkg> <output.pfs> [passcode]");
        string passcode = args.Length == 4 ? args[3] : new string('0', 32);
        File.WriteAllBytes(args[2], ProsperoPackageArchive.DecryptOuterPfs(args[1], passcode));
        Console.WriteLine(args[2]);
        return 0;
    }

    private static int CheckPackageImageDigests(string[] args)
    {
        if (args.Length is < 2 or > 3)
            throw new ArgumentException("Usage: check-pkg-imagedigs <package.pkg> [passcode]");
        string passcode = args.Length == 3 ? args[2] : new string('0', 32);
        byte[] outer = ProsperoPackageArchive.DecryptOuterPfs(args[1], passcode);
        string temporary = Path.Combine(Path.GetTempPath(), "libprospero-imagedigs-" + Guid.NewGuid().ToString("N"));
        try
        {
            ProsperoPackageArchive.ExtractCntEntries(args[1], temporary);
            byte[] expected = File.ReadAllBytes(Path.Combine(temporary, "entry-0000040a.bin"));
            int blockCount = outer.Length / ProsperoPackageArchive.OuterBlockSize;
            int reverseSha3Matches = 0;
            for (int i = 0; i < blockCount; i++)
            {
                byte[] digest = ProsperoSha3.HashData(
                    outer.AsSpan(i * ProsperoPackageArchive.OuterBlockSize, ProsperoPackageArchive.OuterBlockSize));
                Array.Reverse(digest);
                if (expected.AsSpan(i * 32, 32).SequenceEqual(digest)) reverseSha3Matches++;
            }
            Console.WriteLine($"blocks={blockCount} imagedigs={expected.Length} reverse-sha3-matches={reverseSha3Matches}");
            return 0;
        }
        finally
        {
            if (Directory.Exists(temporary)) Directory.Delete(temporary, recursive: true);
        }
    }

    private static int ExtractPackageInner(string[] args)
    {
        if (args.Length is < 3 or > 4) throw new ArgumentException("extract-pkg-inner requires <package.pkg> <output-dir> [passcode].");
        string passcode = args.Length == 4 ? args[3] : new string('0', 32);
        IReadOnlyList<string> files = ProsperoPackageArchive.ExtractInnerFiles(args[1], args[2], passcode);
        Console.WriteLine($"extracted {files.Count} inner PPR-PFS files");
        return 0;
    }

    private static int ExtractPackageCnt(string[] args)
    {
        if (args.Length != 3) throw new ArgumentException("extract-pkg-cnt requires <package.pkg> <output-dir>.");
        IReadOnlyList<string> files = ProsperoPackageArchive.ExtractCntEntries(args[1], args[2]);
        Console.WriteLine($"extracted {files.Count} CNT entries (encrypted entries remain raw)");
        return 0;
    }

    private static int SelfTest(string[] args)
    {
        if (args.Length != 1) throw new ArgumentException("selftest takes no arguments.");
        const string emptySha3 = "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A";
        string actual = Convert.ToHexString(ProsperoSha3.HashData(ReadOnlySpan<byte>.Empty));
        if (!string.Equals(actual, emptySha3, StringComparison.Ordinal))
            throw new InvalidDataException($"Managed SHA3-256 KAT failed: {actual}");
        Console.WriteLine("selftest: SHA3-256 known-answer test passed");
        return 0;
    }

    private static int BuildPfs(string[] args)
    {
        if (args.Length < 3)
            throw new ArgumentException("build requires <source-folder> and <output.pfs>.");

        Dictionary<string, string> options = ReadOptions(args, 3);
        EnsureOnlyOptions(options, "compression", "level", "min-size", "only-if-smaller",
            "min-savings-percent", "exclude", "layout", "classic");
        ProsperoPfsLayoutOptions layoutOptions = CreateLayoutOptions(options);
        bool publisherLayout = layoutOptions.UsePublisherPprLayout;
        ProsperoPfsLayoutResult result = ProsperoPfsLayout.BuildFromFolder(
            args[1], args[2], layoutOptions, Console.WriteLine);
        Console.WriteLine($"{(publisherLayout ? "PPR" : "classic")}-PFS written: {result.OutputPath} ({result.ImageSize:N0} bytes)");
        return 0;
    }

    private static int BuildPublisherArtifacts(string[] args)
    {
        if (args.Length is < 5 or > 6)
            throw new ArgumentException(
                "build-publisher-artifacts requires <source-folder> <output-dir> <content-id> <passcode> [cmac-key-hex].");
        byte[]? cmac = args.Length == 6 ? Convert.FromHexString(args[5]) : null;
        ProsperoPublisherPprBuildResult result = ProsperoPublisherPprBuilder.Build(
            new ProsperoPublisherPprBuildOptions
            {
                SourceFolder = args[1],
                OutputDirectory = args[2],
                ContentId = args[3],
                Passcode = args[4],
                PfsOptions = new ProsperoPfsLayoutOptions
                {
                    FileCompression = PfsFileCompressionMethod.Kraken,
                    CompressionLevel = PprPfsKraken.DefaultLevel,
                },
                NapsOptions = new ProsperoNapsBuildOptions { OuterBlockCmacKey = cmac },
            },
            Console.WriteLine);
        Console.WriteLine(
            $"publisher artifacts: inner-files={result.InnerFileCount} "
            + $"naps=0x{result.Naps.PackedImage.Length:x} outer-superblock={result.OuterSuperblockIndex}");
        return 0;
    }

    private static int BuildPhuc(string[] args)
    {
        if (args.Length < 3)
            throw new ArgumentException("build-phuc requires <game-folder|pfs_image.dat> and <output.phuc>.");
        if (!string.Equals(Path.GetExtension(args[2]), ".phuc", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("A PHUC image must use the .phuc extension.");

        Dictionary<string, string> options = ReadOptions(args, 3);
        EnsureOnlyOptions(options, "level", "min-size", "exclude", "only-if-smaller",
            "read-profile", "raw-small", "raw-inner", "raw-metadata",
            "min-savings-percent");
        if (ReadBool(options, "only-if-smaller", false))
        {
            throw new ArgumentException(
                "build-phuc requires a PFSC wrapper even when it is larger; --only-if-smaller must be false.");
        }
        PhucReadProfile readProfile = CreatePhucReadProfile(options);
        string sourcePath = Path.GetFullPath(args[1]);
        bool useExistingInnerImage = File.Exists(sourcePath);
        if (useExistingInnerImage)
            ValidateExistingInnerPfs(sourcePath);
        else
            ValidatePhucSource(sourcePath);

        IReadOnlyCollection<string> extraExclusions = options.TryGetValue("exclude", out string? excludeValue)
            ? excludeValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : Array.Empty<string>();
        IReadOnlyCollection<string> exclusions = extraExclusions
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var innerOptions = new ProsperoPfsLayoutOptions
        {
            FileCompression = PfsFileCompressionMethod.None,
            UsePublisherPprLayout = false,
            FilterOuterPackageEntries = false,
            ExcludeFileNames = Array.Empty<string>(),
            ExcludeFileSuffixes = Array.Empty<string>(),
            OptimizeFileLayoutForReadSpeed = readProfile.OptimizeInnerLayout,
            ReadPrioritySmallFileSize = readProfile.SmallFileRawThreshold,
            ReadPriorityPatterns = readProfile.RawPatterns,
        };
        var outerOptions = new ProsperoPfsLayoutOptions
        {
            FileCompression = PfsFileCompressionMethod.Kraken,
            CompressionLevel = ReadInt(options, "level", PprPfsKraken.DefaultLevel),
            MinimumKrakenFileSize = ReadLong(options, "min-size", 0),
            KrakenOnlyWhenSmaller = false,
            KrakenMinimumSavingsPercent = readProfile.MinimumSavingsPercent,
            KrakenExcludePatterns = exclusions,
            // PHUC uses the reference publisher direct-root geometry even though the first
            // mount is performed by pfs. ShadowMount then gives only pfs_image.dat a private
            // vector containing the ppr_pfs operations required to read its PFSC v2 stream.
            UsePublisherPprLayout = true,
            FilterOuterPackageEntries = false,
            ExcludeFileNames = Array.Empty<string>(),
            ExcludeFileSuffixes = Array.Empty<string>(),
        };

        string outputPath = Path.GetFullPath(args[2]);
        if (useExistingInnerImage && PathsEqual(sourcePath, outputPath))
            throw new IOException("The source inner PFS and output PHUC paths must be different.");
        if (!useExistingInnerImage && IsPathWithin(outputPath, sourcePath))
        {
            throw new IOException(
                "The output PHUC must be outside the source game folder so an existing image cannot be embedded into pfs_image.dat.");
        }
        string outputDirectory = Path.GetDirectoryName(outputPath) ?? Directory.GetCurrentDirectory();
        Directory.CreateDirectory(outputDirectory);
        string workspaceParent = !useExistingInnerImage && IsPathWithin(outputDirectory, sourcePath)
            ? Path.GetTempPath()
            : outputDirectory;
        string workspace = Path.Combine(workspaceParent, ".phuc-build-" + Guid.NewGuid().ToString("N"));
        if (!useExistingInnerImage && IsPathWithin(workspace, sourcePath))
        {
            throw new IOException(
                "A PHUC staging directory could not be placed outside the source game folder.");
        }
        Directory.CreateDirectory(workspace);
        try
        {
            string innerPath = Path.Combine(workspace, "pfs_image.dat");
            long innerSize;
            if (useExistingInnerImage)
            {
                bool linked = TryCreateHardLink(innerPath, sourcePath);
                if (!linked)
                    File.Copy(sourcePath, innerPath, overwrite: false);
                innerSize = new FileInfo(sourcePath).Length;
                Console.WriteLine($"inner: using existing PFS image ({(linked ? "hard link" : "copy")}): "
                    + $"{sourcePath} ({innerSize:N0} bytes)");
            }
            else
            {
                ProsperoPfsLayoutResult inner = ProsperoPfsLayout.BuildFromFolder(
                    sourcePath, innerPath, innerOptions,
                    message => Console.WriteLine("inner: " + message));
                innerSize = inner.ImageSize;
            }

            PprPfsReadOptimizationPlan readPlan = PprPfsReadOptimizer.AnalyzePfsImage(
                innerPath,
                new PprPfsReadOptimizationOptions
                {
                    KeepMetadataRaw = readProfile.KeepMetadataRaw,
                    SmallFileRawThreshold = readProfile.SmallFileRawThreshold,
                    RawFilePatterns = readProfile.RawPatterns,
                    ForceAllRaw = readProfile.ForceAllRaw,
                });
            outerOptions.KrakenRawRangeProvider = relativePath =>
                string.Equals(relativePath, "pfs_image.dat", StringComparison.OrdinalIgnoreCase)
                    ? readPlan.RawRanges
                    : Array.Empty<PprPfsRawRange>();
            Console.WriteLine($"read profile: {readProfile.Name}; raw groups={readPlan.RawGroupCount:N0}, "
                + $"raw logical={readPlan.RawLogicalBytes:N0} bytes, raw files={readPlan.RawFileCount:N0}, "
                + $"metadata prefix={readPlan.MetadataPrefixBytes:N0} bytes, "
                + $"minimum Kraken saving={readProfile.MinimumSavingsPercent}%");
            ProsperoPfsLayoutResult outer = ProsperoPfsLayout.BuildFromFolder(
                workspace, outputPath, outerOptions, message => Console.WriteLine("outer: " + message));
            ValidatePhucImage(outer.OutputPath);
            Console.WriteLine($"PHUC nested PFS/PPR-PFS container written: {outer.OutputPath} "
                + $"({outer.ImageSize:N0} bytes; inner PFS {innerSize:N0} bytes)");
            return 0;
        }
        finally
        {
            if (Directory.Exists(workspace))
                Directory.Delete(workspace, recursive: true);
        }
    }

    private static int VerifyFolder(string[] args)
    {
        if (args.Length < 2)
            throw new ArgumentException("verify requires <source-folder>.");
        Dictionary<string, string> options = ReadOptions(args, 2);
        EnsureOnlyOptions(options, "compression", "level", "min-size", "only-if-smaller",
            "min-savings-percent", "exclude", "layout", "classic");
        ProsperoPfsLayoutOptions layoutOptions = CreateLayoutOptions(options);
        bool valid = ProsperoPfsLayout.VerifyRoundTrip(args[1], layoutOptions);
        Console.WriteLine(valid ? "Round-trip verification passed." : "Round-trip verification failed.");
        return valid ? 0 : 1;
    }

    private static int VerifyPhuc(string[] args)
    {
        if (args.Length != 2)
            throw new ArgumentException("verify-phuc requires <image.phuc>.");
        ValidatePhucImage(Path.GetFullPath(args[1]));
        return 0;
    }

    private static ProsperoPfsLayoutOptions CreateLayoutOptions(Dictionary<string, string> options)
    {
        PfsFileCompressionMethod compression = ReadCompression(options, PfsFileCompressionMethod.Kraken);
        int level = ReadInt(options, "level", compression == PfsFileCompressionMethod.Zlib ? 9 : PprPfsKraken.DefaultLevel);
        IReadOnlyCollection<string> exclusions = options.TryGetValue("exclude", out string? excludeValue)
            ? excludeValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : ProsperoPfsLayoutOptions.DefaultKrakenExcludePatterns;
        return new ProsperoPfsLayoutOptions
        {
            FileCompression = compression,
            CompressionLevel = level,
            MinimumKrakenFileSize = ReadLong(options, "min-size", 0),
            KrakenOnlyWhenSmaller = ReadBool(options, "only-if-smaller", false),
            KrakenMinimumSavingsPercent = ReadInt(options, "min-savings-percent", 0),
            KrakenExcludePatterns = exclusions,
            UsePublisherPprLayout = ReadPublisherLayout(options),
            FilterOuterPackageEntries = false,
            // A compression exclusion means "store raw", not "omit from the filesystem".
            ExcludeFileNames = Array.Empty<string>(),
            ExcludeFileSuffixes = Array.Empty<string>(),
        };
    }

    private static int PackFile(string[] args)
    {
        if (args.Length < 3)
            throw new ArgumentException("pack requires <input-file> and <output.pfsc>.");

        Dictionary<string, string> options = ReadOptions(args, 3);
        EnsureOnlyOptions(options, "compression", "level", "min-savings-percent");
        PfsFileCompressionMethod compression = ReadCompression(options, PfsFileCompressionMethod.Kraken);
        int level = ReadInt(options, "level", compression == PfsFileCompressionMethod.Zlib ? 9 : PprPfsKraken.DefaultLevel);
        string inputPath = Path.GetFullPath(args[1]);
        string outputPath = Path.GetFullPath(args[2]);
        if (PathsEqual(inputPath, outputPath))
            throw new IOException("Pack input and output paths must be different.");
        if (compression == PfsFileCompressionMethod.Kraken)
        {
            PprPfsKrakenWriteResult result = PprPfsKraken.PackFile(
                inputPath, outputPath, new PprPfsKrakenWriteOptions
                {
                    Level = level,
                    MinimumSavingsPercent = ReadInt(options, "min-savings-percent", 0),
                });
            Console.WriteLine($"PFSC v2/Kraken written: {args[2]}");
            Console.WriteLine($"logical={result.UncompressedSize:N0} stored={result.StoredSize:N0} "
                + $"compressed-blocks={result.CompressedBlockCount}/{result.BlockCount} "
                + $"forced-raw={result.ForcedRawBlockCount} low-gain-raw={result.LowGainRawBlockCount}");
        }
        else if (compression == PfsFileCompressionMethod.Zlib)
        {
            PfscEncodeStats result = WriteOutputAtomically(outputPath, temporaryPath =>
            {
                using var input = new FileStream(
                    inputPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    bufferSize: 1 << 20, FileOptions.SequentialScan);
                using var output = new FileStream(
                    temporaryPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                    bufferSize: 1 << 20, FileOptions.SequentialScan);
                PfscEncodeStats stats = PfscEncoder.Encode(input, input.Length, output, new PfscEncoderOptions
                {
                    ZlibLevel = level,
                });
                return stats;
            });
            Console.WriteLine($"{(result.StoredRaw ? "Raw file (PFSC was not smaller)" : "Classic PFSC/zlib")} written: {args[2]}");
            Console.WriteLine($"logical={result.RawSize:N0} stored={result.EncodedSize:N0} "
                + $"compressed-blocks={result.CompressedBlocks}/{result.BlockCount}");
        }
        else
        {
            WriteOutputAtomically(outputPath, temporaryPath =>
            {
                File.Copy(inputPath, temporaryPath, overwrite: false);
                return true;
            });
            Console.WriteLine($"Raw file written: {args[2]}");
        }
        return 0;
    }

    private static int UnpackFile(string[] args)
    {
        if (args.Length < 3)
            throw new ArgumentException("unpack requires <input-file> and <output-file>.");

        Dictionary<string, string> options = ReadOptions(args, 3);
        EnsureOnlyOptions(options, "offset");
        long offset = ReadLong(options, "offset", 0);
        string inputPath = Path.GetFullPath(args[1]);
        string outputPath = Path.GetFullPath(args[2]);
        if (PathsEqual(inputPath, outputPath))
            throw new IOException("Unpack input and output paths must be different.");
        long size = WriteOutputAtomically(outputPath, temporaryPath =>
        {
            using var input = new FileStream(
                inputPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 1 << 20, FileOptions.SequentialScan);
            using var output = new FileStream(
                temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 1 << 20, FileOptions.SequentialScan);
            long written = PprPfsKraken.Unpack(input, offset, output);
            return written;
        });
        Console.WriteLine($"Unpacked {size:N0} bytes to {args[2]}");
        return 0;
    }

    private static int ListPfs(string[] args)
    {
        if (args.Length != 2)
            throw new ArgumentException("list requires <image.pfs>.");

        using var mapped = MemoryMappedFile.CreateFromFile(
            args[1], FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
        using var view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        var reader = new PfsReader(view);
        Console.WriteLine("state\tstored\tlogical\tpath");
        foreach (PfsReader.File file in reader.GetAllFiles().OrderBy(file => file.FullName, StringComparer.Ordinal))
        {
            bool compressed = file.flags.HasFlag(InodeFlags.compressed);
            long logical = file.compressed_size == 0 ? file.size : file.compressed_size;
            long stored = compressed ? ReadPfscStoredSize(file) : file.size;
            Console.WriteLine($"{(compressed ? "compressed" : "raw")}\t{stored}\t{logical}\t{file.FullName}");
        }
        return 0;
    }

    private static int InspectPfsFile(string[] args)
    {
        if (args.Length != 3)
            throw new ArgumentException("inspect-file requires <image.pfs> and <path>.");

        using var mapped = MemoryMappedFile.CreateFromFile(
            args[1], FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
        using var view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        var reader = new PfsReader(view);
        string imagePath = args[2].TrimStart('/', '\\');
        PfsReader.File file = reader.GetFile(imagePath)
            ?? throw new FileNotFoundException($"File is not present in the PFS image: {args[2]}");

        PfsHeader pfs = reader.Header;
        Console.WriteLine($"pfs.version=0x{pfs.Version:X8}");
        Console.WriteLine($"pfs.mode=0x{(uint)pfs.Mode:X8}");
        Console.WriteLine($"pfs.readonly={pfs.ReadOnly}");
        Console.WriteLine($"pfs.block_size=0x{pfs.BlockSize:X}");
        Console.WriteLine($"pfs.inode_table_block={pfs.InodeBlockSig.StartBlock}");
        Console.WriteLine($"file.path=/{imagePath}");
        Console.WriteLine($"file.inode={file.ino}");
        Console.WriteLine($"file.flags=0x{(uint)file.flags:X8}");
        Console.WriteLine($"file.size={file.size}");
        Console.WriteLine($"file.size_compressed={file.compressed_size}");
        Console.WriteLine($"file.data_offset=0x{file.offset:X}");

        if (!pfs.Mode.HasFlag(PfsMode.Signed))
        {
            const int inodeSize = 0xA8;
            var inode = new byte[inodeSize];
            long inodeOffset = checked((long)pfs.InodeBlockSig.StartBlock * pfs.BlockSize
                + file.ino * inodeSize);
            view.ReadArray(inodeOffset, inode, 0, inode.Length);
            Console.WriteLine($"inode.offset=0x{inodeOffset:X}");
            Console.WriteLine($"inode.mode=0x{BinaryPrimitives.ReadUInt16LittleEndian(inode.AsSpan(0x00)):X4}");
            Console.WriteLine($"inode.flags=0x{BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(0x04)):X8}");
            Console.WriteLine($"inode.size={BinaryPrimitives.ReadInt64LittleEndian(inode.AsSpan(0x08))}");
            Console.WriteLine($"inode.size_compressed={BinaryPrimitives.ReadInt64LittleEndian(inode.AsSpan(0x10))}");
            Console.WriteLine($"inode.unk1=0x{BinaryPrimitives.ReadUInt64LittleEndian(inode.AsSpan(0x50)):X16}");
            Console.WriteLine($"inode.unk2=0x{BinaryPrimitives.ReadUInt64LittleEndian(inode.AsSpan(0x58)):X16}");
            Console.WriteLine($"inode.blocks={BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(0x60))}");
            Console.WriteLine($"inode.start_block={BinaryPrimitives.ReadInt32LittleEndian(inode.AsSpan(0x64))}");
            Console.WriteLine($"inode.raw={Convert.ToHexString(inode)}");
        }

        if (file.flags.HasFlag(InodeFlags.compressed))
        {
            var header = new byte[0x88];
            file.GetView().Read(0, header, 0, header.Length);
            Console.WriteLine($"pfsc.magic=0x{BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x00)):X8}");
            Console.WriteLine($"pfsc.version={BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x04))}");
            Console.WriteLine($"pfsc.algorithm={BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x08))}");
            Console.WriteLine($"pfsc.block_size=0x{BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x0C)):X}");
            Console.WriteLine($"pfsc.entry_size=0x{BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x10)):X}");
            Console.WriteLine($"pfsc.block_count={BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x14))}");
            Console.WriteLine($"pfsc.logical_size={BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x18))}");
            Console.WriteLine($"pfsc.total_size={BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x20))}");
            Console.WriteLine($"pfsc.flags=0x{BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x28)):X}");
            Console.WriteLine($"pfsc.table_offset=0x{BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x30)):X}");
            Console.WriteLine($"pfsc.reserved38=0x{BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x38)):X}");
            Console.WriteLine($"pfsc.data_offset=0x{BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x40)):X}");
            Console.WriteLine($"pfsc.header_raw={Convert.ToHexString(header)}");
        }
        return 0;
    }

    private static long ReadPfscStoredSize(PfsReader.File file)
    {
        var header = new byte[0x28];
        file.GetView().Read(0, header, 0, header.Length);
        return BitConverter.ToUInt32(header, 0) == PprPfsKraken.Magic
            && BitConverter.ToUInt32(header, 4) == PprPfsKraken.Version
            ? checked((long)BitConverter.ToUInt64(header, 0x20))
            : file.size;
    }

    private static void ValidatePhucSource(string sourceFolder)
    {
        string root = Path.GetFullPath(sourceFolder);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"Source folder does not exist: {sourceFolder}");

        if (!File.Exists(Path.Combine(root, "sce_sys", "param.json"))
            && !File.Exists(Path.Combine(root, "sce_sys", "param.sfo")))
        {
            throw new InvalidDataException(
                "The PHUC inner game image requires sce_sys/param.json or sce_sys/param.sfo.");
        }
    }

    private static void ValidateExistingInnerPfs(string imagePath)
    {
        if (!string.Equals(Path.GetFileName(imagePath), "pfs_image.dat", StringComparison.OrdinalIgnoreCase))
            Console.WriteLine("inner: input file will be stored as pfs_image.dat in the PHUC container.");

        var info = new FileInfo(imagePath);
        if (info.Length == 0 || info.Length % 0x10000 != 0)
            throw new InvalidDataException(
                "The existing inner PFS image must be non-empty and aligned to a 0x10000-byte block.");

        using var mapped = MemoryMappedFile.CreateFromFile(
            imagePath, FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
        using var view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        var reader = new PfsReader(view);
        if (reader.Header.Version != PfsHeader.VersionPs5 || reader.Header.BlockSize != 0x10000)
            throw new InvalidDataException(
                "The existing inner image must be a PS5 PFS v2 image with 0x10000-byte blocks.");
        long describedSize = checked(reader.Header.Ndblock * reader.Header.BlockSize);
        if (describedSize != info.Length)
            throw new InvalidDataException(
                $"The inner PFS superblock describes {describedSize:N0} bytes, but the file contains {info.Length:N0} bytes.");
        if (reader.Header.Mode.HasFlag(PfsMode.Encrypted))
            throw new InvalidDataException("An encrypted inner PFS image cannot be used without its keys.");
        if (reader.GetFile("sce_sys/param.json") is null && reader.GetFile("sce_sys/param.sfo") is null)
            throw new InvalidDataException(
                "The existing inner PFS image requires sce_sys/param.json or sce_sys/param.sfo.");
    }

    private static bool TryCreateHardLink(string linkPath, string existingPath)
    {
        if (!OperatingSystem.IsWindows())
            return false;
        return CreateHardLinkWindows(linkPath, existingPath, IntPtr.Zero);
    }

    [DllImport("Kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkWindows(
        string fileName, string existingFileName, IntPtr securityAttributes);

    private static void ValidatePhucImage(string imagePath)
    {
        var imageInfo = new FileInfo(imagePath);
        if (!imageInfo.Exists || imageInfo.Length == 0 || imageInfo.Length % 0x10000 != 0)
            throw new InvalidDataException("PHUC must be a non-empty, 0x10000-byte-aligned PFS image.");
        using var mapped = MemoryMappedFile.CreateFromFile(
            imagePath, FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
        using var view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        var reader = new PfsReader(view);
        if (reader.Header.Version != PfsHeader.VersionPs5 || reader.Header.BlockSize != 0x10000)
            throw new InvalidDataException("PHUC must use a PS5 PFS v2 superblock with 0x10000-byte filesystem blocks.");
        if (checked(reader.Header.Ndblock * reader.Header.BlockSize) != imageInfo.Length)
            throw new InvalidDataException("PHUC file length does not match the PFS superblock block count.");

        if (reader.Header.ReadOnly != 1
            || reader.Header.Mode != PfsMode.UnknownFlagAlwaysSet
            || reader.Header.InodeBlockSig.StartBlock != 2)
        {
            throw new InvalidDataException(
                "PHUC outer PFS must be unsigned, unencrypted, read-only, and start its inode table at block 2.");
        }

        PfsReader.Dir directRoot = reader.GetSuperRoot();
        if (directRoot.Get("uroot") is not null || directRoot.Get("flat_path_table") is not null)
        {
            throw new InvalidDataException(
                "PHUC outer PFS must use publisher direct-root geometry without uroot or flat_path_table.");
        }

        Dictionary<string, PfsReader.File> files = reader.GetAllFiles().ToDictionary(
            file => ImageRelativePath(file.FullName), StringComparer.Ordinal);
        if (files.Count != 1
            || !files.TryGetValue("pfs_image.dat", out PfsReader.File? inner))
        {
            throw new InvalidDataException(
                "PHUC outer PFS must contain only pfs_image.dat.");
        }
        if (!inner.flags.HasFlag(InodeFlags.compressed))
            throw new InvalidDataException("PHUC pfs_image.dat must be PFSC v2/Kraken compressed.");

        ValidateDirectRootBitmap(view, reader.Header.DinodeCount, reader.Header.BlockSize);
        ValidateDirectRootInode(view, reader.Header, inodeNumber: 0, expectedMode: 0x41ED,
            expectedFlags: 0, expectedLogicalSize: null, expectedStoredSize: null);
        long pfscSize = ValidatePfscV2(inner);
        ValidateDirectRootInode(view, reader.Header, inner.ino, expectedMode: 0x81A4,
            expectedFlags: (uint)InodeFlags.compressed,
            expectedLogicalSize: inner.size, expectedStoredSize: pfscSize);

        Console.WriteLine("PHUC validation passed: publisher direct-root outer PFS with one "
            + "reference-style PFSC v2/Kraken pfs_image.dat.");
    }

    private static void ValidateDirectRootBitmap(
        MemoryMappedViewAccessor image, long inodeCount, uint blockSize)
    {
        if (inodeCount <= 0 || inodeCount >= checked((long)blockSize * 8))
            throw new InvalidDataException("PHUC inode count does not fit in the allocation bitmap.");
        int usedBytes = checked((int)((inodeCount + 7) / 8));
        var bitmap = new byte[usedBytes + 1];
        image.ReadArray(blockSize, bitmap, 0, bitmap.Length);
        for (long inode = 0; inode < inodeCount; inode++)
        {
            if ((bitmap[checked((int)(inode / 8))] & (1 << (int)(inode & 7))) == 0)
                throw new InvalidDataException($"PHUC inode bitmap does not allocate inode {inode}.");
        }
        int unusedHighBits = usedBytes * 8 - checked((int)inodeCount);
        if (unusedHighBits > 0 && (bitmap[usedBytes - 1] & (0xFF << (8 - unusedHighBits))) != 0)
            throw new InvalidDataException("PHUC inode bitmap has unexpected bits after the last inode.");
        if (bitmap[usedBytes] != 0)
            throw new InvalidDataException("PHUC inode bitmap has unexpected allocations after the inode table.");
    }

    private static void ValidateDirectRootInode(
        MemoryMappedViewAccessor image,
        PfsHeader pfs,
        uint inodeNumber,
        ushort expectedMode,
        uint expectedFlags,
        long? expectedLogicalSize,
        long? expectedStoredSize)
    {
        const int inodeSize = 0xA8;
        var bytes = new byte[inodeSize];
        long offset = checked((long)pfs.InodeBlockSig.StartBlock * pfs.BlockSize
            + inodeNumber * inodeSize);
        image.ReadArray(offset, bytes, 0, bytes.Length);
        ReadOnlySpan<byte> inode = bytes;
        ushort mode = BinaryPrimitives.ReadUInt16LittleEndian(inode[0x00..]);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(inode[0x04..]);
        long size = BinaryPrimitives.ReadInt64LittleEndian(inode[0x08..]);
        long sizeCompressed = BinaryPrimitives.ReadInt64LittleEndian(inode[0x10..]);
        uint blocks = BinaryPrimitives.ReadUInt32LittleEndian(inode[0x60..]);
        int startBlock = BinaryPrimitives.ReadInt32LittleEndian(inode[0x64..]);

        if (mode != expectedMode || flags != expectedFlags)
            throw new InvalidDataException(
                $"PHUC inode {inodeNumber} has mode/flags 0x{mode:X4}/0x{flags:X}, expected 0x{expectedMode:X4}/0x{expectedFlags:X}.");
        if (expectedLogicalSize.HasValue
            && (size != expectedLogicalSize.Value || sizeCompressed != expectedLogicalSize.Value))
        {
            throw new InvalidDataException(
                $"PHUC inode {inodeNumber} must store the logical size in both size fields.");
        }
        if (!expectedLogicalSize.HasValue && sizeCompressed != size)
            throw new InvalidDataException(
                $"PHUC directory inode {inodeNumber} must store its dirent size in both size fields.");

        long storedSize = expectedStoredSize ?? size;
        uint expectedBlocks = checked((uint)((storedSize + pfs.BlockSize - 1) / pfs.BlockSize));
        long firstDataBlock = checked(2 + pfs.DinodeBlockCount);
        if (blocks != expectedBlocks || startBlock < firstDataBlock
            || checked(startBlock + (long)blocks) > pfs.Ndblock)
            throw new InvalidDataException($"PHUC inode {inodeNumber} has invalid extent geometry.");
        for (int index = 1; index < (int)Math.Min(blocks, 12U); index++)
        {
            int directBlock = BinaryPrimitives.ReadInt32LittleEndian(inode[(0x64 + index * 4)..]);
            if (directBlock != startBlock + index)
                throw new InvalidDataException(
                    $"PHUC inode {inodeNumber} direct block {index} is not sequential.");
        }
        const uint directBlocks = 12;
        uint pointersPerBlock = pfs.BlockSize / sizeof(int);
        int indirect0 = BinaryPrimitives.ReadInt32LittleEndian(inode[0x94..]);
        int indirect1 = BinaryPrimitives.ReadInt32LittleEndian(inode[0x98..]);
        if (blocks > directBlocks && indirect0 != checked(startBlock + (int)blocks))
            throw new InvalidDataException(
                $"PHUC inode {inodeNumber} is missing its single-indirect block map.");
        if (blocks > directBlocks + pointersPerBlock && indirect1 != indirect0 + 1)
            throw new InvalidDataException(
                $"PHUC inode {inodeNumber} is missing its double-indirect block map.");

        uint mappedBlock = Math.Min(blocks, directBlocks);
        uint singleCount = Math.Min(blocks - mappedBlock, pointersPerBlock);
        for (uint entry = 0; entry < singleCount; entry++, mappedBlock++)
        {
            int mapped = image.ReadInt32(checked((long)indirect0 * pfs.BlockSize + entry * sizeof(int)));
            if (mapped != checked(startBlock + (int)mappedBlock))
                throw new InvalidDataException(
                    $"PHUC inode {inodeNumber} has an invalid single-indirect entry {entry}.");
        }

        uint remaining = blocks - mappedBlock;
        if (remaining > 0)
        {
            uint leafCount = checked((remaining + pointersPerBlock - 1) / pointersPerBlock);
            for (uint leaf = 0; leaf < leafCount; leaf++)
            {
                int leafBlock = image.ReadInt32(
                    checked((long)indirect1 * pfs.BlockSize + leaf * sizeof(int)));
                if (leafBlock != checked(indirect1 + 1 + (int)leaf))
                    throw new InvalidDataException(
                        $"PHUC inode {inodeNumber} has an invalid double-indirect leaf {leaf}.");

                uint leafEntries = Math.Min(remaining, pointersPerBlock);
                for (uint entry = 0; entry < leafEntries; entry++, mappedBlock++)
                {
                    int mapped = image.ReadInt32(
                        checked((long)leafBlock * pfs.BlockSize + entry * sizeof(int)));
                    if (mapped != checked(startBlock + (int)mappedBlock))
                        throw new InvalidDataException(
                            $"PHUC inode {inodeNumber} has an invalid double-indirect entry {leaf}:{entry}.");
                }
                remaining -= leafEntries;
            }
        }
    }

    private static long ValidatePfscV2(PfsReader.File file)
    {
        var header = new byte[0x88];
        file.GetView().Read(0, header, 0, header.Length);
        ReadOnlySpan<byte> h = header;
        uint blockCount = BinaryPrimitives.ReadUInt32LittleEndian(h[0x14..]);
        long logicalSize = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x18..]));
        long totalSize = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x20..]));
        long tableOffset = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x30..]));
        long dataOffset = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x40..]));
        long expectedDataOffset = Align(0x400L + checked((long)(blockCount + 1) * sizeof(ulong)), 0x20);
        ReadOnlySpan<byte> expectedEncoder =
        [
            0xD5, 0x75, 0x50, 0xFB, 0x29, 0x22, 0x76, 0xBF,
            0x57, 0xAE, 0xAE, 0xEA, 0x26, 0x31, 0x93, 0xA2,
        ];

        if (BinaryPrimitives.ReadUInt32LittleEndian(h[0x00..]) != PprPfsKraken.Magic
            || BinaryPrimitives.ReadUInt32LittleEndian(h[0x04..]) != PprPfsKraken.Version
            || BinaryPrimitives.ReadUInt32LittleEndian(h[0x08..]) != (uint)CompressionAlgorithm.Kraken
            || BinaryPrimitives.ReadUInt32LittleEndian(h[0x0C..]) != PprPfsKraken.BlockSize
            || BinaryPrimitives.ReadUInt32LittleEndian(h[0x10..]) != 0x20
            || blockCount != Math.Max(1, (logicalSize + PprPfsKraken.BlockSize - 1) / PprPfsKraken.BlockSize)
            || logicalSize != file.size || file.compressed_size != file.size
            || BinaryPrimitives.ReadUInt64LittleEndian(h[0x28..]) != 0x120802
            || tableOffset != 0x400 || dataOffset != expectedDataOffset
            || BinaryPrimitives.ReadUInt64LittleEndian(h[0x38..]) != 0
            || !h[0x48..0x78].SequenceEqual(new byte[0x30])
            || !h[0x78..0x88].SequenceEqual(expectedEncoder))
        {
            throw new InvalidDataException(
                "pfs_image.dat does not match the reference PFSC v2/Kraken header profile.");
        }

        var table = new byte[checked((int)(blockCount + 1) * sizeof(ulong))];
        file.GetView().Read(tableOffset, table, 0, table.Length);
        ulong first = BinaryPrimitives.ReadUInt64LittleEndian(table);
        ulong sentinel = BinaryPrimitives.ReadUInt64LittleEndian(
            table.AsSpan(checked((int)blockCount * sizeof(ulong))));
        const ulong low48Mask = 0x0000FFFFFFFFFFFFUL;
        if ((first & low48Mask) != (ulong)dataOffset
            || sentinel != (0x8000UL << 48 | (ulong)totalSize)
            || totalSize < dataOffset)
        {
            throw new InvalidDataException("pfs_image.dat has an invalid PFSC v2 offset table.");
        }

        // ppr_pfs submits a C000/4000 pair as one 256 KiB Kraken package.  The first
        // 128 KiB chunk contains an eight-byte raw seed; the continuation begins directly
        // with its 0x80+ newLZ control byte.  The old writer encoded both halves independently,
        // so the table looked correct while the second range actually began with another seed.
        // Validate both the grouping and the two control-byte positions so that malformed
        // images are rejected before they reach the console's ZDE.
        for (int index = 0; index < blockCount;)
        {
            ulong current = BinaryPrimitives.ReadUInt64LittleEndian(
                table.AsSpan(index * sizeof(ulong)));
            ulong next = BinaryPrimitives.ReadUInt64LittleEndian(
                table.AsSpan((index + 1) * sizeof(ulong)));
            ushort flags = checked((ushort)(current >> 48));
            ushort nextFlags = checked((ushort)(next >> 48));
            long currentOffset = checked((long)(current & low48Mask));
            long nextOffset = checked((long)(next & low48Mask));
            if (currentOffset < dataOffset || nextOffset <= currentOffset || nextOffset > totalSize)
                throw new InvalidDataException($"pfs_image.dat PFSC block {index} has an invalid range.");

            int logicalBlockSize = logicalSize == 0
                ? PprPfsKraken.BlockSize
                : checked((int)Math.Min(
                    PprPfsKraken.BlockSize,
                    logicalSize - (long)index * PprPfsKraken.BlockSize));

            if (flags == 0x8000)
            {
                if (nextOffset - currentOffset != logicalBlockSize)
                    throw new InvalidDataException(
                        $"pfs_image.dat stored PFSC block {index} has an invalid size.");
                index++;
                continue;
            }

            if (flags != 0xC000)
                throw new InvalidDataException(
                    $"pfs_image.dat PFSC block {index} has unsupported flags 0x{flags:X4}.");
            ValidateKrakenControlByte(file, currentOffset + 8, index, continuation: false);

            bool paired = index + 1 < blockCount && nextFlags == 0x4000;
            if (paired)
            {
                ulong end = BinaryPrimitives.ReadUInt64LittleEndian(
                    table.AsSpan((index + 2) * sizeof(ulong)));
                long endOffset = checked((long)(end & low48Mask));
                if ((index & 1) != 0 || endOffset <= nextOffset || endOffset > totalSize)
                    throw new InvalidDataException(
                        $"pfs_image.dat Kraken pair at block {index} has invalid continuation geometry.");
                ValidateKrakenControlByte(file, nextOffset, index + 1, continuation: true);
                index += 2;
            }
            else
            {
                if (index + 1 < blockCount && (nextFlags & 0x8000) == 0)
                    throw new InvalidDataException(
                        $"pfs_image.dat Kraken block {index} is missing a group boundary.");
                index++;
            }
        }
        return totalSize;
    }

    private static void ValidateKrakenControlByte(
        PfsReader.File file,
        long offset,
        int blockIndex,
        bool continuation)
    {
        var value = new byte[1];
        file.GetView().Read(offset, value, 0, 1);
        if ((value[0] & 0x80) == 0)
        {
            string position = continuation ? "seedless continuation" : "post-seed stream";
            throw new InvalidDataException(
                $"pfs_image.dat PFSC block {blockIndex} does not begin with a valid {position} control byte.");
        }
    }

    private static long Align(long value, int alignment) =>
        checked((value + alignment - 1) & ~(alignment - 1L));

    private static string ImageRelativePath(string fullName) =>
        fullName.TrimStart('/').StartsWith("uroot/", StringComparison.OrdinalIgnoreCase)
            ? fullName.TrimStart('/')[6..]
            : fullName.TrimStart('/');

    private static void EnsureOnlyOptions(Dictionary<string, string> options, params string[] allowed)
    {
        var allowedSet = allowed.ToHashSet(StringComparer.OrdinalIgnoreCase);
        string? unsupported = options.Keys.FirstOrDefault(key => !allowedSet.Contains(key));
        if (unsupported is not null)
            throw new ArgumentException($"Unsupported option: --{unsupported}.");
    }

    private static Dictionary<string, string> ReadOptions(string[] args, int start)
    {
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int index = start; index < args.Length; index += 2)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
                throw new ArgumentException($"Expected --name value at argument {index + 1}.");
            string name = args[index][2..];
            if (name.Length == 0)
                throw new ArgumentException($"Option name is empty at argument {index + 1}.");
            if (!options.TryAdd(name, args[index + 1]))
                throw new ArgumentException($"Option --{name} was specified more than once.");
        }
        return options;
    }

    private static int ReadInt(Dictionary<string, string> options, string name, int fallback) =>
        options.TryGetValue(name, out string? value)
            ? int.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture)
            : fallback;

    private static long ReadLong(Dictionary<string, string> options, string name, long fallback) =>
        options.TryGetValue(name, out string? value)
            ? ParseLong(value)
            : fallback;

    private static long ParseLong(string value) => value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? long.Parse(value[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture)
        : long.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);

    private static bool ReadBool(Dictionary<string, string> options, string name, bool fallback) =>
        options.TryGetValue(name, out string? value) ? bool.Parse(value) : fallback;

    private static PhucReadProfile CreatePhucReadProfile(Dictionary<string, string> options)
    {
        string name = options.TryGetValue("read-profile", out string? value)
            ? value.ToLowerInvariant()
            : "fast";
        bool compact = name == "compact";
        bool raw = name == "raw";
        if (!compact && !raw && name != "fast")
            throw new ArgumentException("--read-profile must be fast, compact, or raw.");

        IReadOnlyCollection<string> defaults = compact
            ? Array.Empty<string>()
            : PprPfsReadOptimizationOptions.DefaultLatencySensitivePatterns;
        IReadOnlyCollection<string> extra = options.TryGetValue("raw-inner", out string? rawValue)
            ? rawValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : Array.Empty<string>();
        string[] patterns = defaults.Concat(extra)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        long smallThreshold = ReadLong(options, "raw-small", compact ? 0 : 0x100000);
        int minimumSavings = ReadInt(options, "min-savings-percent", compact || raw ? 0 : 12);
        bool keepMetadataRaw = ReadBool(options, "raw-metadata", !compact);
        if (smallThreshold < 0)
            throw new ArgumentOutOfRangeException("--raw-small");
        if (minimumSavings is < 0 or > 100)
            throw new ArgumentOutOfRangeException("--min-savings-percent");

        return new PhucReadProfile
        {
            Name = name,
            KeepMetadataRaw = keepMetadataRaw,
            ForceAllRaw = raw,
            SmallFileRawThreshold = smallThreshold,
            MinimumSavingsPercent = minimumSavings,
            RawPatterns = patterns,
            OptimizeInnerLayout = !compact || patterns.Length > 0 || smallThreshold > 0,
        };
    }

    private static PfsFileCompressionMethod ReadCompression(
        Dictionary<string, string> options,
        PfsFileCompressionMethod fallback)
    {
        if (!options.TryGetValue("compression", out string? value))
            return fallback;
        return value.ToLowerInvariant() switch
        {
            "none" or "raw" => PfsFileCompressionMethod.None,
            "zlib" => PfsFileCompressionMethod.Zlib,
            "kraken" => PfsFileCompressionMethod.Kraken,
            _ => throw new ArgumentException("--compression must be none, zlib, or kraken."),
        };
    }

    private static bool ReadPublisherLayout(Dictionary<string, string> options)
    {
        if (options.ContainsKey("classic") && options.ContainsKey("layout"))
            throw new ArgumentException("Use either --classic or --layout, not both.");
        if (options.TryGetValue("classic", out string? classic))
            return !bool.Parse(classic);
        if (!options.TryGetValue("layout", out string? layout))
            return true;
        return layout.ToLowerInvariant() switch
        {
            "ppr" or "publisher" => true,
            "classic" => false,
            _ => throw new ArgumentException("--layout must be ppr or classic."),
        };
    }

    private static T WriteOutputAtomically<T>(string outputPath, Func<string, T> writer)
    {
        string outputFullPath = Path.GetFullPath(outputPath);
        string directory = Path.GetDirectoryName(outputFullPath) ?? Directory.GetCurrentDirectory();
        Directory.CreateDirectory(directory);
        string temporaryPath = Path.Combine(
            directory, ".pfs-output-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            T result = writer(temporaryPath);
            File.Move(temporaryPath, outputFullPath, overwrite: true);
            return result;
        }
        finally
        {
            try { File.Delete(temporaryPath); }
            catch { /* best-effort cleanup */ }
        }
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.GetFullPath(left),
            Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static bool IsPathWithin(string candidate, string directory)
    {
        string candidateFull = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        string directoryFull = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        return string.Equals(candidateFull, directoryFull, comparison)
            || candidateFull.StartsWith(directoryFull + Path.DirectorySeparatorChar, comparison);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("PFS/PPR-PFS compressed-image builder");
        Console.WriteLine("  build-phuc <game-folder|pfs_image.dat> <output.phuc> [--level N]");
        Console.WriteLine("            [--read-profile fast|compact|raw] [--raw-small 0x100000]");
        Console.WriteLine("            [--raw-inner \"eboot.bin;sce_module/**\"] [--raw-metadata true]");
        Console.WriteLine("            [--min-savings-percent 12] [--exclude \"pattern\"]");
        Console.WriteLine("  build <source-folder> <output.pfs> [--layout ppr|classic]");
        Console.WriteLine("        [--compression none|zlib|kraken] [--level N] [--min-size 0]");
        Console.WriteLine("        [--exclude \"sce_sys/**;movies/*.mp4\"] [--only-if-smaller false]");
        Console.WriteLine("        [--classic true]   (alias for --layout classic)");
        Console.WriteLine("  build-publisher-artifacts <source-folder> <output-dir> <content-id> <passcode> [cmac-key-hex]");
        Console.WriteLine("  build-pkg <source-dir> <output-dir> <content-id> <app|ac|al> [passcode] [naps-cmac-key-hex]");
        Console.WriteLine("  pack  <input-file> <output.pfsc> [--compression zlib|kraken|none] [--level N]");
        Console.WriteLine("        [--min-savings-percent 0]");
        Console.WriteLine("  unpack <input-or-image> <output-file> [--offset 0x0]");
        Console.WriteLine("  list <image.pfs>");
        Console.WriteLine("  inspect-file <image.pfs> <path>");
        Console.WriteLine("  verify-phuc <image.phuc>");
        Console.WriteLine("  verify <source-folder> [the same build options]");
        Console.WriteLine("  inspect-naps <naps_pkg_layout.dat>");
        Console.WriteLine("  dump-naps <naps_pkg_layout.dat>");
        Console.WriteLine("  plan-naps <naps_pkg_layout.dat>");
        Console.WriteLine("  decompress-naps <pfs_image.dat> <naps_pkg_layout.dat> <output>");
        Console.WriteLine("  pack-naps <logical-pfs> <pfs_image.dat> <naps_pkg_layout.dat> [cmac-key-hex]");
        Console.WriteLine("  roundtrip-naps <input> <output>");
        Console.WriteLine("  inspect-pkg <package.pkg>");
        Console.WriteLine("  extract-pkg-outer <package.pkg> <output-dir> [passcode]");
        Console.WriteLine("  dump-pkg-outer <package.pkg> <output.pfs> [passcode]");
        Console.WriteLine("  check-pkg-imagedigs <package.pkg> [passcode]");
        Console.WriteLine("  extract-pkg-inner <package.pkg> <output-dir> [passcode]");
        Console.WriteLine("  extract-pkg-cnt <package.pkg> <output-dir>");
        Console.WriteLine("  selftest");
        Console.WriteLine("  Levels: Kraken -4..9 (default 8), zlib 0..9 (default 9).");
        Console.WriteLine("  Valid builds: ppr+kraken/none; classic+zlib/kraken/none.");
    }
}
