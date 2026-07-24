using LibProsperoPkg;
using LibProsperoPkg.Content;
using LibProsperoPkg.GP5;
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
using System.Text;

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
                "hash-flt" => HashFlatPath(args),
                "verify-phuc" => VerifyPhuc(args),
                "verify" => VerifyFolder(args),
                "inspect-naps" => InspectNaps(args),
                "inspect-naps-meta18" => InspectNapsMeta18(args),
                "decrypt-naps-meta18" => DecryptNapsMeta18(args),
                "check-naps-meta18-obcc" => CheckNapsMeta18Obcc(args),
                "probe-publisher-obcc" => ProbePublisherObcc(args),
                "dump-naps" => DumpNaps(args),
                "check-naps-cmac" => CheckNapsCmac(args),
                "encode-dds" => EncodeDds(args),
                "roundtrip-gp5" => RoundTripGp5(args),
                "plan-naps" => PlanNaps(args),
                "decompress-naps" => DecompressNaps(args),
                "pack-naps" => PackNaps(args),
                "roundtrip-naps" => RoundTripNaps(args),
                "inspect-pkg" => InspectPackage(args),
                "extract-pkg-outer" => ExtractPackageOuter(args),
                "dump-pkg-outer" => DumpPackageOuter(args),
                "dump-pkg-inner" => DumpPackageInner(args),
                "check-pkg-fih" => CheckPackageFih(args),
                "check-pkg-imagedigs" => CheckPackageImageDigests(args),
                "check-pkg-signature" => CheckPackageSignature(args),
                "resign-pkg" => ResignPackage(args),
                "extract-pkg-inner" => ExtractPackageInner(args),
                "extract-pkg-cnt" => ExtractPackageCnt(args),
                "extract-pkg-si" => ExtractPackageSi(args),
                "export-publisher-inputs" => ExportPublisherInputs(args),
                "probe-entry-crypto" => ProbeEntryCrypto(args),
                "selftest" => SelfTest(args),
                "selftest-large-outer" => SelfTestLargeOuter(args),
                _ => throw new ArgumentException($"Unknown command: {args[0]}")
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("error: " + exception.Message);
            if (string.Equals(
                    Environment.GetEnvironmentVariable("LIBPROSPERO_TRACE"),
                    "1",
                    StringComparison.Ordinal))
                Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static int EncodeDds(string[] args)
    {
        if (args.Length != 3)
            throw new ArgumentException("encode-dds requires <input.png> <output.dds>.");

        byte[] dds = ProsperoDdsEncoder.EncodePngToDds(File.ReadAllBytes(args[1]));
        string? directory = Path.GetDirectoryName(Path.GetFullPath(args[2]));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        File.WriteAllBytes(args[2], dds);
        Console.WriteLine($"DDS BC7 written: {args[2]} ({dds.Length} bytes)");
        return 0;
    }

    private static int RoundTripGp5(string[] args)
    {
        if (args.Length != 3)
            throw new ArgumentException("roundtrip-gp5 requires <input.gp5> <output.gp5>.");

        Gp5Project project = Gp5Project.ReadFrom(args[1]);
        Gp5Project.WriteTo(project, args[2]);
        Console.WriteLine(
            $"GP5 written: type={project.Volume.Type}, layout={project.Layout}, " +
            $"files={project.Files.Count}, chunks={project.Volume.ChunkInfo?.Chunks.Count ?? 0}");
        return 0;
    }

    private static int InspectNaps(string[] args)
    {
        if (args.Length != 2) throw new ArgumentException("inspect-naps requires <naps_pkg_layout.dat>.");
        byte[] layout = File.ReadAllBytes(args[1]);
        NapsLayoutDocument document = ProsperoNapsLayout.Parse(layout);
        Console.WriteLine($"files={document.Counts.NumFiles} compression={document.Counts.CompressionType} keys={document.Counts.NumKeys}");
        Console.WriteLine($"ublocks={document.Counts.UBlockCount} outer={document.Counts.NumOuterBlocks} cblockInfo={document.Counts.NumCblockInfo}");
        Console.WriteLine($"layout-size=0x{document.Map.TotalSize:x} footer={document.TrailingZeroBytes}");
        Console.WriteLine($"sha3-256={Convert.ToHexString(ProsperoImageDigests.Sha3_256(layout)).ToLowerInvariant()}");
        return 0;
    }

    private static int InspectNapsMeta18(string[] args)
    {
        if (args.Length != 2)
            throw new ArgumentException("inspect-naps-meta18 requires <naps_meta_18.dat>.");

        byte[] plain = ProsperoNapsMeta.DecryptMeta18(File.ReadAllBytes(args[1]));
        int offset = 0;
        int records = 0;
        while (offset < plain.Length)
        {
            if (plain.Length - offset < 16)
                throw new InvalidDataException($"Truncated meta18 record header at 0x{offset:X}.");
            string tag = new string(
            [
                (char)plain[offset + 3],
                (char)plain[offset + 2],
                (char)plain[offset + 1],
                (char)plain[offset],
            ]);
            byte version = plain[offset + 4];
            ulong length = BinaryPrimitives.ReadUInt64LittleEndian(plain.AsSpan(offset + 8, 8));
            if (length > (ulong)(plain.Length - offset - 16))
                throw new InvalidDataException(
                    $"Meta18 record '{tag}' at 0x{offset:X} exceeds the file: length=0x{length:X}.");
            Console.WriteLine(
                $"record[{records}] tag={tag} version={version} offset=0x{offset:X} size=0x{length:X}");
            offset = checked(offset + 16 + (int)length);
            records++;
        }
        Console.WriteLine($"records={records} plaintext-size=0x{plain.Length:X}");
        return 0;
    }

    private static int DecryptNapsMeta18(string[] args)
    {
        if (args.Length != 3)
            throw new ArgumentException(
                "decrypt-naps-meta18 requires <naps_meta_18.dat> <plaintext-output>.");
        byte[] plain = ProsperoNapsMeta.DecryptMeta18(File.ReadAllBytes(args[1]));
        File.WriteAllBytes(args[2], plain);
        Console.WriteLine($"decrypted 0x{plain.Length:X} bytes");
        return 0;
    }

    private static int CheckNapsMeta18Obcc(string[] args)
    {
        if (args.Length != 3)
            throw new ArgumentException(
                "check-naps-meta18-obcc requires <naps_meta_18.dat> <pfs_image.dat>.");
        byte[] plain = ProsperoNapsMeta.DecryptMeta18(File.ReadAllBytes(args[1]));
        byte[] expected = FindMeta18Record(plain, "obcc");
        byte[] expectedDigests = FindMeta18Record(plain, "obdg");
        byte[] image = File.ReadAllBytes(args[2]);
        int blocks = checked((image.Length + 0xFFFF) / 0x10000);
        if (expected.Length != blocks * 4)
            throw new InvalidDataException(
                $"obcc contains {expected.Length / 4} records, while pfs_image.dat contains {blocks} blocks.");
        if (expectedDigests.Length != blocks * 32)
            throw new InvalidDataException(
                $"obdg contains {expectedDigests.Length / 32} records, while pfs_image.dat contains {blocks} blocks.");

        int matches = 0;
        int digestMatches = 0;
        for (int i = 0; i < blocks; i++)
        {
            int offset = i * 0x10000;
            int size = Math.Min(0x10000, image.Length - offset);
            uint actual = ProsperoCrc32C.Compute(image.AsSpan(offset, size));
            uint wanted = BinaryPrimitives.ReadUInt32LittleEndian(expected.AsSpan(i * 4, 4));
            byte[] digest = ProsperoImageDigests.Sha3_256(image.AsSpan(offset, size));
            if (digest.AsSpan().SequenceEqual(expectedDigests.AsSpan(i * 32, 32)))
                digestMatches++;
            if (actual == wanted)
                matches++;
            else if (i < 8)
                Console.WriteLine($"obcc[{i}] expected=0x{wanted:X8} crc32c=0x{actual:X8}");
        }
        Console.WriteLine(
            $"obcc-blocks={blocks} crc32c-matches={matches} mismatches={blocks - matches} " +
            $"obdg-sha3-matches={digestMatches}");
        return matches == blocks ? 0 : 1;
    }

    private static int ProbePublisherObcc(string[] args)
    {
        if (args.Length is < 4 or > 6)
            throw new ArgumentException(
                "probe-publisher-obcc requires <package.pkg> <naps_meta_18.dat> " +
                "<pfs_image.dat> [passcode] or " +
                "<package.pkg> <naps_meta_18.dat> <pfs_image.dat> " +
                "<pfs-image-key-hex> <pfs-image-seed-hex>.");

        bool explicitPfsImageKey = args.Length == 6;
        string passcode = args.Length == 5 ? args[4] : new string('0', 32);
        ProsperoPkg package = ProsperoPkgReader.Read(args[1]);
        string contentId = package.Header?.ContentId
            ?? throw new InvalidDataException("Embedded CNT header is unavailable.");
        byte[] packageBytes = File.ReadAllBytes(args[1]);
        ulong superblockOffset =
            BinaryPrimitives.ReadUInt64LittleEndian(packageBytes.AsSpan(0x20, 8));
        if (superblockOffset + 0x380 > (ulong)packageBytes.Length)
            throw new InvalidDataException("FIH superblock range is outside the package.");
        byte[] seed = explicitPfsImageKey
            ? Convert.FromHexString(args[5])
            : packageBytes.AsSpan(checked((int)superblockOffset) + 0x370, 16).ToArray();
        byte[] pfsImageKey = explicitPfsImageKey
            ? Convert.FromHexString(args[4])
            : ProsperoPfsKeys.DeriveEkpfs(contentId, passcode);
        if (pfsImageKey.Length != 32 || seed.Length != 16)
            throw new ArgumentException(
                "The explicit PFS image key and seed must decode to 32 and 16 bytes respectively.");

        byte[] kdfInput = new byte[4 + 16];
        BinaryPrimitives.WriteUInt32LittleEndian(kdfInput.AsSpan(0, 4), 1);
        seed.CopyTo(kdfInput, 4);
        byte[] digest = System.Security.Cryptography.HMACSHA256.HashData(
            pfsImageKey, kdfInput);

        byte[] expected = FindMeta18Record(
            ProsperoNapsMeta.DecryptMeta18(File.ReadAllBytes(args[2])), "obcc");
        byte[] physical = File.ReadAllBytes(args[3]);
        if ((physical.Length % 0x10000) != 0 || expected.Length != physical.Length / 0x10000 * 4)
            throw new InvalidDataException("pfs_image.dat/obcc block geometry mismatch.");

        for (int order = 0; order < 2; order++)
        {
            byte[] first = digest.AsSpan(order == 0 ? 0 : 16, 16).ToArray();
            byte[] second = digest.AsSpan(order == 0 ? 16 : 0, 16).ToArray();
            foreach (bool encrypt in new[] { false, true })
            {
                int matches = 0;
                using var xts = new XtsBlockTransform(first, second);
                for (int i = 0; i < physical.Length / 0x10000; i++)
                {
                    byte[] block = physical.AsSpan(i * 0x10000, 0x10000).ToArray();
                    xts.CryptSector(block, (ulong)i, encrypt);
                    uint actual = ProsperoCrc32C.Compute(block);
                    uint wanted = BinaryPrimitives.ReadUInt32LittleEndian(
                        expected.AsSpan(i * 4, 4));
                    if (actual == wanted) matches++;
                }
                Console.WriteLine(
                    $"data=D[{(order == 0 ? "0..15" : "16..31")}] " +
                    $"tweak=D[{(order == 0 ? "16..31" : "0..15")}] " +
                    $"mode={(encrypt ? "encrypt" : "decrypt")} matches={matches}/{physical.Length / 0x10000}");
            }
        }
        Console.WriteLine(
            $"{(explicitPfsImageKey ? "pfs-image-key" : "ekpfs-fallback")}=" +
            Convert.ToHexString(pfsImageKey));
        Console.WriteLine($"seed={Convert.ToHexString(seed)}");
        Console.WriteLine($"digest={Convert.ToHexString(digest)}");
        return 0;
    }

    private static int HashFlatPath(string[] args)
    {
        if (args.Length < 2)
            throw new ArgumentException("hash-flt requires one or more paths.");
        foreach (string path in args.Skip(1))
            Console.WriteLine($"{path}=0x{ProsperoPs5FlatPathTable.HashPath(path):x16}");
        return 0;
    }

    private static int BuildPackage(string[] args)
    {
        if (args.Length is < 5 or > 12)
            throw new ArgumentException(
                "build-pkg requires <source-dir> <output-dir> <content-id> <app|ac|al> [passcode] [naps-cmac-key-hex|-] [naps-meta-18-file|-] [metadata-private-key.pem|-] [outer-pfs-seed-hex|-] [deterministic] [strict].");
        ProsperoPackageMode mode = args[4].ToLowerInvariant() switch
        {
            "app" => ProsperoPackageMode.Application,
            "ac" => ProsperoPackageMode.AdditionalContentData,
            "al" => ProsperoPackageMode.AdditionalContentNoData,
            _ => throw new ArgumentException("Package mode must be app, ac, or al."),
        };
        byte[]? cmac = args.Length >= 7 && args[6] != "-" ? Convert.FromHexString(args[6]) : null;
        byte[]? napsMeta18 = args.Length >= 8 && args[7] != "-" ? File.ReadAllBytes(args[7]) : null;
        using ProsperoRsaMetadataSigner? metadataSigner = args.Length >= 9 && args[8] != "-"
            ? ProsperoRsaMetadataSigner.LoadPem(args[8])
            : null;
        byte[]? outerPfsSeed = args.Length >= 10 && args[9] != "-"
            ? Convert.FromHexString(args[9])
            : null;
        string[] modes = args.Skip(10).Select(value => value.ToLowerInvariant()).ToArray();
        if (modes.Any(value => value is not ("deterministic" or "strict")) ||
            modes.Distinct(StringComparer.Ordinal).Count() != modes.Length)
        {
            throw new ArgumentException(
                "Trailing build-pkg modes may contain 'deterministic' and/or 'strict' once each.");
        }
        bool deterministic = modes.Contains("deterministic", StringComparer.Ordinal);
        bool strict = modes.Contains("strict", StringComparer.Ordinal);
        if (outerPfsSeed is { Length: not 16 })
            throw new ArgumentException("Outer PFS seed must decode to exactly 16 bytes.");
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
                NapsMeta18 = napsMeta18,
                MetadataSigner = metadataSigner,
                OuterPfsSeed = outerPfsSeed,
                DeterministicBuild = deterministic,
                RequirePublisherCompatibility = strict,
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
        for (int i = 0; i < document.CblockInfoOffsetByUblock.Count; i++)
        {
            NapsU2cEntry u = document.CblockInfoOffsetByUblock[i];
            Console.WriteLine($"u2c[{i}] base={u.InfoOffset9BBase} indexes=" +
                string.Join(',', u.StartCblockInfoIndex));
        }
        for (int i = 0; i < document.CblockInfos.Count; i++)
        {
            NapsCblockInfoEntry c = document.CblockInfos[i];
            Console.WriteLine(c.IsRunBase
                ? $"cbi[{i}] run end=0x{c.CoffsetEndMod256K:x} tweak=0x{c.TweakIdxStart:x} key={c.KeyTableIdx} base=0x{c.CoffsetStart256K:x}"
                : $"cbi[{i}] block coff=0x{c.CoffsetStartMod256K:x} uoff=0x{c.UoffsetStart:x} clen=0x{c.ClenEvenMinus1 + 1:x} even={c.Even} odd={c.Odd} kde={c.KdePredictor} shuffle={c.ShuffleIdx}");
        }
        for (int i = 0; i < document.OuterBlockDigests.Count; i++)
            Console.WriteLine($"outer-cmac[{i}]={Convert.ToHexString(document.OuterBlockDigests[i]).ToLowerInvariant()}");
        return 0;
    }

    private static int CheckNapsCmac(string[] args)
    {
        if (args.Length != 4)
            throw new ArgumentException(
                "check-naps-cmac requires <naps_pkg_layout.dat> <pfs_image.dat> <16-byte-key-hex>.");

        NapsLayoutDocument document = ProsperoNapsLayout.Parse(File.ReadAllBytes(args[1]));
        byte[] image = File.ReadAllBytes(args[2]);
        byte[] key = Convert.FromHexString(args[3]);
        if (key.Length != 16)
            throw new ArgumentException("NAPS CMAC key must decode to exactly 16 bytes.");

        int blockSize = ProsperoNapsImage.OuterBlockSize;
        int physicalBlocks = checked((image.Length + blockSize - 1) / blockSize);
        if (physicalBlocks != document.Counts.NumOuterBlocks)
            throw new InvalidDataException(
                $"pfs_image.dat has {physicalBlocks} outer blocks, layout declares {document.Counts.NumOuterBlocks}.");

        int matches = 0;
        for (int i = 0; i < physicalBlocks; i++)
        {
            int offset = i * blockSize;
            int available = Math.Min(blockSize, image.Length - offset);
            byte[] padded = new byte[blockSize];
            image.AsSpan(offset, available).CopyTo(padded);
            byte[] actual = ProsperoNapsImage.ComputeOuterBlockDigest(padded, key);
            if (document.OuterBlockDigests[i].AsSpan().SequenceEqual(actual))
                matches++;
        }

        Console.WriteLine(
            $"outer-blocks={physicalBlocks} cmac-matches={matches} cmac-mismatches={physicalBlocks - matches}");
        return matches == physicalBlocks ? 0 : 1;
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
        ProsperoPackageArchive.DecryptOuterPfs(args[1], args[2], passcode);
        Console.WriteLine(args[2]);
        return 0;
    }

    private static int DumpPackageInner(string[] args)
    {
        if (args.Length is < 3 or > 4)
            throw new ArgumentException("Usage: dump-pkg-inner <package.pkg> <output.pfs> [passcode]");
        string passcode = args.Length == 4 ? args[3] : new string('0', 32);
        ProsperoPackageArchive.DecodeInnerPfs(args[1], args[2], passcode);
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

    private static int CheckPackageFih(string[] args)
    {
        if (args.Length is < 2 or > 3)
            throw new ArgumentException("Usage: check-pkg-fih <package.pkg> [passcode]");
        string passcode = args.Length == 3 ? args[2] : new string('0', 32);
        byte[] package = File.ReadAllBytes(args[1]);
        if (package.Length < ProsperoPkgLayout.FihHeaderRegionSize)
            throw new InvalidDataException("Package is too short to contain a FIH header.");

        ulong superblockOffset = BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0x20));
        ulong superblockSize = BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0x28));
        ulong outerOffset = BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0x10));
        ulong outerSize = BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0x18));
        if (superblockSize > int.MaxValue || superblockOffset + superblockSize > (ulong)package.Length)
            throw new InvalidDataException("FIH superblock range is outside the package.");

        ReadOnlySpan<byte> expectedGame = package.AsSpan(0x30, 32);
        byte[] rawGame = ProsperoImageDigests.Sha3_256(
            package.AsSpan(checked((int)superblockOffset), checked((int)superblockSize)));
        byte[] plainOuter = ProsperoPackageArchive.DecryptOuterPfs(args[1], passcode);
        ulong relative = checked(superblockOffset - outerOffset);
        if (relative + superblockSize > (ulong)plainOuter.Length || outerSize > (ulong)plainOuter.Length)
            throw new InvalidDataException("FIH superblock range is outside the decrypted outer PFS.");
        byte[] plainGame = ProsperoImageDigests.Sha3_256(
            plainOuter.AsSpan(checked((int)relative), checked((int)superblockSize)));

        Console.WriteLine(
            $"game-digest raw={expectedGame.SequenceEqual(rawGame)} plaintext={expectedGame.SequenceEqual(plainGame)} " +
            $"copies70={expectedGame.SequenceEqual(package.AsSpan(0x70, 32))} " +
            $"copiesd0={expectedGame.SequenceEqual(package.AsSpan(0xd0, 32))}");

        ulong cntOffset = BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0x58));
        if (cntOffset + 0x5a0 > (ulong)package.Length)
            throw new InvalidDataException("FIH CNT offset is outside the package.");
        ReadOnlySpan<byte> cntTail = package.AsSpan(checked((int)cntOffset));
        ulong cntSize = BinaryPrimitives.ReadUInt64BigEndian(cntTail.Slice(0x4b8, 8));
        if (cntSize < 0x1180 || cntSize > (ulong)cntTail.Length || cntSize > int.MaxValue)
            throw new InvalidDataException("CNT region size is outside the package.");
        ReadOnlySpan<byte> cnt = cntTail[..checked((int)cntSize)];
        byte[] fixedInfo = ProsperoImageDigests.ComputeFixedInfoDigest(
            package.AsSpan(0, ProsperoPkgLayout.FihHeaderRegionSize));
        byte[] packageDigest = ProsperoImageDigests.ComputePackageDigest(cnt);
        byte[] rollup = ProsperoImageDigests.ComputeCntHeaderRollupDigest(cnt);
        Console.WriteLine(
            $"cnt-pfs-digest={expectedGame.SequenceEqual(cnt.Slice(0x440, 32))} " +
            $"cnt-fixed-digest={fixedInfo.AsSpan().SequenceEqual(cnt.Slice(0x460, 32))} " +
            $"cnt-package-digest={packageDigest.AsSpan().SequenceEqual(cnt.Slice(0xfe0, 32))} " +
            $"cnt-rollup={rollup.AsSpan().SequenceEqual(cnt.Slice(0x100, 32))}");

        uint imageKeyOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.Slice(0x510, 4));
        uint imageKeySize = BinaryPrimitives.ReadUInt32BigEndian(cnt.Slice(0x514, 4));
        uint mandatoryOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.Slice(0x518, 4));
        uint mandatorySize = BinaryPrimitives.ReadUInt32BigEndian(cnt.Slice(0x51c, 4));
        bool descriptorRangesValid = imageKeyOffset <= cnt.Length && imageKeySize <= cnt.Length - imageKeyOffset
            && mandatoryOffset <= cnt.Length && mandatorySize <= cnt.Length - mandatoryOffset;
        bool descriptorDigestValid = false;
        if (descriptorRangesValid)
        {
            byte[] descriptorDigest = new byte[64];
            ProsperoImageDigests.Sha3_256(cnt.Slice((int)imageKeyOffset, (int)imageKeySize)).CopyTo(descriptorDigest, 0);
            ProsperoImageDigests.Sha3_256(cnt.Slice((int)mandatoryOffset, (int)mandatorySize)).CopyTo(descriptorDigest, 32);
            descriptorDigestValid = descriptorDigest.AsSpan().SequenceEqual(cnt.Slice(0x520, 64));
        }
        bool seedValid = cnt.Slice(0x4a0, 16).SequenceEqual(
            plainOuter.AsSpan(checked((int)relative + 0x370), 16));
        Console.WriteLine(
            $"cnt-image-seed={seedValid} descriptor-ranges={descriptorRangesValid} " +
            $"descriptor-digest={descriptorDigestValid} rsa3072={ProsperoPackageArchive.VerifyCntMetadataSignature(args[1])}");

        string temporary = Path.Combine(Path.GetTempPath(), "libprospero-fih-" + Guid.NewGuid().ToString("N"));
        try
        {
            ProsperoPackageArchive.ExtractOuterFiles(args[1], temporary, passcode);
            string layoutPath = Path.Combine(temporary, "uroot", ProsperoNapsLayout.FileName);
            byte[] layout = File.ReadAllBytes(layoutPath);
            ulong recordedLength = BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0xa8));
            byte[] nestedDigest = ProsperoImageDigests.Sha3_256(layout);
            Console.WriteLine(
                $"nested-size=0x{recordedLength:x}/0x{layout.Length:x} " +
                $"nested-digest={package.AsSpan(0xb0, 32).SequenceEqual(nestedDigest)}");
        }
        finally
        {
            if (Directory.Exists(temporary)) Directory.Delete(temporary, recursive: true);
        }
        return 0;
    }

    private static int CheckPackageSignature(string[] args)
    {
        if (args.Length != 2)
            throw new ArgumentException("check-pkg-signature requires <package.pkg>.");
        bool valid = ProsperoPackageArchive.VerifyCntMetadataSignature(args[1]);
        Console.WriteLine($"cnt-metadata-signature={(valid ? "valid" : "invalid")}");
        return valid ? 0 : 2;
    }

    private static int ResignPackage(string[] args)
    {
        if (args.Length != 3)
            throw new ArgumentException("resign-pkg requires <input.pkg> <output.pkg>.");
        string input = Path.GetFullPath(args[1]);
        string output = Path.GetFullPath(args[2]);
        if (string.Equals(input, output, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Input and output package paths must be different.");

        byte[] fih = new byte[ProsperoPkgLayout.FihHeaderRegionSize];
        using (var source = File.OpenRead(input))
            source.ReadExactly(fih);
        ulong cntOffset = BinaryPrimitives.ReadUInt64LittleEndian(fih.AsSpan(0x58, 8));
        if (cntOffset > long.MaxValue)
            throw new InvalidDataException("FIH CNT offset exceeds the supported file range.");

        File.Copy(input, output, overwrite: true);
        using var package = new FileStream(output, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        if ((ulong)package.Length < cntOffset + 0x1180)
            throw new InvalidDataException("Embedded CNT header/signature is outside the package.");
        package.Position = (long)cntOffset;
        byte[] signedHeader = new byte[0x1000];
        package.ReadExactly(signedHeader);
        byte[] signature = ProsperoPkgSigner.SignDigest(Crypto.Sha256(signedHeader));
        package.Position = checked((long)cntOffset + 0x1000);
        package.Write(signature);
        Console.WriteLine($"resigned CNT+0x1000 with RSA-3072: {output}");
        return 0;
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
        if (args.Length is < 3 or > 4)
            throw new ArgumentException("extract-pkg-cnt requires <package.pkg> <output-dir> [passcode].");
        IReadOnlyList<string> files = args.Length == 4
            ? ProsperoPackageArchive.ExtractCntEntries(args[1], args[2], args[3])
            : ProsperoPackageArchive.ExtractCntEntries(args[1], args[2]);
        Console.WriteLine(args.Length == 4
            ? $"extracted {files.Count} CNT entries (protected entries decrypted)"
            : $"extracted {files.Count} CNT entries (protected entries remain raw)");
        return 0;
    }

    private static int ExportPublisherInputs(string[] args)
    {
        if (args.Length is < 3 or > 4 ||
            (args.Length == 4 && !string.Equals(args[3], "--overwrite", StringComparison.Ordinal)))
        {
            throw new ArgumentException(
                "export-publisher-inputs requires <package.pkg> <output-dir> [--overwrite].");
        }

        IReadOnlyList<string> paths = ProsperoPublishingSidecar.ExportReusableInputs(
            args[1], args[2], overwrite: args.Length == 4);
        foreach (string path in paths)
            Console.WriteLine(path);
        Console.WriteLine(
            "Exported protected inputs for exact preservation; the separate sc2 estimate " +
            "pfs-image-key cannot be recovered from the package alone (the passcode is not stored).");
        return 0;
    }

    private static int ProbeEntryCrypto(string[] args)
    {
        if (args.Length != 4)
            throw new ArgumentException("probe-entry-crypto requires <package.pkg> <entry-id-hex> <passcode>.");
        uint id = uint.Parse(args[2].Replace("0x", "", StringComparison.OrdinalIgnoreCase), NumberStyles.HexNumber);
        ProsperoPkg pkg = ProsperoPkgReader.Read(args[1]);
        ProsperoPkgEntry entry = pkg.Entries.First(e => e.RawId == id);
        if (pkg.Header is null) throw new InvalidDataException("Package has no embedded CNT header.");
        long cntBase = pkg.Fih is null ? 0 : checked((long)pkg.Fih.EmbeddedCntOffset);
        byte[] ciphertext = new byte[entry.DataSize];
        using (var fs = File.OpenRead(args[1]))
        {
            fs.Position = cntBase + entry.DataOffset;
            fs.ReadExactly(ciphertext);
        }

        byte[] meta = new byte[32];
        BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(0x00), entry.RawId);
        BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(0x04), entry.NameTableOffset);
        BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(0x08), entry.Flags1);
        BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(0x0C), entry.Flags2);
        BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(0x10), entry.DataOffset);
        BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(0x14), entry.DataSize);
        uint keyIndex = (entry.Flags2 >> 12) & 0xF;
        foreach (bool sha3Kdf in new[] { false, true })
        foreach (bool sha3Iv in new[] { false, true })
        {
            byte[] dk = Crypto.ComputeKeys(pkg.Header.ContentId, args[3], keyIndex, sha3Kdf);
            byte[] preimage = meta.Concat(dk).ToArray();
            byte[] ivKey = sha3Iv ? Crypto.Sha3_256(preimage) : Crypto.Sha256(preimage);
            byte[] plaintext = new byte[ciphertext.Length];
            Crypto.AesCbcCfb128Decrypt(
                plaintext, ciphertext, ciphertext.Length,
                ivKey.Skip(16).Take(16).ToArray(), ivKey.Take(16).ToArray());
            ReadOnlySpan<byte> prefix = plaintext.AsSpan(0, Math.Min(64, plaintext.Length));
            string ascii = new(prefix.ToArray().Select(b => b is >= 0x20 and < 0x7F ? (char)b : '.').ToArray());
            Console.WriteLine($"kdf={(sha3Kdf ? "sha3" : "sha256")} iv={(sha3Iv ? "sha3" : "sha256")} " +
                              $"prefix={Convert.ToHexString(prefix)} ascii={ascii}");
        }
        return 0;
    }

    private static int ExtractPackageSi(string[] args)
    {
        if (args.Length != 3)
            throw new ArgumentException("extract-pkg-si requires <package.pkg> <output-dir>.");
        IReadOnlyList<string> files = ProsperoPackageArchive.ExtractSiEntries(args[1], args[2]);
        Console.WriteLine($"extracted {files.Count} SI entries");
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

        byte[] imageDigestTable = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        byte[] storedImageDigestTable =
            ProsperoImageDigests.ToStoredImageDigestTable(imageDigestTable);
        byte[] expectedStoredImageDigestTable = (byte[])imageDigestTable.Clone();
        Array.Reverse(expectedStoredImageDigestTable, 0, 32);
        Array.Reverse(expectedStoredImageDigestTable, 32, 32);
        if (!storedImageDigestTable.AsSpan().SequenceEqual(expectedStoredImageDigestTable))
            throw new InvalidDataException("imagedigs.dat per-digest byte-order conversion failed.");
        try
        {
            ProsperoImageDigests.ToStoredImageDigestTable(new byte[33]);
            throw new InvalidDataException("Invalid imagedigs.dat table length was accepted.");
        }
        catch (ArgumentException)
        {
            // Expected: the stored table consists exclusively of independent SHA3-256 values.
        }
        Console.WriteLine("selftest: imagedigs.dat digest byte order passed");

        List<ProsperoPs5MetaNode> inodeBoundaryNodes = Enumerable.Range(0, 391)
            .Select(i => new ProsperoPs5MetaNode
            {
                Inode = (uint)i,
                Mode = i == 390 ? (ushort)0x816D : (ushort)0x416D,
                Nlink = 1,
                Flags = 0x10,
                Size = 1,
                LogicalOffset = checked((ulong)i * ProsperoPs5InnerMetadata.BlockSize),
            })
            .ToList();
        byte[] inodeBoundaryMetadata = new ProsperoPs5InnerMetadata(0, 0).Build(
            inodeBoundaryNodes,
            ndblock: 4,
            [Array.Empty<byte>()]);
        int secondInodeBlock = 2 * ProsperoPs5InnerMetadata.BlockSize;
        if (inodeBoundaryMetadata.Length != 4 * ProsperoPs5InnerMetadata.BlockSize ||
            BinaryPrimitives.ReadInt64LittleEndian(inodeBoundaryMetadata.AsSpan(0x40)) != 2 ||
            BinaryPrimitives.ReadInt64LittleEndian(inodeBoundaryMetadata.AsSpan(0x58)) != 0x20000 ||
            BinaryPrimitives.ReadInt64LittleEndian(inodeBoundaryMetadata.AsSpan(0xB0)) != 2 ||
            BinaryPrimitives.ReadUInt16LittleEndian(
                inodeBoundaryMetadata.AsSpan(secondInodeBlock)) != 0x816D ||
            BinaryPrimitives.ReadUInt64LittleEndian(
                inodeBoundaryMetadata.AsSpan(secondInodeBlock + 0x60)) !=
                390UL * ProsperoPs5InnerMetadata.BlockSize ||
            !inodeBoundaryMetadata.AsSpan(
                    2 * ProsperoPs5InnerMetadata.BlockSize - 16, 16)
                .SequenceEqual(new byte[16]))
        {
            throw new InvalidDataException(
                "PPR inode table did not preserve the 390-inode block boundary.");
        }
        Console.WriteLine("selftest: multi-block PPR inode table geometry passed");

        byte[] cbcCfbPlaintext = Convert.FromHexString(
            "6BC1BEE22E409F96E93D7E117393172A" +
            "AE2D8A571E03AC9C9EB76FAC45AF8E51" +
            "30C81C46A35CE411E5FB");
        byte[] cbcCfbCiphertext = new byte[cbcCfbPlaintext.Length];
        Crypto.AesCbcCfb128Encrypt(
            cbcCfbCiphertext,
            cbcCfbPlaintext,
            cbcCfbPlaintext.Length,
            Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C"),
            Convert.FromHexString("000102030405060708090A0B0C0D0E0F"));
        byte[] expectedCbcCfb = Convert.FromHexString(
            "7649ABAC8119B246CEE98E9B12E9197D" +
            "5086CB9B507219EE95DB113A917678B2" +
            "71016FE31A6390CAF77E");
        if (!cbcCfbCiphertext.AsSpan().SequenceEqual(expectedCbcCfb))
            throw new InvalidDataException(
                $"AES-CBC-CFB128 KAT failed: {Convert.ToHexString(cbcCfbCiphertext)}");
        Crypto.AesCbcCfb128Decrypt(
            cbcCfbCiphertext,
            cbcCfbCiphertext,
            cbcCfbCiphertext.Length,
            Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C"),
            Convert.FromHexString("000102030405060708090A0B0C0D0E0F"));
        if (!cbcCfbCiphertext.AsSpan().SequenceEqual(cbcCfbPlaintext))
            throw new InvalidDataException("AES-CBC-CFB128 in-place decryption failed.");
        Console.WriteLine("selftest: AES-CBC-CFB128 residual-block KAT passed");

        byte[] checksumKat = [1, 2, 3];
        ulong weak = ProsperoNapsMeta.ComputeInputChecksum(checksumKat);
        ulong rolling = ProsperoNapsMeta.ComputeRollingHash(checksumKat);
        if (weak != 0x0000000D00000006UL || rolling != 0x00000BFFF0000006UL)
            throw new InvalidDataException(
                $"NAPS checksum KAT failed: ihsh=0x{weak:X16}, rhsh=0x{rolling:X16}");
        if (ProsperoCrc32C.Compute("123456789"u8) != 0xE3069283u)
            throw new InvalidDataException("CRC32C known-answer test failed.");
        Console.WriteLine("selftest: NAPS ihsh/rhsh and CRC32C primitive known-answer tests passed");

        var obccKatContext = new ProsperoNapsIntegrityContext
        {
            InnerImageSize = 0x10000,
            MountImage = ReadOnlyMemory<byte>.Empty,
            PhysicalInnerImage = new byte[0x10000],
            PfsImageKey = Convert.FromHexString(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            PfsImageSeed = Convert.FromHexString("000102030405060708090A0B0C0D0E0F"),
            MappingBlocks = Array.Empty<ProsperoNapsIntegrityBlock>(),
        };
        byte[] obccKat = ProsperoNapsMeta.BuildOuterBlockCheckCodes(obccKatContext);
        if (!obccKat.AsSpan().SequenceEqual(Convert.FromHexString("31E5C0F3")))
            throw new InvalidDataException(
                $"NAPS publisher-XTS obcc KAT failed: {Convert.ToHexString(obccKat)}");
        Console.WriteLine("selftest: NAPS HMAC/XTS/CRC32C obcc known-answer test passed");

        byte[] meta18 = ProsperoNapsMeta.BuildMeta18(
            0x20000,
            new byte[0x10000],
            [("selftest.bin", 1L)],
            inner: null,
            integrityProvider: new SelfTestNapsIntegrityProvider());
        byte[] plain = ProsperoNapsMeta.DecryptMeta18(meta18);
        byte[] ihsh = FindMeta18Record(plain, "ihsh");
        byte[] rhsh = FindMeta18Record(plain, "rhsh");
        byte[] obcc = FindMeta18Record(plain, "obcc");
        if (!ihsh.AsSpan(0, 8).SequenceEqual(Enumerable.Range(1, 8).Select(i => (byte)i).ToArray())
            || !rhsh.SequenceEqual(Enumerable.Range(0x11, 8).Select(i => (byte)i).ToArray())
            || !obcc.SequenceEqual(Enumerable.Range(0x21, 8).Select(i => (byte)i).ToArray()))
        {
            throw new InvalidDataException("NAPS protected-integrity provider tables were not serialized verbatim.");
        }
        Console.WriteLine("selftest: NAPS protected-integrity provider passed");

        byte[] napsStreamingInput = new byte[0x84000];
        for (int i = 0; i < napsStreamingInput.Length; i++)
            napsStreamingInput[i] = (byte)((i * 17 + (i >> 12)) & 0xFF);
        var napsStreamingOptions = new ProsperoNapsBuildOptions
        {
            CompressionLevel = 7,
            Compress = true,
            VerifyRoundTrip = true,
            FileBoundaries = [0, 0x20000, napsStreamingInput.Length],
        };
        ProsperoNapsBuildResult napsInMemory =
            ProsperoNapsImage.Pack(napsStreamingInput, napsStreamingOptions);
        using var napsLogicalStream = new MemoryStream(napsStreamingInput, writable: false);
        using var napsPackedStream = new MemoryStream();
        ProsperoNapsFileBuildResult napsFileBacked = ProsperoNapsImage.Pack(
            napsLogicalStream, napsStreamingInput.Length, napsPackedStream, napsStreamingOptions);
        if (!napsPackedStream.ToArray().AsSpan().SequenceEqual(napsInMemory.PackedImage) ||
            !napsFileBacked.LayoutBytes.AsSpan().SequenceEqual(napsInMemory.LayoutBytes) ||
            napsFileBacked.PackedSize != napsInMemory.PackedImage.LongLength)
        {
            throw new InvalidDataException(
                "File-backed and in-memory NAPS writers produced different artifacts.");
        }
        Console.WriteLine("selftest: file-backed NAPS writer matches the in-memory writer");

        const string complexGp5 = """
            <?xml version="1.0" encoding="utf-8"?>
            <psproject fmt="gp5" version="1000">
              <volume>
                <volume_type>prospero_app</volume_type>
                <package passcode="00000000000000000000000000000000"
                         entitlement_key="00112233445566778899AABBCCDDEEFF"/>
                <chunk_info chunk_count="2" scenario_count="1">
                  <chunks supported_languages="en-US ja-JP" default_language="en-US">
                    <chunk id="0" layer_no="0" languages="en-US ja-JP" label="base"/>
                    <chunk id="1" layer_no="0" languages="ja-JP" label="jp"/>
                  </chunks>
                  <scenarios default_id="0">
                    <scenario id="0" type="playmode" initial_chunk_count="1">0 1</scenario>
                  </scenarios>
                </chunk_info>
              </volume>
              <files>
                <file dst_path="sce_sys/icon0.png" src_path="icon.png"
                      content_config_label="us" chunk="0" pfs_compression="disable"/>
                <file dst_path="data/late.bin" chunk="1"/>
              </files>
            </psproject>
            """;
        using var gp5Input = new MemoryStream(Encoding.UTF8.GetBytes(complexGp5));
        Gp5Project gp5 = Gp5Project.ReadFrom(gp5Input);
        if (!gp5.VersionSpecified || !gp5.FilesSpecified ||
            gp5.Volume.Package.EntitlementKey != "00112233445566778899AABBCCDDEEFF" ||
            gp5.Volume.ChunkInfo?.ChunkSet.DefaultLanguage != "en-US" ||
            gp5.Volume.ChunkInfo.Chunks.Count != 2 ||
            gp5.Volume.ChunkInfo.Chunks[1].Languages != "ja-JP" ||
            gp5.Files.Count != 2 || !gp5.Files[0].ChunkSpecified ||
            gp5.Files[0].ContentConfigLabel != "us" ||
            gp5.Files[0].PfsCompression != "disable" ||
            gp5.Files[1].SourcePath is not null)
        {
            throw new InvalidDataException("Complex GP5 attributes were not preserved.");
        }
        using var gp5Output = new MemoryStream();
        Gp5Project.WriteTo(gp5, gp5Output);
        gp5Output.Position = 0;
        Gp5Project gp5Again = Gp5Project.ReadFrom(gp5Output);
        if (gp5Again.Volume.ChunkInfo?.Chunks.Count != 2 ||
            gp5Again.Files[0].ContentConfigLabel != "us" ||
            gp5Again.Files[1].SourcePath is not null)
            throw new InvalidDataException("Complex GP5 write/read round trip failed.");

        const string nestedGp5 = """
            <psproject fmt="gp5">
              <volume><volume_type>prospero_app</volume_type></volume>
              <rootdir src_path="root">
                <dir dst_path="dirC" virtual="true">
                  <file dst_path="fileA.txt" src_path="\fileA.txt"/>
                </dir>
              </rootdir>
            </psproject>
            """;
        using var nestedInput = new MemoryStream(Encoding.UTF8.GetBytes(nestedGp5));
        Gp5Project nested = Gp5Project.ReadFrom(nestedInput);
        if (nested.Layout != Gp5Layout.Normal ||
            nested.RootDir.Directories.Count != 1 ||
            !nested.RootDir.Directories[0].VirtualSpecified ||
            !nested.RootDir.Directories[0].Virtual ||
            nested.RootDir.Directories[0].Files.Single().SourcePath != "\\fileA.txt")
            throw new InvalidDataException("Nested rootdir GP5 mapping was not preserved.");

        const string alGp5 = """
            <psproject fmt="gp5">
              <volume>
                <volume_type>prospero_al</volume_type>
                <package passcode="00000000000000000000000000000000"
                         c_date="2024-01-02 03:04:05"
                         entitlement_key="00112233445566778899AABBCCDDEEFF"/>
              </volume>
              <files/>
            </psproject>
            """;
        using var alInput = new MemoryStream(Encoding.UTF8.GetBytes(alGp5));
        Gp5Project al = Gp5Project.ReadFrom(alInput);
        if (al.Volume.Type != Gp5VolumeType.prospero_al || al.VersionSpecified ||
            !al.FilesSpecified || al.Layout != Gp5Layout.Flat ||
            al.Volume.Package.CreationDate != "2024-01-02 03:04:05")
            throw new InvalidDataException("AL GP5 profile was not preserved.");
        Console.WriteLine("selftest: AL, PlayGo, content-config and nested-rootdir GP5 round trips passed");

        var deterministicKeys1 = new KeysEntry(
            "IV9999-UMTX11110_00-XXXXXXXXXXXXXXXX",
            "00000000000000000000000000000000",
            publisherProfile: true,
            deterministic: true);
        var deterministicKeys2 = new KeysEntry(
            "IV9999-UMTX11110_00-XXXXXXXXXXXXXXXX",
            "00000000000000000000000000000000",
            publisherProfile: true,
            deterministic: true);
        using var keys1 = new MemoryStream();
        using var keys2 = new MemoryStream();
        deterministicKeys1.Write(keys1);
        deterministicKeys2.Write(keys2);
        if (!keys1.ToArray().AsSpan().SequenceEqual(keys2.ToArray()))
            throw new InvalidDataException("Deterministic RSA-wrapped ENTRY_KEYS differ.");
        var distinctPrimaryKeys = new KeysEntry(
            "IV9999-UMTX11110_00-XXXXXXXXXXXXXXXX",
            "00000000000000000000000000000000",
            publisherProfile: true,
            deterministic: true,
            primaryId: "IV9999-UMTX11111_00-XXXXXXXXXXXXXXXX");
        using var primaryKeys = new MemoryStream();
        distinctPrimaryKeys.Write(primaryKeys);
        byte[] commonContext = keys1.ToArray();
        byte[] primaryContext = primaryKeys.ToArray();
        bool changedIndexOneDigest = false;
        bool changedIndexOneCiphertext = false;
        for (int i = 0; i < commonContext.Length; i++)
        {
            if (commonContext[i] == primaryContext[i])
                continue;
            if (i is >= 0x40 and < 0x60)
                changedIndexOneDigest = true;
            else if (i is >= 0x280 and < 0x400)
                changedIndexOneCiphertext = true;
            else
                throw new InvalidDataException(
                    $"Primary id unexpectedly changed ENTRY_KEYS at +0x{i:X}.");
        }
        if (!changedIndexOneDigest || !changedIndexOneCiphertext)
            throw new InvalidDataException(
                "Primary id did not select ENTRY_KEYS key index 1 exclusively.");
        keys1.Position = 0;
        KeysEntry parsedKeys = KeysEntry.Read(
            new MetaEntry { DataOffset = 0, DataSize = deterministicKeys1.Length }, keys1);
        if (parsedKeys.Keys.Length != 7 || parsedKeys.Keys.Any(key => key.key.Length != 384))
            throw new InvalidDataException("RSA-3072 ENTRY_KEYS width was not recovered from its record size.");
        try
        {
            KeysEntry.Read(
                new MetaEntry { DataOffset = 0, DataSize = 0x100 },
                new MemoryStream(new byte[0x100], writable: false));
            throw new InvalidDataException("A truncated ENTRY_KEYS record was accepted.");
        }
        catch (InvalidDataException e) when (e.Message.StartsWith("ENTRY_KEYS has invalid size", StringComparison.Ordinal))
        {
            // Expected structural rejection before reading the record body.
        }

        byte[] displacedPhdrElf = new byte[0x40];
        "\u007fELF"u8.CopyTo(displacedPhdrElf);
        displacedPhdrElf[4] = 2;
        BinaryPrimitives.WriteUInt64LittleEndian(displacedPhdrElf.AsSpan(0x20), 0x80);
        BinaryPrimitives.WriteUInt16LittleEndian(displacedPhdrElf.AsSpan(0x36), 0x38);
        try
        {
            ProsperoFself.MakeFself(displacedPhdrElf);
            throw new InvalidDataException("An ELF with a displaced program-header table was accepted.");
        }
        catch (ArgumentException e) when (e.Message.Contains("e_phoff", StringComparison.Ordinal))
        {
            // Expected: the FSELF header embeds ELF+PHDR as one contiguous region.
        }
        Console.WriteLine("selftest: RSA-3072 ENTRY_KEYS and FSELF structural validation passed");

        string regressionRoot = Path.Combine(
            Path.GetTempPath(), "LibProsperoPkg-selftest-" + Guid.NewGuid().ToString("N"));
        try
        {
            string source1 = Path.Combine(regressionRoot, "source1");
            string source2 = Path.Combine(regressionRoot, "source2");
            string output1 = Path.Combine(regressionRoot, "output1");
            string output2 = Path.Combine(regressionRoot, "output2");
            Directory.CreateDirectory(Path.Combine(source1, "data"));
            Directory.CreateDirectory(Path.Combine(source2, "data"));

            // Create the same tree in opposite host-enumeration order. The package writer must
            // sort by logical path, so creation order and temporary root names cannot affect bytes.
            File.WriteAllBytes(Path.Combine(source1, "data", "z.bin"), [0x5A, 0x31]);
            File.WriteAllBytes(Path.Combine(source1, "data", "a.bin"), [0x41, 0x31]);
            File.WriteAllBytes(Path.Combine(source2, "data", "a.bin"), [0x41, 0x31]);
            File.WriteAllBytes(Path.Combine(source2, "data", "z.bin"), [0x5A, 0x31]);

            byte[] compressibleInnerData = new byte[0x52000];
            for (int i = 0; i < compressibleInnerData.Length; i++)
                compressibleInnerData[i] = (byte)((i >> 8) & 7);
            IReadOnlyList<ProsperoPs5InnerFile> innerFiles =
            [
                new ProsperoPs5InnerFile
                {
                    Path = "/data/payload.bin",
                    Data = compressibleInnerData,
                },
                new ProsperoPs5InnerFile
                {
                    Path = "/sce_sys/keystone",
                    Data = Enumerable.Range(0, 96).Select(i => (byte)i).ToArray(),
                },
            ];
            var innerAssembler = new ProsperoPs5InnerImageAssembler(0, 0);
            ProsperoPs5InnerImageResult memoryInner = innerAssembler.Build(innerFiles);
            int specializedInodeBlocks = checked(
                (memoryInner.Nodes.Count + ProsperoPs5InnerMetadata.InodesPerBlock - 1) /
                ProsperoPs5InnerMetadata.InodesPerBlock);
            long specializedDataEndBlocks = checked(
                (memoryInner.DataEndLogical + ProsperoPs5InnerMetadata.BlockSize - 1) /
                ProsperoPs5InnerMetadata.BlockSize);
            int trailingMetadataOffset = checked(
                memoryInner.MetadataPlaintext.Length -
                ProsperoPs5InnerMetadata.BlockSize);
            if (memoryInner.MetaBaseLogical / ProsperoPs5InnerMetadata.BlockSize -
                    specializedDataEndBlocks != 60 ||
                BinaryPrimitives.ReadInt64LittleEndian(
                    memoryInner.MetadataPlaintext.AsSpan(0x40)) != specializedInodeBlocks ||
                memoryInner.MetadataPlaintext.LongLength !=
                    memoryInner.Ndblock * ProsperoPs5InnerMetadata.BlockSize -
                    memoryInner.MetaBaseLogical ||
                memoryInner.MetadataPlaintext.AsSpan(trailingMetadataOffset)
                    .IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidDataException(
                    "Specialized inner-image metadata reserve or inode geometry is invalid.");
            }
            string fileInnerPath = Path.Combine(regressionRoot, "file-backed-inner.dat");
            ProsperoPs5InnerImageResult fileInner =
                innerAssembler.BuildToFile(innerFiles, fileInnerPath);
            byte[] testCmacKey = Enumerable.Range(0, 16).Select(i => (byte)(0xC0 + i)).ToArray();
            if (fileInner.Image.Length != 0 ||
                fileInner.ImageLength != memoryInner.Image.LongLength ||
                !File.ReadAllBytes(fileInnerPath).AsSpan().SequenceEqual(memoryInner.Image) ||
                !ProsperoNwonlyNapsGenerator.Generate(fileInner, outerBlockCmacKey: testCmacKey)
                    .AsSpan().SequenceEqual(
                        ProsperoNwonlyNapsGenerator.Generate(
                            memoryInner, outerBlockCmacKey: testCmacKey)))
            {
                throw new InvalidDataException(
                    "File-backed and in-memory specialized inner-image assemblers differ.");
            }

            const string deterministicContentId = "IV9999-PPSA00000_00-DETERMINISTIC000";
            const string deterministicPasscode = "00000000000000000000000000000000";

            string outerPackedSource = Path.Combine(regressionRoot, "outer-source-pfs-image.dat");
            string outerLayoutSource = Path.Combine(regressionRoot, ProsperoNapsLayout.FileName);
            string outerFileBackedPath = Path.Combine(regressionRoot, "outer-file-backed.pfs");
            File.WriteAllBytes(outerPackedSource, napsInMemory.PackedImage);
            File.WriteAllBytes(outerLayoutSource, napsInMemory.LayoutBytes);
            byte[] outerSeed = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
            byte[] outerEkpfs = ProsperoPfsKeys.DeriveEkpfs(
                deterministicContentId, deterministicPasscode);
            var outerParameters = new ProsperoOuterPfsBuildParameters
            {
                Seed = outerSeed,
                TimestampSeconds = 0,
                TimestampNanoseconds = 0,
            };
            ProsperoOuterPackageImage outerInMemory = ProsperoOuterPfsBuilder.BuildForPackage(
                [
                    new ProsperoOuterFile
                    {
                        Name = "pfs_image.dat",
                        Data = napsInMemory.PackedImage,
                        SizeCompressed = napsStreamingInput.Length,
                        Signed = false,
                    },
                    new ProsperoOuterFile
                    {
                        Name = ProsperoNapsLayout.FileName,
                        Data = napsInMemory.LayoutBytes,
                        Signed = true,
                    },
                ],
                outerParameters,
                outerEkpfs);
            ProsperoOuterPackageFileResult outerFileBacked =
                ProsperoOuterPfsBuilder.BuildForPackageToFile(
                    [
                        new ProsperoOuterFileSource
                        {
                            Name = "pfs_image.dat",
                            Path = outerPackedSource,
                            SizeCompressed = napsStreamingInput.Length,
                            Signed = false,
                        },
                        new ProsperoOuterFileSource
                        {
                            Name = ProsperoNapsLayout.FileName,
                            Path = outerLayoutSource,
                            Signed = true,
                        },
                    ],
                    outerParameters,
                    outerEkpfs,
                    outerFileBackedPath);
            if (!File.ReadAllBytes(outerFileBackedPath).AsSpan()
                    .SequenceEqual(outerInMemory.Ciphertext) ||
                !outerFileBacked.ImageDigests.AsSpan().SequenceEqual(outerInMemory.ImageDigests) ||
                !outerFileBacked.SuperblockIcv.AsSpan().SequenceEqual(outerInMemory.SuperblockIcv))
            {
                throw new InvalidDataException(
                    "File-backed and in-memory outer-PFS writers produced different artifacts.");
            }

            byte[] deterministicPfsImageSeed =
                Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
            byte[] deterministicPfsImageKey =
                ProsperoPfsKeys.DerivePublisherPfsImageKey(
                    deterministicContentId, deterministicPasscode, deterministicPfsImageSeed);
            byte[] publisherEstimateKat = ProsperoPfsKeys.DerivePublisherPfsImageKey(
                "UP0006-PPSA08560_00-FULLGAMEUNLOCK00",
                deterministicPasscode,
                Convert.FromHexString("DBE696E18CCE59AC67FC923DD08FEB16"));
            if (!publisherEstimateKat.AsSpan().SequenceEqual(
                    Convert.FromHexString(
                        "D874F0A9D8D1AFA9388EEA0F4898EF9BDBFDC27824A0C1BA6864FC18E3ED7785")))
            {
                throw new InvalidDataException(
                    "Publisher pfs-image-key KDF does not match the captured sc2 2.79 estimate.");
            }
            string distinctPrimaryId = "IV9999-PPSA00001_00-DETERMINISTIC001";
            string primaryIdXml = ProsperoSiArchive.BuildPfsImageXml(
                new ProsperoPfsImageXmlOptions
                {
                    ContentId = deterministicContentId,
                    PrimaryId = distinctPrimaryId,
                });
            if (!primaryIdXml.Contains(
                    $"<primary-id>{distinctPrimaryId}</primary-id>",
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "pfsimage.xml did not preserve a primary id distinct from content id.");
            }
            byte[] deterministicPublisherImageKey =
                Enumerable.Range(0, 0x800)
                    .Select(i => (byte)((i * 29 + 7) & 0xFF))
                    .ToArray();
            byte[] deterministicPublisherEntryKeys;
            using (var entryKeysStream = new MemoryStream())
            {
                new KeysEntry(
                    deterministicContentId,
                    deterministicPasscode,
                    publisherProfile: true,
                    deterministic: true).Write(entryKeysStream);
                deterministicPublisherEntryKeys = entryKeysStream.ToArray();
            }
            ProsperoBuildResult build1 = ProsperoPackageBuilder.Build(
                new ProsperoBuildOptions
                {
                    SourceFolder = source1,
                    OutputFolder = output1,
                    ContentId = deterministicContentId,
                    TitleId = "PPSA00000",
                    Mode = ProsperoPackageMode.Application,
                    Passcode = deterministicPasscode,
                    DeterministicBuild = true,
                    NapsPfsImageSeed = deterministicPfsImageSeed,
                    PublisherImageKey = deterministicPublisherImageKey,
                    PublisherEntryKeys = deterministicPublisherEntryKeys,
                },
                _ => { });
            ProsperoBuildResult build2 = ProsperoPackageBuilder.Build(
                new ProsperoBuildOptions
                {
                    SourceFolder = source2,
                    OutputFolder = output2,
                    ContentId = deterministicContentId,
                    TitleId = "PPSA00000",
                    Mode = ProsperoPackageMode.Application,
                    Passcode = deterministicPasscode,
                    DeterministicBuild = true,
                    NapsPfsImageKey = deterministicPfsImageKey,
                    NapsPfsImageSeed = deterministicPfsImageSeed,
                    PublisherImageKey = deterministicPublisherImageKey,
                    PublisherEntryKeys = deterministicPublisherEntryKeys,
                },
                _ => { });

            try
            {
                ProsperoPackageBuilder.Build(
                    new ProsperoBuildOptions
                    {
                        SourceFolder = source1,
                        OutputFolder = Path.Combine(regressionRoot, "strict-output"),
                        ContentId = deterministicContentId,
                        TitleId = "PPSA00000",
                        Mode = ProsperoPackageMode.Application,
                        Passcode = deterministicPasscode,
                        NapsPfsImageSeed = deterministicPfsImageSeed,
                        PublisherImageKey = deterministicPublisherImageKey,
                        PublisherEntryKeys = deterministicPublisherEntryKeys,
                        RequirePublisherCompatibility = true,
                    },
                    _ => { });
                throw new InvalidDataException(
                    "Strict publisher mode accepted a build without an external signer.");
            }
            catch (InvalidOperationException ex) when (
                ex.Message.StartsWith("Strict publisher compatibility requires", StringComparison.Ordinal))
            {
                // Expected: strict mode must stop before emitting a package.
                if (ex.Message.Contains("CMAC", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(
                        "Strict publisher mode incorrectly requires a NAPS CMAC key for the " +
                        "Publishing Tools 2.79 debug/AC profile.", ex);
                if (ex.Message.Contains("obcc", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("pfs-image-key", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "Strict publisher mode incorrectly requires an external PFS image key.",
                        ex);
                }
            }

            string artifactOutput = Path.Combine(regressionRoot, "publisher-artifacts");
            ProsperoPublisherPprFileBuildResult artifacts =
                ProsperoPublisherPprBuilder.BuildFileBacked(
                    new ProsperoPublisherPprBuildOptions
                    {
                        SourceFolder = source1,
                        OutputDirectory = artifactOutput,
                        ContentId = deterministicContentId,
                        Passcode = deterministicPasscode,
                        OuterSeed = outerSeed,
                        DeterministicBuild = true,
                        TimeStamp = DateTime.UnixEpoch,
                        PfsOptions = new ProsperoPfsLayoutOptions
                        {
                            FileCompression = PfsFileCompressionMethod.Kraken,
                            CompressionLevel = PprPfsKraken.DefaultLevel,
                        },
                        NapsOptions = new ProsperoNapsBuildOptions
                        {
                            CompressionLevel = 7,
                            Compress = true,
                            VerifyRoundTrip = true,
                        },
                    },
                    _ => { });
            if (new FileInfo(artifacts.PackedImagePath).Length != artifacts.Naps.PackedSize ||
                new FileInfo(artifacts.OuterPfsPath).Length <= artifacts.Naps.PackedSize ||
                artifacts.InnerFileCount != Directory.EnumerateFiles(
                    source1, "*", SearchOption.AllDirectories).Count())
            {
                throw new InvalidDataException(
                    "File-backed publisher artifact pipeline returned inconsistent geometry: " +
                    $"packedFile={new FileInfo(artifacts.PackedImagePath).Length}, " +
                    $"packedResult={artifacts.Naps.PackedSize}, " +
                    $"outer={new FileInfo(artifacts.OuterPfsPath).Length}, " +
                    $"files={artifacts.InnerFileCount}.");
            }

            byte[] package1 = File.ReadAllBytes(build1.OutputPath);
            byte[] package2 = File.ReadAllBytes(build2.OutputPath);
            if (!package1.AsSpan().SequenceEqual(package2))
            {
                throw new InvalidDataException(
                    $"Deterministic APP/PPR-NAPS packages differ: " +
                    $"{Convert.ToHexString(ProsperoSha3.HashData(package1))} != " +
                    $"{Convert.ToHexString(ProsperoSha3.HashData(package2))}.");
            }
            ProsperoPkg parsedDeterministic = ProsperoPkgReader.Read(build1.OutputPath);
            if (parsedDeterministic.Type != ProsperoPkgType.FullDebug)
                throw new InvalidDataException("Deterministic APP regression package is not a finalized debug image.");
            ProsperoPkgEntry deterministicImageKey = parsedDeterministic.Entries.Single(
                entry => entry.RawId == 0x0020);
            ProsperoPkgEntry deterministicEntryKeys = parsedDeterministic.Entries.Single(
                entry => entry.RawId == 0x0010);
            ulong deterministicCntBase = parsedDeterministic.Fih?.EmbeddedCntOffset ?? 0;
            if (!package1.AsSpan(
                    checked((int)(deterministicCntBase + deterministicImageKey.DataOffset)),
                    checked((int)deterministicImageKey.DataSize))
                    .SequenceEqual(deterministicPublisherImageKey))
            {
                throw new InvalidDataException(
                    "Caller-supplied publisher IMAGE_KEY was not preserved verbatim.");
            }
            if (!package1.AsSpan(
                    checked((int)(deterministicCntBase + deterministicEntryKeys.DataOffset)),
                    checked((int)deterministicEntryKeys.DataSize))
                    .SequenceEqual(deterministicPublisherEntryKeys))
            {
                throw new InvalidDataException(
                    "Caller-supplied publisher ENTRY_KEYS was not preserved verbatim.");
            }
            string exportedInputsDirectory = Path.Combine(regressionRoot, "exported-publisher-inputs");
            IReadOnlyList<string> exportedInputs =
                ProsperoPublishingSidecar.ExportReusableInputs(
                    build1.OutputPath, exportedInputsDirectory);
            string exportedImageKeyPath = Path.Combine(
                exportedInputsDirectory, ProsperoPublishingSidecar.PublisherImageKeyFileName);
            string exportedEntryKeysPath = Path.Combine(
                exportedInputsDirectory, ProsperoPublishingSidecar.PublisherEntryKeysFileName);
            string exportedMeta18Path = Path.Combine(
                exportedInputsDirectory, ProsperoPublishingSidecar.NapsMeta18FileName);
            if (exportedInputs.Count != 3 ||
                !File.ReadAllBytes(exportedImageKeyPath).AsSpan()
                    .SequenceEqual(deterministicPublisherImageKey) ||
                !File.ReadAllBytes(exportedEntryKeysPath).AsSpan()
                    .SequenceEqual(deterministicPublisherEntryKeys) ||
                !File.Exists(exportedMeta18Path) ||
                File.ReadAllBytes(exportedMeta18Path).Length == 0)
            {
                throw new InvalidDataException(
                    "Publisher IMAGE_KEY/naps_meta_18 sidecar export did not preserve package inputs.");
            }
            string extractedCntDirectory = Path.Combine(regressionRoot, "extracted-cnt");
            IReadOnlyList<string> extractedCntEntries =
                ProsperoPackageArchive.ExtractCntEntries(
                    build1.OutputPath, extractedCntDirectory, includeEncrypted: false);
            if (!extractedCntEntries.Contains(".image_key", StringComparer.Ordinal) ||
                !File.ReadAllBytes(Path.Combine(extractedCntDirectory, ".image_key")).AsSpan()
                    .SequenceEqual(deterministicPublisherImageKey))
            {
                throw new InvalidDataException(
                    "Known unencrypted CNT entry names were not resolved during raw extraction.");
            }

            string streamedOuterPath = Path.Combine(regressionRoot, "outer.pfs");
            ProsperoPackageArchive.DecryptOuterPfs(
                build1.OutputPath, streamedOuterPath, deterministicPasscode);
            if (!File.ReadAllBytes(streamedOuterPath).AsSpan().SequenceEqual(
                    ProsperoPackageArchive.DecryptOuterPfs(
                        build1.OutputPath, deterministicPasscode)))
            {
                throw new InvalidDataException(
                    "Streaming and in-memory outer-PFS decryptors produced different bytes.");
            }
            ProsperoPackageMap deterministicMap =
                ProsperoPackageArchive.Inspect(build1.OutputPath);
            byte[] streamedOuter = File.ReadAllBytes(streamedOuterPath);
            int deterministicSuperblockOffset =
                checked(deterministicMap.OuterSuperblockIndex * 0x10000);
            if (!streamedOuter.AsSpan(deterministicSuperblockOffset + 0x370, 16)
                    .SequenceEqual(deterministicPfsImageSeed))
            {
                throw new InvalidDataException(
                    "NAPS pfs-image-seed was not written to outer superblock +0x370.");
            }

            string deterministicOuterFiles = Path.Combine(regressionRoot, "outer-files");
            IReadOnlyList<string> deterministicOuterPaths =
                ProsperoPackageArchive.ExtractOuterFiles(
                    build1.OutputPath, deterministicOuterFiles, deterministicPasscode);
            string physicalRelative = deterministicOuterPaths.Single(
                path => path.EndsWith("pfs_image.dat", StringComparison.Ordinal));
            string physicalPath = Path.Combine(
                deterministicOuterFiles,
                physicalRelative.Replace('/', Path.DirectorySeparatorChar));
            string deterministicSi = Path.Combine(regressionRoot, "si");
            IReadOnlyList<string> deterministicSiPaths =
                ProsperoPackageArchive.ExtractSiEntries(build1.OutputPath, deterministicSi);
            string meta18Relative = deterministicSiPaths.Single(
                path => path.EndsWith("naps_meta_18.dat", StringComparison.Ordinal));
            byte[] generatedObcc = FindMeta18Record(
                ProsperoNapsMeta.DecryptMeta18(
                    File.ReadAllBytes(Path.Combine(
                        deterministicSi,
                        meta18Relative.Replace('/', Path.DirectorySeparatorChar)))),
                "obcc");
            byte[] rebuiltObcc = ProsperoNapsMeta.BuildOuterBlockCheckCodes(
                new ProsperoNapsIntegrityContext
                {
                    InnerImageSize = checked((ulong)new FileInfo(physicalPath).Length),
                    MountImage = ReadOnlyMemory<byte>.Empty,
                    PhysicalInnerImage = ReadOnlyMemory<byte>.Empty,
                    PhysicalInnerImagePath = physicalPath,
                    PfsImageKey = deterministicPfsImageKey,
                    PfsImageSeed = deterministicPfsImageSeed,
                    MappingBlocks = Array.Empty<ProsperoNapsIntegrityBlock>(),
                });
            if (!generatedObcc.AsSpan().SequenceEqual(rebuiltObcc) ||
                generatedObcc.All(value => value == 0))
            {
                throw new InvalidDataException(
                    "The finalized SI did not preserve the generated non-zero NAPS obcc table.");
            }

            string extracted = Path.Combine(regressionRoot, "extracted");
            IReadOnlyList<string> extractedPaths = ProsperoPackageArchive.ExtractInnerFiles(
                build1.OutputPath, extracted, deterministicPasscode);
            if (!extractedPaths.Contains("data/a.bin", StringComparer.Ordinal) ||
                !extractedPaths.Contains("data/z.bin", StringComparer.Ordinal) ||
                !File.ReadAllBytes(Path.Combine(extracted, "data", "a.bin")).AsSpan()
                    .SequenceEqual(new byte[] { 0x41, 0x31 }) ||
                !File.ReadAllBytes(Path.Combine(extracted, "data", "z.bin")).AsSpan()
                    .SequenceEqual(new byte[] { 0x5A, 0x31 }) ||
                Directory.EnumerateFiles(extracted, ".libprospero-*.tmp").Any())
            {
                throw new InvalidDataException(
                    "File-backed APP/PPR-NAPS extraction did not reproduce the source tree cleanly.");
            }

            // A GP5 is authoritative for ordinary payload, but publisher AC/AL licenses are issued
            // out-of-band. Verify that decrypted license sidecars beside an otherwise explicit GP5
            // are validated, content-id matched and emitted as protected CNT ids 0x400/0x401.
            const string acContentId = "IV9999-PPSA00001_00-ACSIDECARTEST000";
            string acSource = Path.Combine(regressionRoot, "ac-sidecar-source");
            string acOutput = Path.Combine(regressionRoot, "ac-sidecar-output");
            Directory.CreateDirectory(Path.Combine(acSource, "sce_sys"));
            Directory.CreateDirectory(Path.Combine(acSource, "data"));
            File.WriteAllText(
                Path.Combine(acSource, "project.gp5"),
                $$"""
                <?xml version="1.0" encoding="utf-8"?>
                <psproject fmt="gp5" version="1000">
                  <volume>
                    <volume_type>prospero_ac</volume_type>
                    <package passcode="{{deterministicPasscode}}"
                             entitlement_key="00112233445566778899AABBCCDDEEFF"/>
                  </volume>
                  <files>
                    <file dst_path="sce_sys/param.json" src_path="sce_sys\param.json"/>
                    <file dst_path="sce_sys/nptitle.dat" src_path="sce_sys\nptitle.dat"/>
                    <file dst_path="sce_sys/npbind.dat" src_path="sce_sys\npbind.dat"/>
                    <file dst_path="data/payload.bin" src_path="data\payload.bin"/>
                  </files>
                </psproject>
                """,
                new UTF8Encoding(false));
            File.WriteAllText(
                Path.Combine(acSource, "sce_sys", "param.json"),
                "{\"conceptId\":\"10000001\",\"contentId\":\"" + acContentId +
                "\",\"contentVersion\":\"01.000.000\",\"localizedParameters\":" +
                "{\"defaultLanguage\":\"en-US\",\"en-US\":{\"titleName\":\"AC sidecar test\"}}," +
                "\"masterVersion\":\"01.00\",\"requiredSystemSoftwareVersion\":" +
                "\"0x0100000000000000\",\"titleId\":\"PPSA00001\",\"versionFileUri\":\"\"}",
                new UTF8Encoding(false));
            File.WriteAllBytes(Path.Combine(acSource, "data", "payload.bin"), [1, 2, 3, 4]);
            byte[] acContentIdBytes = Encoding.ASCII.GetBytes(acContentId);
            var licenseDat = new byte[ProsperoSystemFiles.LicenseDatSize];
            "RIF\0"u8.CopyTo(licenseDat);
            acContentIdBytes.CopyTo(licenseDat, 0x20);
            var licenseInfo = new byte[ProsperoSystemFiles.LicenseInfoSize];
            acContentIdBytes.CopyTo(licenseInfo, 0);
            Convert.FromHexString("00112233445566778899AABBCCDDEEFF")
                .CopyTo(licenseInfo, 0x30);
            File.WriteAllBytes(Path.Combine(acSource, "sce_sys", "license.dat"), licenseDat);
            File.WriteAllBytes(Path.Combine(acSource, "sce_sys", "license.info"), licenseInfo);
            byte[] nptitle = new byte[ProsperoSystemFiles.NptitleSize];
            "NPTD"u8.CopyTo(nptitle);
            BinaryPrimitives.WriteUInt32BigEndian(nptitle.AsSpan(4), 0x80);
            Encoding.ASCII.GetBytes("PPSA00001_00").CopyTo(nptitle, 0x10);
            File.WriteAllBytes(Path.Combine(acSource, "sce_sys", "nptitle.dat"), nptitle);
            byte[] npbind = new byte[ProsperoSystemFiles.NpbindSize];
            BinaryPrimitives.WriteUInt32BigEndian(
                npbind, ProsperoSystemFiles.NpbindMagic);
            BinaryPrimitives.WriteUInt32BigEndian(npbind.AsSpan(4), 1);
            BinaryPrimitives.WriteUInt32BigEndian(
                npbind.AsSpan(0x0C), ProsperoSystemFiles.NpbindSize);
            const string testCommId = "NPWR23725_00";
            BinaryPrimitives.WriteUInt16BigEndian(npbind.AsSpan(0x80), 0x0010);
            BinaryPrimitives.WriteUInt16BigEndian(
                npbind.AsSpan(0x82), checked((ushort)testCommId.Length));
            Encoding.ASCII.GetBytes(testCommId).CopyTo(npbind, 0x84);
            File.WriteAllBytes(Path.Combine(acSource, "sce_sys", "npbind.dat"), npbind);

            ProsperoBuildResult acBuild = ProsperoPackageBuilder.Build(
                new ProsperoBuildOptions
                {
                    SourceFolder = acSource,
                    OutputFolder = acOutput,
                    ContentId = acContentId,
                    TitleId = "PPSA00001",
                    Mode = ProsperoPackageMode.AdditionalContentData,
                    Passcode = deterministicPasscode,
                    UsePublisherPprNaps = true,
                    DeterministicBuild = true,
                });
            ProsperoPkg parsedAc = ProsperoPkgReader.Read(acBuild.OutputPath);
            ProsperoPkgEntry? licenseDatEntry =
                parsedAc.Entries.SingleOrDefault(entry => entry.RawId == 0x0400);
            ProsperoPkgEntry? licenseInfoEntry =
                parsedAc.Entries.SingleOrDefault(entry => entry.RawId == 0x0401);
            ProsperoPkgEntry? nptitleEntry =
                parsedAc.Entries.SingleOrDefault(entry => entry.RawId == 0x0402);
            ProsperoPkgEntry? npbindEntry =
                parsedAc.Entries.SingleOrDefault(entry => entry.RawId == 0x0403);
            if (licenseDatEntry is null || licenseInfoEntry is null ||
                nptitleEntry is null || npbindEntry is null ||
                licenseDatEntry.DataSize != ProsperoSystemFiles.LicenseDatSize ||
                licenseInfoEntry.DataSize != ProsperoSystemFiles.LicenseInfoSize ||
                licenseDatEntry.Flags1 != 0x80000000 || licenseDatEntry.Flags2 != 0x00003000 ||
                licenseInfoEntry.Flags1 != 0x80000000 || licenseInfoEntry.Flags2 != 0x00004000 ||
                nptitleEntry.Flags1 != 0x80000000 || nptitleEntry.Flags2 != 0x00003000 ||
                npbindEntry.Flags1 != 0x80000000 || npbindEntry.Flags2 != 0x00003000)
            {
                throw new InvalidDataException(
                    "GP5 AC system sidecars were not emitted with publisher CNT ids/flags.");
            }
            string acExtractedCnt = Path.Combine(regressionRoot, "ac-sidecar-extracted");
            ProsperoPackageArchive.ExtractCntEntries(
                acBuild.OutputPath, acExtractedCnt, deterministicPasscode);
            if (!File.ReadAllBytes(Path.Combine(acExtractedCnt, "nptitle.dat"))
                    .AsSpan().SequenceEqual(nptitle) ||
                !File.ReadAllBytes(Path.Combine(acExtractedCnt, "npbind.dat"))
                    .AsSpan().SequenceEqual(npbind))
            {
                throw new InvalidDataException(
                    "Encrypted nptitle.dat/npbind.dat CNT round trip changed their logical bytes.");
            }
            Console.WriteLine(
                "selftest: GP5 AC system-sidecar validation and CNT encryption passed");

            Console.WriteLine(
                "selftest: deterministic APP/PPR-NAPS build + file-backed extraction passed " +
                $"(SHA3-256 {Convert.ToHexString(ProsperoSha3.HashData(package1))})");
        }
        finally
        {
            try
            {
                if (Directory.Exists(regressionRoot))
                    Directory.Delete(regressionRoot, recursive: true);
            }
            catch
            {
                // Best-effort cleanup must not hide the regression result.
            }
        }
        return 0;
    }

    private static int SelfTestLargeOuter(string[] args)
    {
        if (args.Length != 1)
            throw new ArgumentException("selftest-large-outer takes no arguments.");

        const int directBlocks = 12;
        int indirectEntries = ProsperoOuterPfsBuilder.BlockSize / 36;
        long firstTripleBlockCount = checked(
            directBlocks + (long)indirectEntries +
            (long)indirectEntries * indirectEntries + 1);
        ProsperoOuterAddressingGeometry tripleGeometry =
            ProsperoOuterPfsBuilder.GetAddressingGeometry(firstTripleBlockCount);
        if (tripleGeometry.HighestIndirectLevel != 2 ||
            tripleGeometry.DataBlocksByIndirectLevel[0] != indirectEntries ||
            tripleGeometry.DataBlocksByIndirectLevel[1] !=
                (long)indirectEntries * indirectEntries ||
            tripleGeometry.DataBlocksByIndirectLevel[2] != 1 ||
            tripleGeometry.MetadataBlocksByIndirectLevel[0] != 1 ||
            tripleGeometry.MetadataBlocksByIndirectLevel[1] != indirectEntries + 1L ||
            tripleGeometry.MetadataBlocksByIndirectLevel[2] != 3 ||
            tripleGeometry.TotalIndirectMetadataBlocks != indirectEntries + 5L)
        {
            throw new InvalidDataException(
                "Triple-indirect outer-PFS addressing geometry is incorrect.");
        }

        int largeFileBlocks = directBlocks + indirectEntries + 1;
        long largeFileLength = checked((long)largeFileBlocks * ProsperoOuterPfsBuilder.BlockSize);
        string root = Path.Combine(
            Path.GetTempPath(), "LibProsperoPkg-large-outer-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string payloadPath = Path.Combine(root, "large.bin");
            string encryptedPath = Path.Combine(root, "outer.pfs");
            string plaintextPath = Path.Combine(root, "outer.plain.pfs");
            using (var payload = new FileStream(
                       payloadPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                payload.SetLength(largeFileLength);

            byte[] seed = Enumerable.Range(0, 16).Select(i => (byte)(0xA0 + i)).ToArray();
            byte[] ekpfs = Enumerable.Range(0, 32).Select(i => (byte)(0x20 + i)).ToArray();
            ProsperoOuterPackageFileResult result =
                ProsperoOuterPfsBuilder.BuildForPackageToFile(
                    [
                        new ProsperoOuterFileSource
                        {
                            Name = "large.bin",
                            Path = payloadPath,
                            SizeCompressed = largeFileLength,
                            Signed = false,
                        },
                    ],
                    new ProsperoOuterPfsBuildParameters
                    {
                        TimestampSeconds = 0,
                        TimestampNanoseconds = 0,
                        Seed = seed,
                    },
                    ekpfs,
                    encryptedPath);

            if (result.FileBlockCount.Length != 1 ||
                result.FileBlockCount[0] != largeFileBlocks)
                throw new InvalidDataException("Large outer-PFS block geometry is incorrect.");

            var (tweakKey, dataKey) =
                ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, seed);
            using (var encrypted = new FileStream(
                       encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                       bufferSize: 1 << 20, FileOptions.SequentialScan))
            using (var plaintext = new FileStream(
                       plaintextPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       bufferSize: 1 << 20, FileOptions.SequentialScan))
                ProsperoOuterPfsImage.Transform(
                    encrypted, plaintext, result.PfsSize,
                    tweakKey, dataKey, ProsperoOuterPfsBuilder.BlockSize,
                    result.BlockKinds, encrypt: false);

            using (var plaintext = new FileStream(
                       plaintextPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                       bufferSize: 1 << 20, FileOptions.RandomAccess))
            {
                plaintext.Position = checked(
                    (long)result.InodeTableIndex * ProsperoOuterPfsBuilder.BlockSize +
                    3 * DinodeS32.SizeOf);
                DinodeS32 inode = DinodeS32.ReadFromStream(plaintext);
                if (inode.ib[0].block <= 0 || inode.ib[1].block <= 0 ||
                    inode.ib[2].block != 0 || inode.Blocks != largeFileBlocks)
                {
                    throw new InvalidDataException(
                        "Large outer inode does not contain the expected single/double-indirect roots.");
                }
            }

            using (var plaintext = new FileStream(
                       plaintextPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                       bufferSize: 1 << 20, FileOptions.RandomAccess))
            using (var source = new LibProsperoPkg.Util.StreamReader(plaintext))
            {
                var reader = new PfsReader(
                    source,
                    superblockOffset: checked(
                        (long)result.SuperblockIndex * ProsperoOuterPfsBuilder.BlockSize),
                    encryptedDataAlreadyDecrypted: true);
                PfsReader.File file = reader.GetFile("large.bin")
                    ?? throw new InvalidDataException("Large file is absent from the rebuilt outer PFS.");
                if (file.size != largeFileLength)
                    throw new InvalidDataException("Large outer-PFS inode size is incorrect.");
                file.CopyTo(Stream.Null, decompress: false);
            }

            Console.WriteLine(
                "selftest-large-outer: serialized single/double maps and planned triple map passed " +
                $"({largeFileBlocks:N0} serialized blocks; ib[2] starts at " +
                $"{firstTripleBlockCount:N0} data blocks)");
            return 0;
        }
        finally
        {
            try
            {
                if (Directory.Exists(root))
                    Directory.Delete(root, recursive: true);
            }
            catch
            {
                // Best-effort cleanup must not hide the regression result.
            }
        }
    }

    private static byte[] FindMeta18Record(byte[] plain, string wantedTag)
    {
        for (int pos = 0; pos + 16 <= plain.Length;)
        {
            string tag = new([
                (char)plain[pos + 3],
                (char)plain[pos + 2],
                (char)plain[pos + 1],
                (char)plain[pos],
            ]);
            ulong length = BinaryPrimitives.ReadUInt64LittleEndian(plain.AsSpan(pos + 8, 8));
            if (length > int.MaxValue || pos + 16L + (long)length > plain.Length)
                throw new InvalidDataException("Malformed naps_meta_18 self-test TLV.");
            if (string.Equals(tag, wantedTag, StringComparison.Ordinal))
                return plain.AsSpan(pos + 16, (int)length).ToArray();
            pos = checked(pos + 16 + (int)length);
        }
        throw new InvalidDataException($"naps_meta_18 self-test record '{wantedTag}' was not found.");
    }

    private sealed class SelfTestNapsIntegrityProvider : IProsperoNapsIntegrityProvider
    {
        public byte[] BuildIhshPrefixes(ProsperoNapsIntegrityContext context) =>
            Enumerable.Range(1, checked(context.MappingBlocks.Count * 8)).Select(i => (byte)i).ToArray();

        public byte[] BuildRollingHashes(ProsperoNapsIntegrityContext context) =>
            Enumerable.Range(0x11, checked(context.MappingBlocks.Count * 8)).Select(i => (byte)i).ToArray();

        public byte[] BuildOuterBlockCheckCodes(ProsperoNapsIntegrityContext context) =>
            Enumerable.Range(0x21, checked(context.PhysicalInnerBlockCount * 4)).Select(i => (byte)i).ToArray();
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
        ProsperoPublisherPprFileBuildResult result = ProsperoPublisherPprBuilder.BuildFileBacked(
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
            + $"naps=0x{result.Naps.PackedSize:x} outer-superblock={result.OuterSuperblockIndex}");
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
        if (args.Length < 2)
            throw new ArgumentException("list requires <image.pfs> [--offset auto|0x0].");
        Dictionary<string, string> options = ReadOptions(args, 2);
        EnsureOnlyOptions(options, "offset");
        long superblockOffset = ResolvePfsSuperblockOffset(args[1], options);

        using var mapped = MemoryMappedFile.CreateFromFile(
            args[1], FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
        using var view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        var reader = new PfsReader(
            view, superblockOffset, encryptedDataAlreadyDecrypted: true);
        Console.WriteLine($"superblock\t0x{superblockOffset:X}");
        Console.WriteLine(
            $"pfs\tversion={reader.Header.Version} mode=0x{(ushort)reader.Header.Mode:X4} " +
            $"blocks={reader.Header.Ndblock} dinodes={reader.Header.DinodeCount} " +
            $"dinode-blocks={reader.Header.DinodeBlockCount}");
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

    private static long ResolvePfsSuperblockOffset(
        string imagePath,
        Dictionary<string, string> options)
    {
        if (options.TryGetValue("offset", out string? requested) &&
            !string.Equals(requested, "auto", StringComparison.OrdinalIgnoreCase))
            return ParseLong(requested);

        using var input = new FileStream(
            imagePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 4096, FileOptions.RandomAccess);
        Span<byte> header = stackalloc byte[0x48];
        long lastBlock = (input.Length - header.Length) & ~0xFFFFL;
        for (long offset = lastBlock; offset >= 0; offset -= 0x10000)
        {
            input.Position = offset;
            input.ReadExactly(header);
            if (BinaryPrimitives.ReadInt64LittleEndian(header) != PfsHeader.VersionPs5 ||
                BinaryPrimitives.ReadInt64LittleEndian(header[8..]) != 20130315 ||
                BinaryPrimitives.ReadUInt32LittleEndian(header[0x20..]) != 0x10000)
                continue;

            long blocks = BinaryPrimitives.ReadInt64LittleEndian(header[0x38..]);
            long dinodes = BinaryPrimitives.ReadInt64LittleEndian(header[0x30..]);
            long inodeBlocks = BinaryPrimitives.ReadInt64LittleEndian(header[0x40..]);
            if (blocks <= 0 || blocks > input.Length / 0x10000 ||
                dinodes <= 0 || inodeBlocks <= 0)
                continue;
            return offset;
        }
        throw new InvalidDataException(
            "No block-aligned PS5 PFS v2 superblock was found in the image.");
    }

    private static int InspectPfsFile(string[] args)
    {
        if (args.Length < 3)
            throw new ArgumentException(
                "inspect-file requires <image.pfs> <path> [--offset auto|0x0].");
        Dictionary<string, string> options = ReadOptions(args, 3);
        EnsureOnlyOptions(options, "offset");
        long superblockOffset = ResolvePfsSuperblockOffset(args[1], options);

        using var mapped = MemoryMappedFile.CreateFromFile(
            args[1], FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
        using var view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        var reader = new PfsReader(
            view, superblockOffset, encryptedDataAlreadyDecrypted: true);
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
            int inodesPerBlock = checked((int)pfs.BlockSize / inodeSize);
            var inode = new byte[inodeSize];
            long inodeOffset = checked(
                ((long)pfs.InodeBlockSig.StartBlock + file.ino / inodesPerBlock) * pfs.BlockSize
                + file.ino % inodesPerBlock * inodeSize);
            view.ReadArray(inodeOffset, inode, 0, inode.Length);
            Console.WriteLine($"inode.offset=0x{inodeOffset:X}");
            Console.WriteLine($"inode.mode=0x{BinaryPrimitives.ReadUInt16LittleEndian(inode.AsSpan(0x00)):X4}");
            Console.WriteLine($"inode.flags=0x{BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(0x04)):X8}");
            Console.WriteLine($"inode.size={BinaryPrimitives.ReadInt64LittleEndian(inode.AsSpan(0x08))}");
            Console.WriteLine($"inode.size_compressed={BinaryPrimitives.ReadInt64LittleEndian(inode.AsSpan(0x10))}");
            Console.WriteLine($"inode.unk1=0x{BinaryPrimitives.ReadUInt64LittleEndian(inode.AsSpan(0x50)):X16}");
            Console.WriteLine($"inode.unk2=0x{BinaryPrimitives.ReadUInt64LittleEndian(inode.AsSpan(0x58)):X16}");
            if (pfs.Mode.HasFlag(PfsMode.PprDirectOffsets))
            {
                Console.WriteLine($"inode.data_offset=0x{BinaryPrimitives.ReadUInt64LittleEndian(inode.AsSpan(0x60)):X}");
                Console.WriteLine($"inode.afid={BinaryPrimitives.ReadInt32LittleEndian(inode.AsSpan(0x68))}");
                Console.WriteLine($"inode.parent={BinaryPrimitives.ReadInt32LittleEndian(inode.AsSpan(0x6C))}");
                Console.WriteLine($"inode.dirent_offset={BinaryPrimitives.ReadInt32LittleEndian(inode.AsSpan(0x70))}");
            }
            else
            {
                Console.WriteLine($"inode.blocks={BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(0x60))}");
                Console.WriteLine($"inode.start_block={BinaryPrimitives.ReadInt32LittleEndian(inode.AsSpan(0x64))}");
            }
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
        Console.WriteLine("  build-pkg <source-dir> <output-dir> <content-id> <app|ac|al> [passcode] [naps-cmac-key-hex|-] [naps-meta-18-file|-] [metadata-private-key.pem|-] [outer-pfs-seed-hex|-] [deterministic] [strict]");
        Console.WriteLine("  pack  <input-file> <output.pfsc> [--compression zlib|kraken|none] [--level N]");
        Console.WriteLine("        [--min-savings-percent 0]");
        Console.WriteLine("  unpack <input-or-image> <output-file> [--offset 0x0]");
        Console.WriteLine("  list <image.pfs> [--offset auto|0x0]");
        Console.WriteLine("  inspect-file <image.pfs> <path> [--offset auto|0x0]");
        Console.WriteLine("  hash-flt <path> [path ...]");
        Console.WriteLine("  verify-phuc <image.phuc>");
        Console.WriteLine("  verify <source-folder> [the same build options]");
        Console.WriteLine("  inspect-naps <naps_pkg_layout.dat>");
        Console.WriteLine("  inspect-naps-meta18 <naps_meta_18.dat>");
        Console.WriteLine("  decrypt-naps-meta18 <naps_meta_18.dat> <plaintext-output>");
        Console.WriteLine("  check-naps-meta18-obcc <naps_meta_18.dat> <pfs_image.dat>");
        Console.WriteLine("  probe-publisher-obcc <package.pkg> <naps_meta_18.dat> <pfs_image.dat> [passcode]");
        Console.WriteLine("  probe-publisher-obcc <package.pkg> <naps_meta_18.dat> <pfs_image.dat> <pfs-image-key-hex> <pfs-image-seed-hex>");
        Console.WriteLine("  dump-naps <naps_pkg_layout.dat>");
        Console.WriteLine("  check-naps-cmac <naps_pkg_layout.dat> <pfs_image.dat> <16-byte-key-hex>");
        Console.WriteLine("  encode-dds <input.png> <output.dds>");
        Console.WriteLine("  roundtrip-gp5 <input.gp5> <output.gp5>");
        Console.WriteLine("  plan-naps <naps_pkg_layout.dat>");
        Console.WriteLine("  decompress-naps <pfs_image.dat> <naps_pkg_layout.dat> <output>");
        Console.WriteLine("  pack-naps <logical-pfs> <pfs_image.dat> <naps_pkg_layout.dat> [cmac-key-hex]");
        Console.WriteLine("  roundtrip-naps <input> <output>");
        Console.WriteLine("  inspect-pkg <package.pkg>");
        Console.WriteLine("  extract-pkg-outer <package.pkg> <output-dir> [passcode]");
        Console.WriteLine("  dump-pkg-outer <package.pkg> <output.pfs> [passcode]");
        Console.WriteLine("  dump-pkg-inner <package.pkg> <output.pfs> [passcode]");
        Console.WriteLine("  check-pkg-fih <package.pkg> [passcode]");
        Console.WriteLine("  check-pkg-imagedigs <package.pkg> [passcode]");
        Console.WriteLine("  check-pkg-signature <package.pkg>");
        Console.WriteLine("  resign-pkg <input.pkg> <output.pkg>");
        Console.WriteLine("  extract-pkg-inner <package.pkg> <output-dir> [passcode]");
        Console.WriteLine("  extract-pkg-cnt <package.pkg> <output-dir> [passcode]");
        Console.WriteLine("  extract-pkg-si <package.pkg> <output-dir>");
        Console.WriteLine("  export-publisher-inputs <package.pkg> <output-dir> [--overwrite]");
        Console.WriteLine("  probe-entry-crypto <package.pkg> <entry-id-hex> <passcode>");
        Console.WriteLine("  selftest");
        Console.WriteLine("  selftest-large-outer");
        Console.WriteLine("  Levels: Kraken -4..9 (default 8), zlib 0..9 (default 9).");
        Console.WriteLine("  Valid builds: ppr+kraken/none; classic+zlib/kraken/none.");
    }
}
