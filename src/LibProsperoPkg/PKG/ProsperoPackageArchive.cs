// LibProsperoPkg - complete structural access to finalized Prospero packages.
#nullable enable
using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using LibProsperoPkg.Util;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LibProsperoPkg.PKG;

public readonly record struct ProsperoPackageMap(
    long FihOffset, long FihSize,
    long OuterPfsOffset, long OuterPfsSize,
    long CntOffset, long CntSize,
    long SupplementOffset, long SupplementSize,
    int OuterSuperblockIndex);

/// <summary>
/// Splits, decrypts and extracts finalized debug packages. Container parsing is independent of
/// protected transformations; outer-PFS decryption requires the package passcode.
/// </summary>
public static class ProsperoPackageArchive
{
    public const int OuterBlockSize = 0x10000;

    public static ProsperoPackageMap Inspect(string path)
    {
        using var input = File.OpenRead(path);
        return Inspect(input);
    }

    public static ProsperoPackageMap Inspect(Stream input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!input.CanRead || !input.CanSeek) throw new ArgumentException("Package stream must be readable and seekable.", nameof(input));
        ProsperoPkg package = ProsperoPkgReader.Read(input);
        ProsperoFihHeader fih = package.Fih ?? throw new InvalidDataException("A finalized FIH package is required.");
        if (fih.PfsImageOffset > long.MaxValue || fih.PfsImageSize > long.MaxValue || fih.EmbeddedCntOffset > long.MaxValue)
            throw new InvalidDataException("Package ranges exceed Int64.");
        long pfsOffset = (long)fih.PfsImageOffset;
        long pfsSize = (long)fih.PfsImageSize;
        long cntOffset = (long)fih.EmbeddedCntOffset;
        RequireRange(input.Length, pfsOffset, pfsSize, "outer PFS");
        if (cntOffset != checked(pfsOffset + pfsSize))
            throw new InvalidDataException("FIH CNT offset does not immediately follow the outer PFS image.");

        long cntEnd = ProsperoPkgLayout.HeaderSize;
        ProsperoPkgHeader cnt = package.Header ?? throw new InvalidDataException("Embedded CNT header is unavailable.");
        cntEnd = Math.Max(cntEnd, checked((long)cnt.EntryTableOffset + package.Entries.Count * ProsperoPkgLayout.EntryMetaSize));
        if (cnt.BodyOffset > long.MaxValue || cnt.BodySize > long.MaxValue) throw new InvalidDataException("CNT body range exceeds Int64.");
        cntEnd = Math.Max(cntEnd, checked((long)cnt.BodyOffset + (long)cnt.BodySize));
        foreach (ProsperoPkgEntry entry in package.Entries)
            cntEnd = Math.Max(cntEnd, checked((long)entry.DataOffset + entry.DataSize));
        cntEnd = AlignUp(cntEnd, 16);
        RequireRange(input.Length, cntOffset, cntEnd, "CNT");

        long supplement = checked(cntOffset + cntEnd);
        int superblock = ResolveSuperblockIndex(fih, checked((int)(pfsSize / OuterBlockSize)));
        return new ProsperoPackageMap(0, pfsOffset, pfsOffset, pfsSize, cntOffset, cntEnd,
            supplement, input.Length - supplement, superblock);
    }

    public static void Split(Stream input, Stream outerPfs, Stream cnt, Stream? supplement = null)
    {
        ProsperoPackageMap map = Inspect(input);
        CopyRange(input, outerPfs, map.OuterPfsOffset, map.OuterPfsSize);
        CopyRange(input, cnt, map.CntOffset, map.CntSize);
        if (supplement is not null) CopyRange(input, supplement, map.SupplementOffset, map.SupplementSize);
    }

    public static byte[] DecryptOuterPfs(string packagePath, string passcode)
    {
        using var input = File.OpenRead(packagePath);
        ProsperoPkg package = ProsperoPkgReader.Read(input);
        ProsperoFihHeader fih = package.Fih ?? throw new InvalidDataException("A finalized FIH package is required.");
        ProsperoPkgHeader cnt = package.Header ?? throw new InvalidDataException("Embedded CNT header is unavailable.");
        ProsperoPackageMap map = Inspect(input);
        if (map.OuterPfsSize > int.MaxValue) throw new InvalidDataException("Outer PFS is too large for the in-memory decryptor.");
        byte[] image = ReadRange(input, map.OuterPfsOffset, checked((int)map.OuterPfsSize));
        int blocks = image.Length / OuterBlockSize;
        if (blocks * OuterBlockSize != image.Length) throw new InvalidDataException("Outer PFS is not block aligned.");
        int superblock = map.OuterSuperblockIndex;
        ReadOnlySpan<byte> sb = image.AsSpan(superblock * OuterBlockSize, OuterBlockSize);
        ValidateSuperblockShape(sb, blocks);
        byte[] seed = sb.Slice(0x370, 16).ToArray();
        byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(cnt.ContentId, passcode);
        var (tweak, data) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, seed);
        ProsperoOuterBlockKind[] kinds = InferBlockKinds(fih, blocks, superblock);
        ProsperoOuterPfsImage.Transform(image, tweak, data, OuterBlockSize, kinds, encrypt: false);
        byte[] expectedIcv = image.AsSpan(superblock * OuterBlockSize + ProsperoOuterPfsSignature.SuperblockIcvOffset, 32).ToArray();
        byte[] actualIcv = ProsperoOuterPfsSignature.ComputeSuperblockIcv(image.AsSpan(superblock * OuterBlockSize, OuterBlockSize));
        if (!expectedIcv.AsSpan().SequenceEqual(actualIcv)) throw new InvalidDataException("Outer PFS superblock ICV mismatch.");
        return image;
    }

    public static IReadOnlyList<string> ExtractOuterFiles(string packagePath, string outputDirectory, string passcode, bool decompress = false)
    {
        byte[] image = DecryptOuterPfs(packagePath, passcode);
        ProsperoPkg package = ProsperoPkgReader.Read(packagePath);
        int superblock = ResolveSuperblockIndex(package.Fih!, image.Length / OuterBlockSize);
        using var memory = new MemoryStream(image, writable: false);
        using var source = new LibProsperoPkg.Util.StreamReader(memory);
        var pfs = new PfsReader(source, superblockOffset: (long)superblock * OuterBlockSize, encryptedDataAlreadyDecrypted: true);
        Directory.CreateDirectory(outputDirectory);
        var written = new List<string>();
        foreach (PfsReader.File file in pfs.GetAllFiles())
        {
            string relative = NormalizeRelativePath(file.FullName);
            string target = SafeTarget(outputDirectory, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            file.Save(target, decompress);
            written.Add(relative);
        }
        return written;
    }

    /// <summary>
    /// Decrypts the outer filesystem, resolves its NAPS sidecar and expands <c>pfs_image.dat</c> to
    /// the complete logical inner PPR-PFS image.
    /// </summary>
    public static byte[] DecodeInnerPfs(string packagePath, string passcode)
    {
        byte[] outerImage = DecryptOuterPfs(packagePath, passcode);
        ProsperoPkg package = ProsperoPkgReader.Read(packagePath);
        int outerSuperblock = ResolveSuperblockIndex(package.Fih!, outerImage.Length / OuterBlockSize);
        using var memory = new MemoryStream(outerImage, writable: false);
        using var source = new LibProsperoPkg.Util.StreamReader(memory);
        var outer = new PfsReader(
            source,
            superblockOffset: (long)outerSuperblock * OuterBlockSize,
            encryptedDataAlreadyDecrypted: true);
        PfsReader.File packedImage = FindFile(outer, "pfs_image.dat");
        PfsReader.File layoutFile = FindFile(outer, ProsperoNapsLayout.FileName);
        byte[] packed = packedImage.ReadAllBytes();
        NapsLayoutDocument layout = ProsperoNapsLayout.Parse(layoutFile.ReadAllBytes());
        using var packedStream = new MemoryStream(packed, writable: false);
        using var logical = new MemoryStream();
        ProsperoNapsImage.Decompress(packedStream, layout, logical);
        return logical.ToArray();
    }

    /// <summary>Extracts every file from the NAPS-decoded inner PPR-PFS image.</summary>
    public static IReadOnlyList<string> ExtractInnerFiles(
        string packagePath, string outputDirectory, string passcode, bool decompressFiles = true)
    {
        byte[] innerImage = DecodeInnerPfs(packagePath, passcode);
        int superblockOffset = ProsperoImageDigests.LocateSuperblock(innerImage);
        if (superblockOffset < 0)
            throw new InvalidDataException("The NAPS logical stream does not contain an inner PPR-PFS superblock.");
        using var memory = new MemoryStream(innerImage, writable: false);
        using var source = new LibProsperoPkg.Util.StreamReader(memory);
        var inner = new PfsReader(source, superblockOffset: superblockOffset, encryptedDataAlreadyDecrypted: true);
        Directory.CreateDirectory(outputDirectory);
        var written = new List<string>();
        foreach (PfsReader.File file in inner.GetAllFiles())
        {
            string relative = NormalizeRelativePath(file.FullName);
            string target = SafeTarget(outputDirectory, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            file.Save(target, decompressFiles);
            written.Add(relative);
        }
        return written;
    }

    public static IReadOnlyList<string> ExtractCntEntries(string packagePath, string outputDirectory, bool includeEncrypted = true)
    {
        using var input = File.OpenRead(packagePath);
        ProsperoPkg package = ProsperoPkgReader.Read(input);
        long cntBase = package.Fih is null ? 0 : checked((long)package.Fih.EmbeddedCntOffset);
        Directory.CreateDirectory(outputDirectory);
        var written = new List<string>();
        foreach (ProsperoPkgEntry entry in package.Entries)
        {
            if (!includeEncrypted && entry.Encrypted) continue;
            string name = string.IsNullOrWhiteSpace(entry.Name) ? $"entry-{entry.RawId:x8}.bin" : NormalizeRelativePath(entry.Name!);
            string target = SafeTarget(outputDirectory, name);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            byte[] data = ReadRange(input, checked(cntBase + entry.DataOffset), checked((int)entry.DataSize));
            File.WriteAllBytes(target, data);
            written.Add(name);
        }
        return written;
    }

    private static ProsperoOuterBlockKind[] InferBlockKinds(ProsperoFihHeader fih, int blocks, int superblock)
    {
        var kinds = Enumerable.Repeat(ProsperoOuterBlockKind.Signed, blocks).ToArray();
        int plainDataBlocks = checked((int)fih.InnerImageBlockCount);
        if (plainDataBlocks > superblock) throw new InvalidDataException("FIH inner-image block count crosses the superblock.");
        for (int i = 0; i < plainDataBlocks; i++) kinds[i] = ProsperoOuterBlockKind.Data;
        kinds[superblock] = ProsperoOuterBlockKind.Plaintext;
        return kinds;
    }

    private static int ResolveSuperblockIndex(ProsperoFihHeader fih, int blocks)
    {
        long napsBlocks = checked(((long)fih.NapsLayoutSize + OuterBlockSize - 1) / OuterBlockSize);
        long index = checked((long)fih.InnerImageBlockCount + napsBlocks);
        if (index < 0 || index >= blocks) throw new InvalidDataException("FIH-derived outer superblock index is out of range.");
        return (int)index;
    }

    private static PfsReader.File FindFile(PfsReader pfs, string name)
    {
        PfsReader.File? result = pfs.GetAllFiles().FirstOrDefault(
            file => string.Equals(Path.GetFileName(file.FullName), name, StringComparison.Ordinal));
        return result ?? throw new InvalidDataException($"Outer PFS does not contain {name}.");
    }

    private static void ValidateSuperblockShape(ReadOnlySpan<byte> sb, int blocks)
    {
        ulong version = BinaryPrimitives.ReadUInt64LittleEndian(sb);
        ulong compatibility = BinaryPrimitives.ReadUInt64LittleEndian(sb[8..]);
        uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(sb[0x20..]);
        ulong blockCount = BinaryPrimitives.ReadUInt64LittleEndian(sb[0x38..]);
        if (version is not (1 or 2) || compatibility <= 0x01332A0A || blockSize != OuterBlockSize || blockCount != (ulong)blocks)
            throw new InvalidDataException("FIH-derived block is not a valid outer PPR-PFS superblock.");
    }

    private static string NormalizeRelativePath(string value)
    {
        string normalized = value.Replace('\\', '/').TrimStart('/');
        if (normalized.Length == 0 || normalized.Split('/').Any(p => p is "" or "." or ".."))
            throw new InvalidDataException($"Unsafe package path: {value}");
        return normalized;
    }

    private static string SafeTarget(string root, string relative)
    {
        string fullRoot = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        string target = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!target.StartsWith(fullRoot, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidDataException($"Package path escapes output directory: {relative}");
        return target;
    }

    private static byte[] ReadRange(Stream input, long offset, int size)
    {
        RequireRange(input.Length, offset, size, "stream range");
        byte[] result = new byte[size];
        input.Position = offset;
        input.ReadExactly(result);
        return result;
    }

    private static void CopyRange(Stream input, Stream output, long offset, long size)
    {
        RequireRange(input.Length, offset, size, "stream range");
        input.Position = offset;
        byte[] buffer = new byte[1024 * 1024];
        while (size != 0)
        {
            int requested = (int)Math.Min(buffer.Length, size);
            int read = input.Read(buffer, 0, requested);
            if (read == 0) throw new EndOfStreamException();
            output.Write(buffer, 0, read);
            size -= read;
        }
    }

    private static void RequireRange(long length, long offset, long size, string name)
    {
        if (offset < 0 || size < 0 || offset > length || size > length - offset)
            throw new InvalidDataException($"{name} lies outside the package.");
    }

    private static long AlignUp(long value, int alignment) => checked((value + alignment - 1) / alignment * alignment);
}
