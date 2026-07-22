// LibProsperoPkg - publisher-profile PPR-PFS and NAPS artifact pipeline.
#nullable enable
using LibProsperoPkg.PFS.Compression;
using LibProsperoPkg.PKG;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LibProsperoPkg.PFS;

/// <summary>Inputs for the publisher-compatible PPR-PFS/NAPS/outer-PFS pipeline.</summary>
public sealed class ProsperoPublisherPprBuildOptions
{
    public required string SourceFolder { get; init; }
    public required string OutputDirectory { get; init; }
    public required string ContentId { get; init; }
    public string Passcode { get; init; } = new('0', 32);

    /// <summary>Inner direct-offset PPR-PFS options. Publisher layout is forced for this operation.</summary>
    public ProsperoPfsLayoutOptions PfsOptions { get; init; } = new();

    public ProsperoNapsBuildOptions NapsOptions { get; init; } = new();

    /// <summary>Outer-PFS seed. A random 16-byte seed is generated when omitted.</summary>
    public byte[]? OuterSeed { get; init; }

    public DateTime TimeStamp { get; init; } = DateTime.UnixEpoch;
}

/// <summary>Paths and geometry produced by <see cref="ProsperoPublisherPprBuilder.Build"/>.</summary>
public sealed class ProsperoPublisherPprBuildResult
{
    public required string InnerPfsPath { get; init; }
    public required string LogicalImagePath { get; init; }
    public required string PackedImagePath { get; init; }
    public required string NapsLayoutPath { get; init; }
    public required string OuterPfsPath { get; init; }
    public required byte[] OuterSeed { get; init; }
    public required int OuterSuperblockIndex { get; init; }
    public required int InnerFileCount { get; init; }
    /// <summary>
    /// CNT <c>imagedigs.dat</c>: one byte-reversed SHA3-256 digest for every plaintext 64-KiB
    /// outer-PFS block. This formula is byte-exact against publisher-produced packages.
    /// </summary>
    public required byte[] ImageDigests { get; init; }
    /// <summary>SHA3-256 of the complete uncompressed logical PPR-PFS stream (FIH slot 0xB0).</summary>
    public required byte[] LogicalImageDigest { get; init; }
    public required ProsperoNapsBuildResult Naps { get; init; }
}

/// <summary>
/// Builds the publisher PPR path through all filesystem layers, stopping immediately before the
/// CNT/FIH container stage. The logical NAPS stream begins with the ten-byte PFS version marker,
/// pads to 4 MiB, and places the direct-offset PPR-PFS superblock at logical offset 0x400000.
/// </summary>
public static class ProsperoPublisherPprBuilder
{
    public const int NestedPfsOffset = 0x400000;
    public static ReadOnlySpan<byte> PfsVersion => "01.000.000"u8;

    public static ProsperoPublisherPprBuildResult Build(
        ProsperoPublisherPprBuildOptions options, Action<string>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.SourceFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.OutputDirectory);
        if (!Directory.Exists(options.SourceFolder))
            throw new DirectoryNotFoundException(options.SourceFolder);
        if (options.ContentId.Length != 36)
            throw new ArgumentException("Content id must be exactly 36 characters.", nameof(options));
        if (options.Passcode.Length != 32)
            throw new ArgumentException("Passcode must be exactly 32 characters.", nameof(options));
        if (options.OuterSeed is { Length: not 16 })
            throw new ArgumentException("Outer seed must be exactly 16 bytes.", nameof(options));

        Action<string> log = logger ?? (_ => { });
        string output = Path.GetFullPath(options.OutputDirectory);
        Directory.CreateDirectory(output);
        string innerPath = Path.Combine(output, "inner.ppr-pfs");
        string logicalPath = Path.Combine(output, "logical.ppr-pfs");
        string packedPath = Path.Combine(output, "pfs_image.dat");
        string layoutPath = Path.Combine(output, ProsperoNapsLayout.FileName);
        string outerPath = Path.Combine(output, "outer.pfs");

        ProsperoPfsLayoutOptions pfs = options.PfsOptions;
        bool savedPublisher = pfs.UsePublisherPprLayout;
        bool savedFilter = pfs.FilterOuterPackageEntries;
        ProsperoPfsLayoutResult inner;
        try
        {
            pfs.UsePublisherPprLayout = true;
            pfs.FilterOuterPackageEntries = true;
            log("Building publisher direct-offset PPR-PFS...");
            inner = ProsperoPfsLayout.BuildFromFolder(options.SourceFolder, innerPath, pfs, log);
        }
        finally
        {
            pfs.UsePublisherPprLayout = savedPublisher;
            pfs.FilterOuterPackageEntries = savedFilter;
        }

        if (inner.ImageSize > Array.MaxLength - NestedPfsOffset)
            throw new InvalidDataException("Publisher logical image exceeds the in-memory builder limit.");
        byte[] innerBytes = File.ReadAllBytes(innerPath);
        byte[] logical = BuildLogicalImage(innerBytes);
        File.WriteAllBytes(logicalPath, logical);

        log("Packing the logical PPR-PFS stream as NAPS...");
        ProsperoNapsBuildOptions requestedNaps = options.NapsOptions;
        var napsOptions = new ProsperoNapsBuildOptions
        {
            CompressionLevel = requestedNaps.CompressionLevel,
            Compress = requestedNaps.Compress,
            VerifyRoundTrip = requestedNaps.VerifyRoundTrip,
            OuterBlockCmacKey = requestedNaps.OuterBlockCmacKey,
            FileBoundaries = new long[] { 0, PfsVersion.Length, NestedPfsOffset, logical.Length },
        };
        ProsperoNapsBuildResult naps = ProsperoNapsImage.Pack(logical, napsOptions);
        File.WriteAllBytes(packedPath, naps.PackedImage);
        File.WriteAllBytes(layoutPath, naps.LayoutBytes);

        byte[] seed = options.OuterSeed?.AsSpan().ToArray() ?? RandomNumberGenerator.GetBytes(16);
        long unixSeconds = new DateTimeOffset(options.TimeStamp.ToUniversalTime()).ToUnixTimeSeconds();
        var parameters = new ProsperoOuterPfsBuildParameters
        {
            Seed = seed,
            TimestampSeconds = unixSeconds,
            TimestampNanoseconds = 0,
        };
        var outerFiles = new ProsperoOuterFile[]
        {
            new()
            {
                Name = "pfs_image.dat",
                Data = naps.PackedImage,
                SizeCompressed = logical.Length,
                Signed = false,
            },
            new()
            {
                Name = ProsperoNapsLayout.FileName,
                Data = naps.LayoutBytes,
                SizeCompressed = naps.LayoutBytes.Length,
                Signed = true,
            },
        };

        log("Building and encrypting the data-first outer PFS...");
        ProsperoOuterPfsBuildResult outer = ProsperoOuterPfsBuilder.BuildPlaintext(outerFiles, parameters);
        byte[] plaintext = outer.Plaintext.AsSpan().ToArray();
        byte[] imageDigests = BuildImageDigests(plaintext);
        byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(options.ContentId, options.Passcode);
        var keys = ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, seed);
        ProsperoOuterPfsBuilder.Encrypt(outer, keys.TweakKey, keys.DataKey);
        File.WriteAllBytes(outerPath, outer.Plaintext);

        // Verify both reversible transforms and the inner filesystem view before returning artifacts.
        byte[] decrypted = outer.Plaintext.AsSpan().ToArray();
        ProsperoOuterPfsImage.Transform(
            decrypted, keys.TweakKey, keys.DataKey, ProsperoOuterPfsBuilder.BlockSize,
            outer.BlockKinds, encrypt: false);
        if (!decrypted.AsSpan().SequenceEqual(plaintext))
            throw new InvalidDataException("Outer PFS AES-XTS round-trip failed.");
        int innerFileCount = ValidateInner(logical);

        return new ProsperoPublisherPprBuildResult
        {
            InnerPfsPath = innerPath,
            LogicalImagePath = logicalPath,
            PackedImagePath = packedPath,
            NapsLayoutPath = layoutPath,
            OuterPfsPath = outerPath,
            OuterSeed = seed,
            OuterSuperblockIndex = outer.SuperblockIndex,
            InnerFileCount = innerFileCount,
            ImageDigests = imageDigests,
            LogicalImageDigest = ProsperoImageDigests.Sha3_256(logical),
            Naps = naps,
        };
    }

    private static byte[] BuildImageDigests(byte[] plaintext)
    {
        if (plaintext.Length % ProsperoOuterPfsBuilder.BlockSize != 0)
            throw new InvalidDataException("Outer PFS is not block aligned.");
        int blocks = plaintext.Length / ProsperoOuterPfsBuilder.BlockSize;
        var result = new byte[checked(blocks * 32)];
        for (int block = 0; block < blocks; block++)
        {
            byte[] digest = ProsperoOuterPfsSignature.ComputeBlockHash(
                plaintext.AsSpan(block * ProsperoOuterPfsBuilder.BlockSize, ProsperoOuterPfsBuilder.BlockSize));
            Array.Reverse(digest);
            digest.CopyTo(result, block * 32);
        }
        return result;
    }

    private static int ValidateInner(byte[] logical)
    {
        using var memory = new MemoryStream(logical, writable: false);
        using var source = new LibProsperoPkg.Util.StreamReader(memory);
        var reader = new PfsReader(
            source, superblockOffset: NestedPfsOffset, encryptedDataAlreadyDecrypted: true);
        PfsReader.File[] files = reader.GetAllFiles().ToArray();
        foreach (PfsReader.File file in files)
            file.CopyTo(Stream.Null, decompress: true);
        int count = files.Length;
        return count;
    }

    private static byte[] BuildLogicalImage(byte[] standalone)
    {
        using var input = new MemoryStream(standalone, writable: false);
        PfsHeader header = PfsHeader.ReadFromStream(input);
        if (header.BlockSize != 0x10000 || header.Mode.HasFlag(PfsMode.Signed))
            throw new InvalidDataException("Publisher relocation requires an unsigned 64-KiB PFS image.");
        int baseBlock = NestedPfsOffset / checked((int)header.BlockSize);
        long oldInodeBlock = header.InodeBlockSig.StartBlock;
        if (oldInodeBlock < 0 || oldInodeBlock > standalone.Length / header.BlockSize)
            throw new InvalidDataException("Standalone PFS has an invalid inode-table block.");

        var logical = new byte[checked(NestedPfsOffset + standalone.Length)];
        PfsVersion.CopyTo(logical);
        standalone.CopyTo(logical, NestedPfsOffset);

        header.Mode |= PfsMode.PprDirectOffsets;
        header.Ndblock = checked(header.Ndblock + baseBlock);
        for (int i = 0; i < header.InodeBlockSig.db.Length; i++)
        {
            long block = header.InodeBlockSig.db[i].block;
            if (block > 0)
                header.InodeBlockSig.db[i].block = checked(block + baseBlock);
        }
        using (var output = new MemoryStream(logical, writable: true))
        {
            output.Position = NestedPfsOffset;
            header.WriteToStream(output);

            input.Position = checked(oldInodeBlock * header.BlockSize);
            output.Position = checked((oldInodeBlock + baseBlock) * header.BlockSize);
            for (long index = 0; index < header.DinodeCount; index++)
            {
                DinodeD32 legacy = DinodeD32.ReadFromStream(input);
                var direct = new DinodePpr
                {
                    Mode = legacy.Mode,
                    Nlink = legacy.Nlink,
                    Flags = legacy.Flags,
                    Size = legacy.Size,
                    SizeCompressed = legacy.SizeCompressed,
                    Time1_sec = legacy.Time1_sec,
                    Time2_sec = legacy.Time2_sec,
                    Time3_sec = legacy.Time3_sec,
                    Time4_sec = legacy.Time4_sec,
                    Time1_nsec = legacy.Time1_nsec,
                    Time2_nsec = legacy.Time2_nsec,
                    Time3_nsec = legacy.Time3_nsec,
                    Time4_nsec = legacy.Time4_nsec,
                    Uid = legacy.Uid,
                    Gid = legacy.Gid,
                    Unk1 = legacy.Unk1,
                    Unk2 = legacy.Unk2,
                    Blocks = legacy.Blocks,
                    DataOffset = checked((long)(legacy.StartBlock + baseBlock) * header.BlockSize),
                };
                direct.WriteToStream(output);
            }
        }
        return logical;
    }
}
