// LibProsperoPkg - NAPS streaming-image planner and decoder.
#nullable enable
using LibProsperoPkg.PFS.Compression.Oodle;
using LibProsperoPkg.PKG;
using System;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.PFS.Compression;

/// <summary>One decoded normal <c>CblockInfo</c> span.</summary>
public readonly record struct ProsperoNapsSpan(
    int Index,
    int CblockInfoIndex,
    long CompressedOffset,
    int CompressedLength,
    int FirstChunkCompressedLength,
    long StoredOffset,
    long UncompressedOffset,
    int UncompressedLength,
    uint TweakIndex,
    byte KeyTableIndex,
    byte Even,
    byte Odd,
    byte KdePredictor,
    byte ShuffleIndex);

/// <summary>Logical file range described by the NAPS fidx boundary table.</summary>
public readonly record struct ProsperoNapsLogicalFile(
    int Index, byte Type, long UncompressedOffset, long Length);

/// <summary>
/// Fully resolved view of the NAPS boundary tables. It is the managed equivalent of the span,
/// ublock and file-view construction performed by <c>ric.exe</c> before image verification.
/// </summary>
public sealed class ProsperoNapsPlan
{
    public required IReadOnlyList<ProsperoNapsSpan> Spans { get; init; }
    public required IReadOnlyList<ProsperoNapsLogicalFile> Files { get; init; }
    public required long UncompressedSize { get; init; }
}

/// <summary>Resolves and decodes <c>pfs_image.dat</c> using <c>naps_pkg_layout.dat</c>.</summary>
public static class ProsperoNapsImage
{
    public const int UBlockSize = 0x40000;
    public const int OuterBlockSize = 0x10000;

    /// <summary>Builds and strictly validates the compressed-span graph.</summary>
    public static ProsperoNapsPlan BuildPlan(NapsLayoutDocument layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        if (layout.FileOffsets.Count < 1)
            throw new InvalidDataException("NAPS layout has no terminal file boundary.");

        var files = new List<ProsperoNapsLogicalFile>(layout.FileOffsets.Count - 1);
        for (int i = 0; i + 1 < layout.FileOffsets.Count; i++)
        {
            NapsFileOffsetEntry current = layout.FileOffsets[i];
            NapsFileOffsetEntry next = layout.FileOffsets[i + 1];
            if (next.UncompressedOffsetStart < current.UncompressedOffsetStart)
                throw new InvalidDataException($"NAPS file boundary {i + 1} moves backwards.");
            files.Add(new ProsperoNapsLogicalFile(
                i,
                current.Type,
                checked((long)current.UncompressedOffsetStart),
                checked((long)(next.UncompressedOffsetStart - current.UncompressedOffsetStart))));
        }

        var spans = new List<ProsperoNapsSpan>();
        ProsperoNapsSpan? previous = null;

        foreach (ProsperoNapsLogicalFile file in files)
        {
            if ((file.Type & 0x40) != 0)
            {
                if (previous is null)
                    throw new InvalidDataException($"NAPS continuation file {file.Index} has no preceding span.");
                continue;
            }

            long position = file.UncompressedOffset;
            long remaining = file.Length;
            int cblockIndex = ResolveCblockInfoIndex(layout, position);
            while (remaining != 0)
            {
                if ((uint)cblockIndex >= (uint)layout.CblockInfos.Count)
                    throw new InvalidDataException($"NAPS file {file.Index} runs past CblockInfo.");
                NapsCblockInfoEntry current = layout.CblockInfos[cblockIndex];
                if (current.IsRunBase)
                {
                    cblockIndex++;
                    continue;
                }
                if (current.IsTerminal)
                    throw new InvalidDataException($"NAPS file {file.Index} reaches the terminal boundary early.");

                int immediateNextIndex = checked(cblockIndex + 1);
                if ((uint)immediateNextIndex >= (uint)layout.CblockInfos.Count)
                    throw new InvalidDataException("NAPS normal CblockInfo has no following boundary.");
                NapsCblockInfoEntry immediateNext = layout.CblockInfos[immediateNextIndex];
                int logicalNextIndex = immediateNext.IsRunBase
                    ? checked(immediateNextIndex + 1)
                    : immediateNextIndex;
                if ((uint)logicalNextIndex >= (uint)layout.CblockInfos.Count)
                    throw new InvalidDataException("NAPS run-base has no following logical boundary.");
                NapsCblockInfoEntry logicalNext = layout.CblockInfos[logicalNextIndex];

                int compressedLength = Delta18(
                    immediateNext.IsRunBase ? immediateNext.CoffsetEndMod256K : immediateNext.CoffsetStartMod256K,
                    current.CoffsetStartMod256K);
                int uncompressedLength = Delta18(logicalNext.UoffsetStart, current.UoffsetStart);
                if (compressedLength <= 0 || uncompressedLength <= 0 || uncompressedLength > UBlockSize)
                    throw new InvalidDataException($"NAPS span at CblockInfo {cblockIndex} has invalid lengths.");
                if (uncompressedLength > remaining)
                    throw new InvalidDataException($"NAPS span at CblockInfo {cblockIndex} crosses file {file.Index}.");

                long compressedOffset;
                uint tweak;
                byte key;
                if (cblockIndex > 0 && layout.CblockInfos[cblockIndex - 1].IsRunBase)
                {
                    NapsCblockInfoEntry run = layout.CblockInfos[cblockIndex - 1];
                    compressedOffset = checked(((long)run.CoffsetStart256K << 18) | current.CoffsetStartMod256K);
                    tweak = run.TweakIdxStart;
                    key = run.KeyTableIdx;
                }
                else if (previous is ProsperoNapsSpan prior)
                {
                    compressedOffset = checked(prior.CompressedOffset + prior.CompressedLength);
                    long blockDelta = (compressedOffset >> 16) - (prior.CompressedOffset >> 16);
                    tweak = checked((uint)(prior.TweakIndex + blockDelta));
                    key = prior.KeyTableIndex;
                }
                else
                {
                    throw new InvalidDataException("The first NAPS span is not preceded by a run-base.");
                }

                long storedOffset = checked((long)tweak * OuterBlockSize + (compressedOffset & 0xFFFF));
                var span = new ProsperoNapsSpan(
                    spans.Count,
                    cblockIndex,
                    compressedOffset,
                    compressedLength,
                    checked((int)current.ClenEvenMinus1 + 1),
                    storedOffset,
                    position,
                    uncompressedLength,
                    tweak,
                    key,
                    current.Even,
                    current.Odd,
                    current.KdePredictor,
                    current.ShuffleIdx);
                spans.Add(span);
                previous = span;
                position += uncompressedLength;
                remaining -= uncompressedLength;
                cblockIndex++;
            }
        }

        int expectedSpans = 0;
        foreach (NapsCblockInfoEntry entry in layout.CblockInfos)
            if (!entry.IsRunBase && !entry.IsTerminal)
                expectedSpans++;
        if (spans.Count != expectedSpans)
            throw new InvalidDataException($"NAPS span graph used {spans.Count} of {expectedSpans} normal entries.");

        return new ProsperoNapsPlan
        {
            Spans = spans,
            Files = files,
            UncompressedSize = checked((long)layout.FileOffsets[^1].UncompressedOffsetStart),
        };
    }

    /// <summary>Decompresses the complete logical stream to a seekable destination.</summary>
    public static void Decompress(Stream pfsImage, NapsLayoutDocument layout, Stream destination)
    {
        ArgumentNullException.ThrowIfNull(pfsImage);
        ArgumentNullException.ThrowIfNull(destination);
        if (!pfsImage.CanRead || !pfsImage.CanSeek)
            throw new ArgumentException("NAPS pfs_image stream must be readable and seekable.", nameof(pfsImage));
        if (!destination.CanWrite || !destination.CanSeek)
            throw new ArgumentException("NAPS output stream must be writable and seekable.", nameof(destination));

        ProsperoNapsPlan plan = BuildPlan(layout);
        destination.SetLength(plan.UncompressedSize);
        foreach (ProsperoNapsSpan span in plan.Spans)
        {
            if (span.StoredOffset < 0 || span.StoredOffset > pfsImage.Length
                || span.CompressedLength > pfsImage.Length - span.StoredOffset)
                throw new InvalidDataException($"NAPS span {span.Index} lies outside pfs_image.dat.");
            var payload = new byte[span.CompressedLength];
            pfsImage.Position = span.StoredOffset;
            pfsImage.ReadExactly(payload);

            var output = new byte[span.UncompressedLength];
            if (span.CompressedLength == span.UncompressedLength)
            {
                payload.CopyTo(output, 0);
            }
            else
            {
                if (span.KdePredictor != 0 || span.ShuffleIndex != 0)
                    throw new NotSupportedException(
                        $"NAPS span {span.Index} requires predictor/shuffle {span.KdePredictor}/{span.ShuffleIndex}.");
                int firstChunk = span.UncompressedLength > 0x20000
                    ? span.FirstChunkCompressedLength
                    : 0;
                DecodeKrakenSpan(payload, output, firstChunk, span);
            }

            destination.Position = span.UncompressedOffset;
            destination.Write(output);
        }
        destination.Position = 0;
    }

    private static int ResolveCblockInfoIndex(NapsLayoutDocument layout, long uncompressedOffset)
    {
        if (uncompressedOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(uncompressedOffset));
        int ublock = checked((int)(uncompressedOffset >> 18));
        uint start = ResolveU2c(layout, ublock);
        uint end = ResolveU2c(layout, checked(ublock + 1));
        long blockBase = (long)ublock << 18;
        for (uint index = start; index < end; index++)
        {
            if (index >= layout.CblockInfos.Count)
                break;
            NapsCblockInfoEntry entry = layout.CblockInfos[(int)index];
            if (!entry.IsRunBase && !entry.IsTerminal
                && uncompressedOffset == blockBase + entry.UoffsetStart)
                return checked((int)index);
        }
        throw new InvalidDataException($"No NAPS CblockInfo starts at logical offset 0x{uncompressedOffset:x}.");
    }

    private static uint ResolveU2c(NapsLayoutDocument layout, int ublock)
    {
        if (ublock < 0 || ublock >= layout.Counts.UBlockCount)
            throw new InvalidDataException($"NAPS ublock {ublock} is outside the u2c table.");
        NapsU2cEntry group = layout.CblockInfoOffsetByUblock[ublock >> 3];
        return (ublock & 7) == 0
            ? group.InfoOffset9BBase
            : checked(group.InfoOffset9BBase + group.DeltaFromBase[(ublock & 7) - 1]);
    }

    private static int Delta18(uint next, uint previous)
    {
        int delta = checked((int)next - (int)previous);
        if (delta <= 0)
            delta += UBlockSize;
        return delta;
    }

    private static void DecodeKrakenSpan(
        byte[] payload, byte[] output, int firstChunk, ProsperoNapsSpan span)
    {
        // NAPS uses bit 2 of each three-bit even/odd value for the newLZ-vs-bare-entropy choice.
        // Literal prediction is carried separately by KdePredictor; predictor zero is raw literals.
        int flags = ((span.Even & 4) != 0 ? 0x02 : 0)
            | ((span.Odd & 4) != 0 ? 0x20 : 0);
        KrakenDecodeStatus status = KrakenDecoder.DecodeBlock(payload, flags, firstChunk, output);
        if (status != KrakenDecodeStatus.Success)
            throw new InvalidDataException(
                $"NAPS span {span.Index} Kraken decode failed ({status}, modes {span.Even}/{span.Odd}).");
    }
}
