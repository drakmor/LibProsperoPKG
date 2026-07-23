// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK

using System;
using System.IO;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Conventional external test-key files used by the publisher-compatible build path.
/// Explicit providers/keys always take precedence; sidecars are loaded from the application
/// directory only when the corresponding build option is omitted.
/// </summary>
public static class ProsperoPublishingSidecar
{
    /// <summary>Default RSA-3072 PKCS#1/PKCS#8 private-key sidecar.</summary>
    public const string MetadataPrivateKeyFileName = "pkg_meta_rsa_key.pem";

    /// <summary>Default raw 16-byte AES-CMAC key sidecar.</summary>
    public const string NapsCmacKeyFileName = "naps_cmac_key.bin";

    /// <summary>Returns the absolute sidecar directory used by default.</summary>
    public static string DefaultDirectory => Path.GetFullPath(AppContext.BaseDirectory);

    /// <summary>Returns an absolute path for a conventional sidecar name.</summary>
    public static string GetPath(string fileName, string? directory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        return Path.Combine(Path.GetFullPath(directory ?? DefaultDirectory), fileName);
    }

    /// <summary>
    /// Loads <c>pkg_meta_rsa_key.pem</c> when it exists next to the host executable.
    /// A present but malformed key is rejected instead of silently falling back.
    /// </summary>
    public static ProsperoRsaMetadataSigner? TryLoadMetadataSigner(string? directory = null)
    {
        string path = GetPath(MetadataPrivateKeyFileName, directory);
        return File.Exists(path)
            ? ProsperoRsaMetadataSigner.LoadPem(path, $"sidecar:{MetadataPrivateKeyFileName}")
            : null;
    }

    /// <summary>
    /// Loads the raw 16-byte <c>naps_cmac_key.bin</c> sidecar when present.
    /// A present file with another size is rejected.
    /// </summary>
    public static byte[]? TryLoadNapsCmacKey(string? directory = null)
    {
        string path = GetPath(NapsCmacKeyFileName, directory);
        if (!File.Exists(path))
            return null;

        byte[] key = File.ReadAllBytes(path);
        if (key.Length != 16)
            throw new InvalidDataException(
                $"{NapsCmacKeyFileName} must contain exactly 16 raw bytes, not {key.Length}.");
        return key;
    }
}
