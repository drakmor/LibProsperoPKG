#!/usr/bin/env python3
"""Extract every meaningful PS5 PKG artifact with or without a title passcode/key.

The script parses the public FIH/CNT headers, exports CNT plaintext entries,
preserves protected entries as their complete aligned ciphertext, inspects the
plaintext outer-PFS superblock, and extracts a trailing SI ZIP when one is
present.  The fixed, package-independent AES-XTS key set used by
``naps_meta_18.dat`` is implemented locally, so that SI record is decrypted and
fully split without invoking another program.

The Python package ``cryptography`` is required for AES-XTS/AES-CBC.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


FIH_MAGIC = b"\x7fFIH"
CNT_MAGIC = b"\x7fCNT"
RLC_MAGIC = b"\x7fRLC"
UCP_MAGIC = b"\xB2\x28\xC6\x0A"
FIH_SIZE = 0x10000
CNT_HEADER_SIZE = 0x5A0
ENTRY_SIZE = 0x20
RLC_INDEX_RECORD_SIZE = 0x40
OUTER_BLOCK_SIZE = 0x10000
MAX_ENTRIES = 0x10000
KNOWN_NAMES: dict[int, str] = {
    0x0001: ".digests",
    0x0010: ".entry_keys",
    0x0020: ".image_key",
    0x0080: ".general_digests",
    # Delta-patch packages use this entry as a SHA3-authenticated index of the
    # trailing RLC records.  The publisher's original filename is not public.
    0x00C0: ".rlc_records",
    0x0100: ".metas",
    0x0200: ".entry_names",
    0x0400: "license.dat",
    0x0401: "license.info",
    0x0402: "nptitle.dat",
    0x0403: "npbind.dat",
    0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat",
    0x0407: "target-deltainfo.dat",
    0x0408: "origin-deltainfo.dat",
    0x040A: "imagedigs.dat",
    0x040B: "psreserved.dat",
    # Header-only copy of the first RLC record.  Full delta-patch packages put
    # complete RLC records in the trailing supplement indexed by entry 0xC0.
    0x040C: "rlc-header.bin",
    0x1000: "param.sfo",
    0x1001: "playgo-chunk.dat",
    0x1002: "playgo-chunk.sha",
    0x1003: "playgo-manifest.xml",
    0x1004: "pronunciation.xml",
    0x1005: "pronunciation.sig",
    0x1006: "pic1.png",
    0x1007: "pubtoolinfo.dat",
    0x1008: "app/playgo-chunk.dat",
    0x1009: "app/playgo-chunk.sha",
    0x100A: "app/playgo-manifest.xml",
    0x100B: "shareparam.json",
    0x100C: "shareoverlayimage.png",
    0x100E: "shareprivacyguardimage.png",
    0x1200: "icon0.png",
    0x1220: "pic0.png",
    0x1240: "snd0.at9",
    0x1260: "changeinfo/changeinfo.xml",
    0x1280: "icon0.dds",
    0x12A0: "pic0.dds",
    0x12C0: "pic1.dds",
    0x1480: "trophy2/trophy00.ucp",
    0x14A0: "uds/uds00.ucp",
    0x2000: "param.json",
    0x2010: "playgo-hash-table.dat",
    0x2011: "playgo-ficm.dat",
    0x2020: "uds/npbind.dat",
    0x2021: "trophy2/npbind.dat",
    0x2040: "pic1.dds",
    0x2060: "pic2.dds",
    0x3000: "playgo-scenario.json",
}

GENERAL_DIGEST_NAMES = [
    "content", "game", "header", "system", "major_param", "param",
    "playgo", "trophy", "manual", "keymap", "origin", "target",
    "origin_game", "target_game",
]

# naps_meta_18.dat is not protected by the per-title passcode.  Publisher tools
# use this fixed AES-128-XTS data/tweak key pair and one fixed data-unit tweak for
# every package.  Keeping the transform here makes this script standalone.
NAPS_META18_DATA_KEY = bytes.fromhex("022DCAF6D111E58F25936EF5469345AB")
NAPS_META18_TWEAK_KEY = bytes.fromhex("ADAC163760DA514698C245AB4C9C426C")
NAPS_META18_TWEAK = bytes.fromhex("3CBA107D000000000000000000000000")

# Sony's public trophy master keys.  They protect encrypted ESFM members, not
# the UCP container itself.  The per-title AES key is AES-CBC(master, zero-IV,
# NpCommId padded to 16 bytes); every encrypted member then stores IV || CBC.
TROPHY_MASTER_RELEASE = bytes.fromhex("21F41A6BAD8A1D3ECA7AD586C101B7A9")
TROPHY_MASTER_DEBUG = bytes.fromhex("02CCD346B459CB83505E8E760A44D457")
UCP_ENTRY_IDS = {0x1480, 0x14A0}

# Published SceShellCore PKG-metadata RSA-3072 key.  It matches publisher
# ENTRY_KEYS slot 3.  Keeping the PEM in this file makes automatic recovery
# independent of the repository layout and external key files.
PKG_METADATA_RSA_PRIVATE_KEY_PEM = b"""-----BEGIN RSA PRIVATE KEY-----
MIIG4wIBAAKCAYEAqx29QzlJMxajXEBOLCKXuDNoXBrTVOjFuniI0bD68lqPFKoG
Uo+kZYZu1CMD0wCRC9nYQQH+VMEr/E9/nDp6yRMz/SzcyxQAdhreXC68oBFtjDBL
i0fzPEE3coSenh0YO017vJlMN+14h9SGlCNLcazLTblQcDNmGJdu1nscQBohE9Q5
iANASZ9la3rus4bAZ5jC0UTrtYS1ZXso4pCUSTF5mwsJsnGh2TcL/k+Eusx46jyR
fTANU9XFajQLKwdWCA8oMlNj65vITrkdcEaO74vUqzAvE/MAQXCVecqlTovXZCNW
7IUjChUU4AZnVoQjCB1kOZaIM6UcWy/Htu8AYj+3JYmaKWfLwUzurv6HRygClaMc
kIlZs37OsAZBgsUzZk3tY1X/MTz4KokaQtyIZV/d/nHmUOUbFJCoiM441vuFDiDR
JAjNsPDvqy/xn5qVgC1DdWDAyYbF8suyDiuJf2vLZ6Vle0ck29oss4/iPXOM8m+M
wG4PEiH+dA0ONoFxAgMBAAECggGBAI4E88UscYV2X4U8VeUpnNSjzhTLquSJATrf
uWaYRd8JrEERUIgLcf1VUvy8RvtEOB4m4uYpemXroc8aSCZpHuluB7M0HdhqtGtR
p4XIwIL1k/9LQhfKUqWK1zMzwNYn/amSiIUiknDEpknN6RhgJsilCmNqz8kfz7fP
T42xxeOqDBQCCvHJCP1RzwIimKTlzSDuV5sKYbtY9pjQXEGWj4wkBPLaeWTiDNtU
ZZ7fbqD+/cgjFvlY/Wa8QMoBgddnkPMo0g7JO/XK9qvdo/+J/qJHQ4rIJa/Ygi4T
iXD+jvsZ3dNzpc7Lv8wuBHlY/NjnrTpabDOdmPt5R+oDTXJLkDZIeo4AaUkeGtSX
4ehXlXTinu+mKtIlHYPa1zpPGqqs9x7fNRBVfY20cU/QXWPcdOrjYh0rBAbFEm/H
1qELmVY4nHVWy9pRxEtdrIe7l9ZGjaceJ9WDLvqWAEjQU6QAw6z+Krpoo6GvT0N+
oau8Mc15pRRwfWGAv/1Y2nwqRKu/QQKBwQDYT3iTjzH0VugozyiQYgTZNpn2oxlu
xydTbftoXmPEz612B4gfbz+9hr06BWLFIv0KQn0SAsN3zuNzyVHnYwcpiQDykV7l
3bE/lhS6w1/SKzS9qFv/hrzHHpiPZCLjoC7J0Y1E5MDQVF26fsZZOq7LDh0es91/
YTU79IgR+7tvpQ31NX846Afhw8P+8VLLxrLCtGdPPX1EOcjuoO8XtACiAtI+kzlK
orIPV3oGFSjxuNXIU9B/NadTyyQ3PuAFxckCgcEAyoNnf/Oec0fZD5lVxVpWV8NU
O6lmuoYQ4LEvwpbV8dHYz/J9A67O7Mx3Bl8xmZ46hDexhiQTdXWeqoyNZstfSret
ZBicXGNMfbNzcOKCJOMuy8oJsI7fZKmePmLZtKGmx16sUbGC49Vt0HHiOL1WQdme
y+KR619I+/pTQwa4fWDkQB0YS+BaI2nPOeBZ+0fDtQP0qqiC8303Yd7OXqcNhx4J
s3aqVO8zqr3yeO1osuJRZoEHfO5Rby58WQM1jlJpAoHAB3gfCsFcETrbA2W72dh4
oGOBR4H0Q93+nqPilYUE3uvo6nVyHtvBkLLRX+qFsZb2s9794JxV0ZJESmA+QsYp
niaL8NRSOY/BKhftmVFbwq8ZQB9LJfSqGhoVXIYxqjiCxRdGUIWxnr/7CJCOGtCq
7noLSV8em+JoayyTckOGAmHprHjvbrCcbRBMeUYt/LlcvNpr4tGVvMBeDtdhyii+
CNoeFmkRBmG90kfL/9/FLSubvjIetfXNVFhkZL/4Dlr5AoHAPJljsEMbSA3Y4zUU
GHE24x49J3lCl1Ak3sfGrejq7mjIAznhtOdrXiq090AnHHvfsM7lnWlQNVbT+t8C
NR9oTXh3NzuyFmdUbUz0n3P4U8dzqmGz0pR+PqYPB0YXNVkmCgTHdc6zhy/Ho5dg
hXAKzrurLAGJfrBNq7E1lxn8vO/wfUr3iUUCVBSGgSAkbPAFnTYo0aSJQwlWOEAu
6t38S1Fuv7gjsjS99jrOwubv7I+SoiS8M+MwlR+I8C3oqcT5AoHAXFDvIxTb4c8Z
ZoqTTdznYjRypS/9p2kAzgVsmnpAWlWdgU5J/PNyNhhielRoNj2QjvTuJjMUZjZq
HmYtWyVSEF2FIRG5kd55EOKaJa87FCww3zxbjf/onDWWxvVjCehBntlhVZSYL9mG
BTIBI4Z03BJK+dW0/aWebSiuAtvs4M+yw6xsvu5kIGO0jqfwaZa97E2n+BYUPNpn
afy1hEcQcaxkJL2UPorj37SpVHMeTNO4+QjMHYU7wcwKz0e7rWt7
-----END RSA PRIVATE KEY-----
"""


class PkgError(Exception):
    pass


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def hx(value: int) -> str:
    return f"0x{value:X}"


def hex_bytes(value: bytes) -> str:
    return value.hex().upper()


def ascii_z(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("ascii", errors="replace")


def u16be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def u64be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", data, offset)[0]


def u16le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def i64le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<q", data, offset)[0]


def decrypt_naps_meta18(encrypted: bytes) -> bytes:
    """Decrypt the fixed publisher NAPS TLV data unit using AES-XTS."""
    if not encrypted or len(encrypted) % 16:
        raise PkgError("naps_meta_18.dat must be a non-empty multiple of 16 bytes")
    cipher = Cipher(
        algorithms.AES(NAPS_META18_DATA_KEY + NAPS_META18_TWEAK_KEY),
        modes.XTS(NAPS_META18_TWEAK))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()


def derive_publisher_key(content_id: str, passcode: str, index: int) -> bytes:
    """Derive one PS5 CNT key using the publisher SHA3-256 profile."""
    if len(content_id) != 36:
        raise PkgError("CNT content ID must contain exactly 36 characters")
    if len(passcode) != 32:
        raise PkgError("Passcode must contain exactly 32 ASCII characters")
    try:
        passcode_bytes = passcode.encode("ascii")
        content_id_bytes = content_id.encode("ascii")
    except UnicodeEncodeError as error:
        raise PkgError("Content ID and passcode must be ASCII") from error
    digest = hashlib.sha3_256
    material = (
        digest(struct.pack(">I", index)).digest()
        + digest(content_id_bytes.ljust(48, b"\0")).digest()
        + passcode_bytes
    )
    return digest(material).digest()


def derived_key_digest(key: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(hashlib.sha3_256(key).digest(), key))


def decrypt_cnt_entry(ciphertext: bytes, meta_record: bytes, derived_key: bytes, logical_size: int) -> bytes:
    """Decrypt one publisher-profile protected CNT entry."""
    if len(meta_record) != ENTRY_SIZE or len(derived_key) != 32:
        raise PkgError("CNT metadata record/key has an invalid size")
    if len(ciphertext) % 16:
        raise PkgError("Protected CNT entry ciphertext is not AES-block aligned")
    iv_key = hashlib.sha3_256(meta_record + derived_key).digest()
    decryptor = Cipher(algorithms.AES(iv_key[16:]), modes.CBC(iv_key[:16])).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    if logical_size > len(padded):
        raise PkgError("Protected CNT entry plaintext is shorter than its declared size")
    if any(padded[logical_size:]):
        raise PkgError("Protected CNT entry has nonzero alignment padding; the supplied key is invalid")
    return padded[:logical_size]


def is_ucp_cnt_protected(entry_id: int, flags1: int) -> bool:
    """Recognize the publisher's sealed UCP CNT profile.

    Retail trophy2/uds archives use flags1=0x1C000000.  Unlike ordinary data
    entries (0x08000000), their bytes are ciphertext even though bit 31 is not
    set.  flags2 is zero, selecting publisher derived key index 0.
    """
    return entry_id in UCP_ENTRY_IDS and flags1 & 0x1C000000 == 0x1C000000


def decrypt_trophy_esfm(data: bytes, np_comm_id: str, master_key: bytes) -> bytes:
    """Decrypt an IV-prefixed trophy ESFM member using the public master key."""
    if len(master_key) != 16:
        raise PkgError("Trophy master key must contain 16 bytes")
    try:
        comm_id = np_comm_id.encode("ascii")
    except UnicodeEncodeError as error:
        raise PkgError("NP Communication ID must be ASCII") from error
    if not comm_id or len(comm_id) > 16:
        raise PkgError("NP Communication ID does not fit the 16-byte trophy key block")
    if len(data) < 32 or (len(data) - 16) % 16:
        raise PkgError("Encrypted trophy member is not IV plus AES-block-aligned ciphertext")
    zero_iv = bytes(16)
    key_encryptor = Cipher(algorithms.AES(master_key), modes.CBC(zero_iv)).encryptor()
    title_key = key_encryptor.update(comm_id.ljust(16, b"\0")) + key_encryptor.finalize()
    decryptor = Cipher(algorithms.AES(title_key), modes.CBC(data[:16])).decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()


def derive_outer_pfs_xts_keys(ekpfs: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """Return the publisher new-crypt (tweak key, data key) pair."""
    if len(ekpfs) != 32 or len(seed) != 16:
        raise PkgError("Outer-PFS EKPFS/seed must contain 32/16 bytes")
    base_key = hmac.digest(ekpfs, seed, "sha256")
    material = hmac.digest(base_key, struct.pack("<I", 1) + seed, "sha256")
    return material[:16], material[16:]


def decrypt_outer_pfs_to_file(
        stream: BinaryIO, output_path: Path, image_offset: int, image_size: int,
        superblock_offset: int, ekpfs: bytes, seed: bytes) -> dict[str, Any]:
    """Stream-decrypt a data-first publisher outer PFS without materializing it in RAM."""
    if image_size <= 0 or image_size % 16:
        raise PkgError("Outer-PFS size is empty or not AES-block aligned")
    relative_superblock = superblock_offset - image_offset
    if relative_superblock < 0 or relative_superblock % OUTER_BLOCK_SIZE:
        raise PkgError("Outer-PFS superblock is not block-aligned inside the image")
    plaintext_block = relative_superblock // OUTER_BLOCK_SIZE
    tweak_key, data_key = derive_outer_pfs_xts_keys(ekpfs, seed)
    block_count = (image_size + OUTER_BLOCK_SIZE - 1) // OUTER_BLOCK_SIZE
    digest = hashlib.sha256()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stream.seek(image_offset)
    with output_path.open("wb") as destination:
        remaining = image_size
        for block_index in range(block_count):
            size = min(OUTER_BLOCK_SIZE, remaining)
            block = stream.read(size)
            if len(block) != size:
                raise PkgError("Unexpected end of outer PFS during decryption")
            if block_index != plaintext_block:
                # Data precedes the data-first superblock.  Signed filesystem
                # metadata follows it and sets bit 47 in the XTS data-unit number.
                sector = block_index
                if block_index > plaintext_block:
                    sector |= 0x800000000000
                data_unit = struct.pack("<Q", sector) + bytes(8)
                decryptor = Cipher(
                    algorithms.AES(data_key + tweak_key), modes.XTS(data_unit)).decryptor()
                block = decryptor.update(block) + decryptor.finalize()
            destination.write(block)
            digest.update(block)
            remaining -= size
    return {
        "output": str(output_path),
        "size": image_size,
        "block_count": block_count,
        "plaintext_superblock_block": plaintext_block,
        "sha256": digest.hexdigest().upper(),
    }


def parse_hex_key(value: str, expected_size: int, label: str) -> bytes:
    compact = re.sub(r"[\s:_-]", "", value)
    try:
        decoded = bytes.fromhex(compact)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{label} must be hexadecimal") from error
    if len(decoded) != expected_size:
        raise argparse.ArgumentTypeError(
            f"{label} must contain exactly {expected_size} bytes ({expected_size * 2} hex digits)")
    return decoded


def parse_derived_key_argument(value: str) -> tuple[int, bytes]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("derived key must use INDEX:HEX format")
    index_text, key_text = value.split(":", 1)
    try:
        index = int(index_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("derived key index must be an integer from 0 to 6") from error
    if not 0 <= index <= 6:
        raise argparse.ArgumentTypeError("derived key index must be from 0 to 6")
    return index, parse_hex_key(key_text, 32, f"derived key {index}")


def read_exact_at(stream: BinaryIO, offset: int, size: int, file_size: int) -> bytes:
    if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
        raise PkgError(f"Range is outside the file: offset={hx(offset)}, size={hx(size)}")
    stream.seek(offset)
    value = stream.read(size)
    if len(value) != size:
        raise PkgError(f"Unexpected end of file at {hx(offset)}")
    return value


def copy_range(stream: BinaryIO, output: Path, offset: int, size: int, file_size: int) -> None:
    if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
        raise PkgError(f"Cannot export range {hx(offset)}+{hx(size)}")
    output.parent.mkdir(parents=True, exist_ok=True)
    stream.seek(offset)
    remaining = size
    with output.open("wb") as dst:
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise PkgError("Unexpected end of file while copying a segment")
            dst.write(block)
            remaining -= len(block)


def hash_range(stream: BinaryIO, offset: int, size: int, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    stream.seek(offset)
    remaining = size
    while remaining:
        block = stream.read(min(4 * 1024 * 1024, remaining))
        if not block:
            raise PkgError("Unexpected end of file while hashing a range")
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest().upper()


def json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def safe_parts(name: str) -> list[str]:
    name = name.replace("\\", "/")
    parts = []
    for raw in name.split("/"):
        if not raw or raw in (".", ".."):
            continue
        part = re.sub(r"[<>:\"|?*\x00-\x1f]", "_", raw).rstrip(" .")
        parts.append(part or "_")
    return parts or ["unnamed.bin"]


def entry_output_path(root: Path, entry_id: int, name: str, encrypted: bool) -> Path:
    parts = safe_parts(name)
    if encrypted:
        parts[-1] = f"{entry_id:08X}_{parts[-1]}.ciphertext.bin"
    target = root.joinpath(*parts)
    target.resolve().relative_to(root.resolve())
    return target


def entry_known_name(entry_id: int) -> str | None:
    if entry_id in KNOWN_NAMES:
        return KNOWN_NAMES[entry_id]
    if 0x1201 <= entry_id <= 0x121F:
        return f"icon0_{entry_id - 0x1201:02d}.png"
    if 0x1241 <= entry_id <= 0x125F:
        return f"pic1_{entry_id - 0x1241:02d}.png"
    if 0x1261 <= entry_id <= 0x127F:
        return f"changeinfo/changeinfo_{entry_id - 0x1261:02d}.xml"
    if 0x1281 <= entry_id <= 0x129F:
        return f"icon0_{entry_id - 0x1281:02d}.dds"
    if 0x12C1 <= entry_id <= 0x12DF:
        return f"pic1_{entry_id - 0x12C1:02d}.dds"
    if 0x1400 <= entry_id <= 0x147F:
        return f"trophy/trophy{entry_id - 0x1400:02d}.trp"
    return None


def parse_fih(header: bytes) -> dict[str, Any]:
    result = {
        "magic": header[:4].hex(" ").upper(),
        "version": header[4],
        "signed_byte": hx(header[5]),
        "is_retail": header[5] == 0x80,
        "kind": hx(header[6]),
        "header_version": u32le(header, 0x08),
        "pfs_offset": u64le(header, 0x10),
        "pfs_size": u64le(header, 0x18),
        "outer_superblock_offset": u64le(header, 0x20),
        "outer_superblock_size": u64le(header, 0x28),
        "sblock_digest_sha3_256": hex_bytes(header[0x30:0x50]),
        "data_region_block_count": u64le(header, 0x50),
        "embedded_cnt_offset": u64le(header, 0x58),
        "secondary_offset": u64le(header, 0x60),
        "secondary_flags": hx(u64le(header, 0x68)),
        "game_digest": hex_bytes(header[0x70:0x90]),
        "inner_image_block_count": u32le(header, 0x90),
        "naps_nonterminal_file_count": u32le(header, 0x94),
        "naps_file_and_empty_boundary_count": u32le(header, 0x98),
        "content_version": hx(u32le(header, 0x9C)),
        "inner_image_aligned_size": u64le(header, 0xA0),
        "naps_layout_size": u64le(header, 0xA8),
        "naps_layout_digest_sha3_256": hex_bytes(header[0xB0:0xD0]),
        "target_digest": hex_bytes(header[0xD0:0xF0]),
        "app_payload_file_count": u32le(header, 0xF0),
        "sparse_afid_count": u32le(header, 0xF4),
        "flat_path_table_block_count": u32le(header, 0xF8),
        "empty_file_count": u32le(header, 0xFC),
        "retail_finalization_offset": 0xF000,
        "retail_finalization_size": 0x300,
        "retail_finalization_sha256": hashlib.sha256(header[0xF000:0xF300]).hexdigest().upper(),
        "fih_sha3_256": hashlib.sha3_256(header).hexdigest().upper(),
    }
    return result


def parse_cnt_header(data: bytes) -> dict[str, Any]:
    # The profile/delta names below are semantic names inferred from publisher
    # corpus and the builder.  Their original Sony member names are not public:
    # +0x08/+0x0c select the PS5 CNT profile, +0x88..+0x94 are populated only by
    # patch variants, and +0x400 enables the following PFS mount descriptor.
    result = {
        "magic": data[:4].hex(" ").upper(),
        "flags": hx(u32be(data, 0x04)),
        "ps5_profile_marker": hx(u32be(data, 0x08)),
        "header_profile_code": hx(u32be(data, 0x0C)),
        "entry_count": u32be(data, 0x10),
        "system_entry_count": u16be(data, 0x14),
        "entry_count_mirror": u16be(data, 0x16),
        "entry_table_offset": u32be(data, 0x18),
        "main_entry_data_size": u32be(data, 0x1C),
        "body_offset": u64be(data, 0x20),
        "body_size": u64be(data, 0x28),
        "mandatory_size": u64be(data, 0x30),
        "content_id": ascii_z(data[0x40:0x70]),
        "drm_type": hx(u32be(data, 0x70)),
        "content_type": hx(u32be(data, 0x74)),
        "content_flags": hx(u32be(data, 0x78)),
        "promote_size": u32be(data, 0x7C),
        "version_date": hx(u32be(data, 0x80)),
        "version_hash": hx(u32be(data, 0x84)),
        "delta_patch_metadata_0": hx(u32be(data, 0x88)),
        "delta_patch_metadata_1": hx(u32be(data, 0x8C)),
        "delta_patch_metadata_2": hx(u32be(data, 0x90)),
        "delta_patch_metadata_3": hx(u32be(data, 0x94)),
        "iro_tag": hx(u32be(data, 0x98)),
        "ekc_version": u32be(data, 0x9C),
        "sc_entries_1_hash": hex_bytes(data[0x100:0x120]),
        "sc_entries_2_hash": hex_bytes(data[0x120:0x140]),
        "digest_table_hash": hex_bytes(data[0x140:0x160]),
        "body_digest": hex_bytes(data[0x160:0x180]),
        "content_id_mirror": ascii_z(data[0x200:0x230]),
        "pfs_descriptor_presence": u32be(data, 0x400),
        "pfs_image_count": u32be(data, 0x404),
        "pfs_flags": hx(u64be(data, 0x408)),
        "pfs_image_offset": u64be(data, 0x410),
        "pfs_image_size": u64be(data, 0x418),
        "mount_image_offset": u64be(data, 0x420),
        "mount_image_size": u64be(data, 0x428),
        "package_size": u64be(data, 0x430),
        "pfs_signed_size": u32be(data, 0x438),
        "pfs_cache_size": u32be(data, 0x43C),
        "pfs_image_digest": hex_bytes(data[0x440:0x460]),
        "pfs_signed_or_fixed_info_digest": hex_bytes(data[0x460:0x480]),
        "pfs_split_size_image_0": u64be(data, 0x480),
        "pfs_split_size_image_1": u64be(data, 0x488),
        "image_seed": hex_bytes(data[0x4A0:0x4B0]),
        "cnt_region_offset": u64be(data, 0x4B0),
        "cnt_region_size": u64be(data, 0x4B8),
        "image_key_descriptor": {
            "offset": u32be(data, 0x510), "size": u32be(data, 0x514),
        },
        "mandatory_descriptor": {
            "offset": u32be(data, 0x518), "size": u32be(data, 0x51C),
        },
        "descriptor_digests": [
            hex_bytes(data[0x520:0x540]), hex_bytes(data[0x540:0x560])
        ],
    }
    pkg_flags = u32be(data, 0x04)
    content_type = u32be(data, 0x74)
    content_flags = u32be(data, 0x78)
    result["known_package_flags"] = [
        name for bit, name in (
            # Present in every ordinary package emitted by both legacy and PS5
            # builders; it selects the common/base CNT package profile.
            (0x00000001, "BASE_PACKAGE_PROFILE"),
            (0x01000000, "VERSION_1"),
            (0x02000000, "VERSION_2"),
            (0x40000000, "INTERNAL"),
            (0x80000000, "FINALIZED"),
        ) if pkg_flags & bit
    ]
    result["content_type_name"] = {
        0x20: "PS5 application/game",
        0x21: "PS5 additional content with data",
        0x22: "PS5 entitlement-only additional content",
        0x23: "PS5 delta patch",
        0x26: "PS5 media application",
    }.get(content_type, "unrecognized")
    result["known_content_flags"] = [
        name for bit, name in (
            (0x00100000, "FIRST_PATCH"),
            (0x00200000, "PATCHGO"),
            (0x00400000, "REMASTER"),
            (0x00800000, "PS_CLOUD"),
            (0x02000000, "GD_AC"),
            (0x04000000, "NON_GAME"),
            # Set by the current publisher builder for applicationDrmType=upgradable.
            (0x08000000, "UPGRADABLE_APPLICATION"),
            (0x40000000, "SUBSEQUENT_PATCH"),
            (0x41000000, "DELTA_PATCH"),
            (0x60000000, "CUMULATIVE_PATCH"),
        ) if content_flags & bit == bit
    ]
    result["pfs_flags_low_profile"] = hx(u64be(data, 0x408) & 0xFFFFF)
    result["license_policy"] = "not determinable from public PKG header fields alone"
    return result


def split_content_id(content_id: str) -> dict[str, Any]:
    result: dict[str, Any] = {"valid_shape": False}
    if len(content_id) == 36 and content_id[6:7] == "-" and content_id[16:17] == "_" and content_id[19:20] == "-":
        result.update({
            "valid_shape": True,
            "publisher_region": content_id[:6],
            "title_id": content_id[7:16],
            "prefix": content_id[:19],
            "label": content_id[20:36],
        })
    return result


def parse_entries(stream: BinaryIO, file_size: int, cnt_base: int, cnt: dict[str, Any]) -> list[dict[str, Any]]:
    count = int(cnt["entry_count"])
    table_offset = int(cnt["entry_table_offset"])
    if count > MAX_ENTRIES:
        raise PkgError(f"Implausible CNT entry count: {count}")
    table_size = count * ENTRY_SIZE
    raw = read_exact_at(stream, cnt_base + table_offset, table_size, file_size)
    entries: list[dict[str, Any]] = []
    for index in range(count):
        item = raw[index * ENTRY_SIZE:(index + 1) * ENTRY_SIZE]
        entry_id = u32be(item, 0)
        flags1 = u32be(item, 8)
        flags2 = u32be(item, 12)
        logical_size = u32be(item, 20)
        ordinary_encrypted = bool(flags1 & 0x80000000)
        sealed_ucp = is_ucp_cnt_protected(entry_id, flags1)
        encrypted = ordinary_encrypted or sealed_ucp
        entries.append({
            "index": index,
            "id": hx(entry_id),
            "id_value": entry_id,
            "name_table_offset": u32be(item, 4),
            "flags1": hx(flags1),
            "flags2": hx(flags2),
            "encrypted": encrypted,
            "encryption_profile": (
                "sealed-ucp-key0" if sealed_ucp
                else "publisher-aes-cbc" if ordinary_encrypted
                else "none"
            ),
            "key_index": 0 if sealed_ucp else (flags2 & 0xF000) >> 12,
            "data_offset": u32be(item, 16),
            "logical_size": logical_size,
            "stored_size": align_up(logical_size, 16) if encrypted else logical_size,
            "metadata_record": hex_bytes(item),
        })
    return entries


def resolve_entry_names(stream: BinaryIO, file_size: int, cnt_base: int, entries: list[dict[str, Any]]) -> None:
    table = next((item for item in entries if item["id_value"] == 0x0200), None)
    names = b""
    if table and not table["encrypted"]:
        names = read_exact_at(stream, cnt_base + table["data_offset"], table["logical_size"], file_size)
    for item in entries:
        name: str | None = None
        offset = item["name_table_offset"]
        if offset and offset < len(names):
            end = names.find(b"\0", offset)
            if end < 0:
                end = len(names)
            name = names[offset:end].decode("ascii", errors="replace")
        item["name"] = name or entry_known_name(item["id_value"]) or f"entry-{item['id_value']:08X}.bin"


def parse_entry_keys(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
    }
    fixed = 32 + 7 * 32
    if len(data) >= fixed and (len(data) - fixed) % 7 == 0:
        wrap_size = (len(data) - fixed) // 7
        result["profile"] = "publisher-rsa3072" if wrap_size == 0x180 else f"wrap-{hx(wrap_size)}"
        result["seed_digest"] = hex_bytes(data[:32])
        result["key_digests"] = [hex_bytes(data[32 + i * 32:64 + i * 32]) for i in range(7)]
        wraps = data[fixed:]
        result["wrapped_keys"] = [
            {
                "index": i,
                "size": wrap_size,
                "sha256": hashlib.sha256(wraps[i * wrap_size:(i + 1) * wrap_size]).hexdigest().upper(),
            }
            for i in range(7)
        ]
    return result


def recover_entry_keys_with_metadata_rsa(data: bytes) -> dict[int, bytes]:
    """Recover publisher keys wrapped by the published PKG-metadata RSA key.

    Publisher ENTRY_KEYS contains seven independent RSA-3072 ciphertexts.  Each
    slot was encrypted with a different public modulus, so a private key can be
    valid for only its matching slot.  The published PKG-metadata private key
    matches slot 3 in retail packages.  Accept a result only when its length and
    the ENTRY_KEYS SHA3-derived digest both match; failed slots are expected.
    """
    fixed_size = 32 + 7 * 32
    if len(data) != fixed_size + 7 * 0x180:
        return {}
    private_key = serialization.load_pem_private_key(
        PKG_METADATA_RSA_PRIVATE_KEY_PEM, password=None)
    recovered: dict[int, bytes] = {}
    wraps = data[fixed_size:]
    for key_index in range(7):
        wrapped = wraps[key_index * 0x180:(key_index + 1) * 0x180]
        try:
            plaintext = private_key.decrypt(wrapped, asymmetric_padding.PKCS1v15())
        except ValueError:
            continue
        stored_digest = data[32 + key_index * 32:64 + key_index * 32]
        if len(plaintext) == 32 and hmac.compare_digest(
                derived_key_digest(plaintext), stored_digest):
            recovered[key_index] = plaintext
    return recovered


def parse_image_key(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "nonzero_bytes": sum(value != 0 for value in data),
    }
    if len(data) == 0x800:
        head, tail = data[:0x180], data[0x180:]
        result.update({
            "format": "RSA3072[0x180] || SHAKE128-tail[0x680]",
            "rsa3072_head_sha256": hashlib.sha256(head).hexdigest().upper(),
            "shake128_tail_sha256": hashlib.sha256(tail).hexdigest().upper(),
        })
    return result


def parse_general_digests(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"size": len(data)}
    if len(data) < 0x20:
        return result
    result.update({
        "magic": hx(u16be(data, 0)),
        "type": hx(u16be(data, 2)),
        "set_mask": hx(u32be(data, 0x1C)),
    })
    slot_count = min(len(GENERAL_DIGEST_NAMES), (len(data) - 0x20) // 0x20)
    result["digests"] = {
        GENERAL_DIGEST_NAMES[i]: hex_bytes(data[0x20 + i * 0x20:0x40 + i * 0x20])
        for i in range(slot_count)
    }
    return result


def parse_meta_records(data: bytes) -> dict[str, Any]:
    records = []
    for index in range(len(data) // ENTRY_SIZE):
        item = data[index * ENTRY_SIZE:(index + 1) * ENTRY_SIZE]
        flags1, flags2 = u32be(item, 8), u32be(item, 12)
        records.append({
            "index": index,
            "id": hx(u32be(item, 0)),
            "name_table_offset": u32be(item, 4),
            "flags1": hx(flags1),
            "flags2": hx(flags2),
            "encrypted": bool(flags1 & 0x80000000),
            "key_index": (flags2 & 0xF000) >> 12,
            "data_offset": u32be(item, 16),
            "data_size": u32be(item, 20),
        })
    return {"record_count": len(records), "records": records}


def parse_name_table(data: bytes) -> dict[str, Any]:
    names = []
    offset = 0
    while offset < len(data):
        end = data.find(b"\0", offset)
        if end < 0:
            end = len(data)
        names.append({"offset": offset, "name": data[offset:end].decode("ascii", errors="replace")})
        offset = end + 1
    return {"name_count": len(names), "names": names}


def parse_rlc_header(data: bytes) -> dict[str, Any] | None:
    """Decode a complete or header-only RLC record."""
    if len(data) < 0x180 or data[:4] != RLC_MAGIC:
        return None
    header_size = u32le(data, 0x20)
    payload_size = u32le(data, 0x24)
    record_data_size = u32le(data, 0x18)
    element_capacity = u32le(data, 0x14)
    result: dict[str, Any] = {
        "format": "RLC record header",
        "magic": "7F524C43",
        "format_version": hx(u32le(data, 0x04)),
        "format_profile": hx(u32le(data, 0x10)),
        "element_capacity": element_capacity,
        "record_data_size": record_data_size,
        "format_revision_date": hx(u32le(data, 0x1C)),
        "header_size": header_size,
        "payload_size": payload_size,
        "record_count": u32le(data, 0x30),
        "records_remaining": u32le(data, 0x34),
        "selected_index_count": u32le(data, 0x38),
        "index_upper_bound": u32le(data, 0x3C),
        "header_static_digest": hex_bytes(data[0xA0:0xC0]),
        "primary_descriptor": {
            "id": hex_bytes(data[0x100:0x104]),
            "element_count_or_limit": u32le(data, 0x104),
            "digest": hex_bytes(data[0x120:0x140]),
        },
        "secondary_descriptor": {
            "id": hex_bytes(data[0x140:0x144]),
            "element_count_or_limit": u32le(data, 0x144),
            "digest": hex_bytes(data[0x160:0x180]),
        },
    }
    result["size_fields_consistent"] = (
        header_size == 0x1000
        and header_size + payload_size == record_data_size
        and payload_size == element_capacity * 4
    )
    result["available_size"] = len(data)
    result["header_complete"] = len(data) >= header_size
    result["payload_available_size"] = max(0, min(payload_size, len(data) - header_size))
    result["complete_record_present"] = len(data) >= record_data_size
    return result


def parse_rlc_index(data: bytes) -> dict[str, Any]:
    """Parse CNT entry 0xC0, the authenticated index of trailing RLC records."""
    result: dict[str, Any] = {
        "format": "RLC supplement index",
        "record_size": RLC_INDEX_RECORD_SIZE,
        "size": len(data),
    }
    if not data or len(data) % RLC_INDEX_RECORD_SIZE:
        result["parse_error"] = "Entry size is not a nonzero multiple of 0x40"
        return result
    records = []
    for index in range(len(data) // RLC_INDEX_RECORD_SIZE):
        item = data[index * RLC_INDEX_RECORD_SIZE:(index + 1) * RLC_INDEX_RECORD_SIZE]
        records.append({
            "index": index,
            # This eight-byte compound identifier is repeated in the two RLC
            # header descriptors.  Its exact publisher-side type name is not
            # public, so preserve it byte-exact instead of inventing bit fields.
            "compound_record_id": hex_bytes(item[:8]),
            "primary_descriptor_id": hex_bytes(item[:4]),
            "secondary_descriptor_id": hex_bytes(item[4:8]),
            "reserved_zero": hx(u64le(item, 0x08)),
            "supplement_offset": u64le(item, 0x10),
            "authenticated_size": u64le(item, 0x18),
            "sha3_256": hex_bytes(item[0x20:0x40]),
        })
    result["record_count"] = len(records)
    result["records"] = records
    return result


def inspect_rlc_supplement(path: Path, index_data: bytes) -> dict[str, Any]:
    """Validate and summarize a delta-patch RLC supplement without any key."""
    index = parse_rlc_index(index_data)
    records = index.get("records", [])
    result: dict[str, Any] = {
        "format": "RLC delta-patch block-index sets",
        "size": path.stat().st_size,
        "index_record_count": len(records),
        "records": [],
    }
    if not records:
        result["parse_error"] = "CNT entry 0xC0 contains no usable RLC index records"
        return result

    file_size = path.stat().st_size
    all_hashes_valid = True
    all_layouts_valid = True
    all_headers_consistent = True
    previous_end = 0
    with path.open("rb") as stream:
        for record in records:
            offset = int(record["supplement_offset"])
            size = int(record["authenticated_size"])
            if offset > file_size or size > file_size - offset:
                item_result = {
                    "index": record["index"],
                    "offset": offset,
                    "authenticated_size": size,
                    "range_valid": False,
                }
                result["records"].append(item_result)
                all_hashes_valid = all_layouts_valid = all_headers_consistent = False
                continue

            gap_size = offset - previous_end
            gap_is_zero = gap_size >= 0
            if gap_size > 0:
                stream.seek(previous_end)
                gap_is_zero = not any(stream.read(gap_size))
            stream.seek(offset)
            blob = stream.read(size)
            digest = hashlib.sha3_256(blob).hexdigest().upper()
            hash_valid = digest == record["sha3_256"]
            header_valid = len(blob) >= 0x1000 and blob[:4] == RLC_MAGIC
            item_result: dict[str, Any] = {
                "index": record["index"],
                "compound_record_id": record["compound_record_id"],
                "offset": offset,
                "authenticated_size": size,
                "gap_before_size": gap_size,
                "gap_before_is_zero": gap_is_zero,
                "computed_sha3_256": digest,
                "sha3_256_valid": hash_valid,
                "header_valid": header_valid,
            }
            all_hashes_valid &= hash_valid
            if header_valid:
                header_size = u32le(blob, 0x20)
                payload_size = u32le(blob, 0x24)
                element_capacity = u32le(blob, 0x14)
                selected_count = u32le(blob, 0x38)
                record_count = u32le(blob, 0x30)
                records_remaining = u32le(blob, 0x34)
                size_consistent = (
                    header_size == 0x1000
                    and header_size + payload_size == size
                    and payload_size == element_capacity * 4
                )
                descriptor_ids_match = (
                    blob[0x100:0x104] == bytes.fromhex(record["primary_descriptor_id"])
                    and blob[0x140:0x144] == bytes.fromhex(record["secondary_descriptor_id"])
                )
                payload = blob[header_size:header_size + payload_size]
                values = struct.unpack(f"<{element_capacity}I", payload) if size_consistent else ()
                # Observed RLC payload grammar: one leading sentinel, the sorted
                # unique selected block indexes, then sentinel padding to the
                # fixed capacity.  This is plain integer data, not ciphertext.
                selected = values[1:1 + selected_count] if values else ()
                sentinels_valid = bool(values) and values[0] == 0xFFFFFFFF and all(
                    value == 0xFFFFFFFF for value in values[1 + selected_count:])
                selected_valid = (
                    len(selected) == selected_count
                    and all(value != 0xFFFFFFFF for value in selected)
                    and all(left < right for left, right in zip(selected, selected[1:]))
                )
                layout_valid = size_consistent and sentinels_valid and selected_valid
                all_layouts_valid &= layout_valid
                all_headers_consistent &= descriptor_ids_match and record_count == len(records)
                item_result["header"] = {
                    "magic": "7F524C43",
                    "format_version": hx(u32le(blob, 0x04)),
                    "format_profile": hx(u32le(blob, 0x10)),
                    "element_capacity": element_capacity,
                    "record_data_size": u32le(blob, 0x18),
                    "format_revision_date": hx(u32le(blob, 0x1C)),
                    "header_size": header_size,
                    "payload_size": payload_size,
                    "record_count": record_count,
                    "records_remaining": records_remaining,
                    "selected_index_count": selected_count,
                    "index_upper_bound": u32le(blob, 0x3C),
                    "header_static_digest": hex_bytes(blob[0xA0:0xC0]),
                    "primary_descriptor": {
                        "id": hex_bytes(blob[0x100:0x104]),
                        "element_count_or_limit": u32le(blob, 0x104),
                        "digest": hex_bytes(blob[0x120:0x140]),
                    },
                    "secondary_descriptor": {
                        "id": hex_bytes(blob[0x140:0x144]),
                        "element_count_or_limit": u32le(blob, 0x144),
                        "digest": hex_bytes(blob[0x160:0x180]),
                    },
                    "descriptor_ids_match_index": descriptor_ids_match,
                    "size_fields_consistent": size_consistent,
                }
                item_result["payload"] = {
                    "encoding": "uint32-le: leading FFFFFFFF, selected indexes, FFFFFFFF padding",
                    "layout_valid": layout_valid,
                    "selected_indexes_strictly_increasing": selected_valid,
                    "first_selected_index": selected[0] if selected else None,
                    "last_selected_index": selected[-1] if selected else None,
                    "padding_sentinel_count": max(0, element_capacity - selected_count),
                }
            else:
                all_layouts_valid = all_headers_consistent = False
            result["records"].append(item_result)
            previous_end = offset + size

    trailing_size = file_size - previous_end
    trailing_is_zero = trailing_size >= 0
    if trailing_size > 0:
        with path.open("rb") as stream:
            stream.seek(previous_end)
            trailing_is_zero = not any(stream.read())
    result.update({
        "all_record_sha3_256_valid": all_hashes_valid,
        "all_payload_layouts_valid": all_layouts_valid,
        "all_headers_consistent_with_index": all_headers_consistent,
        "trailing_size": trailing_size,
        "trailing_is_zero": trailing_is_zero,
    })
    return result


def parse_playgo_chunk(data: bytes) -> dict[str, Any] | None:
    if len(data) < 0x100 or data[:4] != b"plgx":
        return None
    declared_size = u32le(data, 0x10)
    chunk_count = u16le(data, 0x0A)
    scenario_count = u16le(data, 0x0E)
    result: dict[str, Any] = {
        "format": "PS5 PlayGo chunk layout",
        "magic": "plgx",
        "version_major": hx(u16le(data, 4)),
        "version_minor": hx(u16le(data, 6)),
        "image_count": u16le(data, 8),
        "chunk_count": chunk_count,
        "mchunk_count": u16le(data, 0x0C),
        "scenario_count": scenario_count,
        "declared_file_size": declared_size,
        "available_file_size": len(data),
        "declared_file_size_valid": declared_size == len(data),
        "default_scenario_id": u16le(data, 0x14),
        "attributes": hx(u16le(data, 0x16)),
        "sdk_version": hx(u32le(data, 0x18)),
        "disc_count": u16le(data, 0x1C),
        "layer_bitmap": hx(u16le(data, 0x1E)),
        "language_slot_count": u32le(data, 0x20),
        "default_language_index": u32le(data, 0x24),
        "language_profile": hx(u64le(data, 0x28)),
        "language_attributes": hx(u64le(data, 0x30)),
        "default_language_mask": hx(u64le(data, 0x38)),
        "content_id": ascii_z(data[0x40:0x70]),
        "reserved_0x70_0xBF_is_zero": not any(data[0x70:0xC0]),
    }

    section_names = [
        "chunk_attributes",
        "chunk_mchunk_indices",
        "chunk_labels",
        "mchunk_attributes",
        "scenario_attributes",
        "scenario_chunk_indices",
        "scenario_labels",
        "reserved_section",
    ]
    sections: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(section_names):
        at = 0xC0 + index * 8
        offset, size = u32le(data, at), u32le(data, at + 4)
        range_valid = offset <= len(data) and size <= len(data) - offset
        if declared_size:
            range_valid &= offset <= declared_size and size <= declared_size - offset
        sections[name] = {
            "offset": offset,
            "size": size,
            "range_valid": range_valid,
        }
    result["sections"] = sections

    def section_bytes(name: str) -> bytes:
        section = sections[name]
        if not section["range_valid"]:
            return b""
        offset, size = int(section["offset"]), int(section["size"])
        return data[offset:offset + size]

    def string_at(table: bytes, offset: int) -> str | None:
        if offset < 0 or offset >= len(table):
            return None
        end = table.find(b"\0", offset)
        if end < 0:
            end = len(table)
        return table[offset:end].decode("utf-8", errors="replace")

    def string_table(table: bytes) -> list[dict[str, Any]]:
        strings = []
        offset = 0
        while offset < len(table):
            end = table.find(b"\0", offset)
            if end < 0:
                end = len(table)
            strings.append({
                "offset": offset,
                "value": table[offset:end].decode("utf-8", errors="replace"),
            })
            if end == len(table):
                break
            offset = end + 1
        return strings

    chunk_index_data = section_bytes("chunk_mchunk_indices")
    chunk_indices = [
        u32le(chunk_index_data, offset)
        for offset in range(0, len(chunk_index_data) - 3, 4)
    ]
    chunk_labels_data = section_bytes("chunk_labels")
    result["chunk_mchunk_indices_u32le"] = chunk_indices
    result["chunk_labels"] = string_table(chunk_labels_data)

    chunk_attr_data = section_bytes("chunk_attributes")
    chunks = []
    for index in range(min(chunk_count, len(chunk_attr_data) // 0x20)):
        at = index * 0x20
        mchunk_count = u16le(chunk_attr_data, at + 0x04)
        mchunk_offset = u32le(chunk_attr_data, at + 0x18)
        label_offset = u32le(chunk_attr_data, at + 0x1C)
        indexes_valid = (
            mchunk_offset <= len(chunk_index_data)
            and mchunk_count * 4 <= len(chunk_index_data) - mchunk_offset
        )
        mchunks = [
            u32le(chunk_index_data, mchunk_offset + item * 4)
            for item in range(mchunk_count)
        ] if indexes_valid else []
        chunks.append({
            "id": index,
            "flags": hx(chunk_attr_data[at]),
            "image_disc_layer_number": chunk_attr_data[at + 1],
            "required_locus": chunk_attr_data[at + 2],
            "profile_byte": hx(chunk_attr_data[at + 3]),
            "mchunk_count": mchunk_count,
            "profile_word": hx(u16le(chunk_attr_data, at + 0x06)),
            "attributes": hx(u64le(chunk_attr_data, at + 0x08)),
            "language_mask": hx(u64le(chunk_attr_data, at + 0x10)),
            "mchunk_indices_offset": mchunk_offset,
            "mchunk_indices_valid": indexes_valid,
            "mchunk_indices": mchunks,
            "label_offset": label_offset,
            "label": string_at(chunk_labels_data, label_offset),
        })
    result["chunks"] = chunks
    result["chunk_count_matches_section"] = len(chunks) == chunk_count

    mchunk_attr_data = section_bytes("mchunk_attributes")
    mchunks = []
    for index in range(len(mchunk_attr_data) // 0x10):
        offset = u64le(mchunk_attr_data, index * 0x10)
        size = u64le(mchunk_attr_data, index * 0x10 + 8)
        mchunks.append({
            "id": index,
            "offset": offset,
            "size": size,
            "end": offset + size,
        })
    result["mchunk_attributes"] = mchunks
    result["mchunk_attribute_record_size"] = 0x10
    result["mchunk_attribute_section_aligned"] = len(mchunk_attr_data) % 0x10 == 0

    scenario_chunk_data = section_bytes("scenario_chunk_indices")
    scenario_chunk_indices = [
        u16le(scenario_chunk_data, offset)
        for offset in range(0, len(scenario_chunk_data) - 1, 2)
    ]
    scenario_labels_data = section_bytes("scenario_labels")
    result["scenario_chunk_indices_u16le"] = scenario_chunk_indices
    result["scenario_labels"] = string_table(scenario_labels_data)

    scenario_attr_data = section_bytes("scenario_attributes")
    scenarios = []
    for index in range(min(scenario_count, len(scenario_attr_data) // 0x20)):
        at = index * 0x20
        initial_count = u16le(scenario_attr_data, at + 0x14)
        scenario_chunk_count = u16le(scenario_attr_data, at + 0x16)
        chunk_offset = u32le(scenario_attr_data, at + 0x18)
        label_offset = u32le(scenario_attr_data, at + 0x1C)
        indexes_valid = (
            chunk_offset <= len(scenario_chunk_data)
            and scenario_chunk_count * 2 <= len(scenario_chunk_data) - chunk_offset
        )
        scenario_chunks = [
            u16le(scenario_chunk_data, chunk_offset + item * 2)
            for item in range(scenario_chunk_count)
        ] if indexes_valid else []
        type_code = scenario_attr_data[at]
        scenarios.append({
            "id": index,
            "type_code": hx(type_code),
            "type_name": {0x21: "playmode"}.get(type_code, "unrecognized"),
            "profile_0x01_0x13": hex_bytes(scenario_attr_data[at + 1:at + 0x14]),
            "initial_chunk_count": initial_count,
            "chunk_count": scenario_chunk_count,
            "chunk_indices_offset": chunk_offset,
            "chunk_indices_valid": indexes_valid,
            "chunk_indices": scenario_chunks,
            "label_offset": label_offset,
            "label": string_at(scenario_labels_data, label_offset),
        })
    result["scenarios"] = scenarios
    result["scenario_count_matches_section"] = len(scenarios) == scenario_count
    result["layout_valid"] = (
        result["declared_file_size_valid"]
        and all(section["range_valid"] for section in sections.values())
        and result["chunk_count_matches_section"]
        and result["scenario_count_matches_section"]
        and result["mchunk_attribute_section_aligned"]
        and all(chunk["mchunk_indices_valid"] for chunk in chunks)
        and all(scenario["chunk_indices_valid"] for scenario in scenarios)
    )
    return result


def parse_playgo_ficm(data: bytes) -> dict[str, Any] | None:
    if len(data) < 0x10:
        return None
    offset, count = u32le(data, 8), u32le(data, 0x0C)
    if offset > len(data) or count > len(data) - offset:
        return None
    values = list(data[offset:offset + count])
    return {
        "format": "PlayGo file-to-chunk map",
        "version": u32le(data, 0),
        "flags": hx(u32le(data, 4)),
        "array_offset": offset,
        "file_count": count,
        "declared_size_valid": offset + count == len(data),
        "per_file_values_histogram": {
            str(value): values.count(value)
            for value in sorted(set(values))
        },
        "chunk_id_per_file": values,
    }


def parse_playgo_hash_table(data: bytes) -> dict[str, Any] | None:
    if len(data) < 0x38 or data[0x18:0x1C] != b"\x7fFLT":
        return None
    offset, size, count = u32le(data, 8), u32le(data, 0x0C), u32le(data, 0x24)
    if offset > len(data) or size > len(data) - offset:
        return None
    available_count = min(count, size // 8)
    items = [u64le(data, offset + index * 8) for index in range(available_count)]
    return {
        "format": "PlayGo flat-path hash table",
        "version": u32le(data, 0),
        "flags": hx(u32le(data, 4)),
        "table_offset": offset,
        "table_size": size,
        "reserved_0x10_0x17": hex_bytes(data[0x10:0x18]),
        "magic": "7F464C54",
        "reserved_0x1C_0x23": hex_bytes(data[0x1C:0x24]),
        "item_count": count,
        "prefix": hex_bytes(data[0x28:0x38]),
        "item_count_matches_table_size": count * 8 == size,
        "table_reaches_end_of_file": offset + size == len(data),
        "items_strictly_increasing": all(left < right for left, right in zip(items, items[1:])),
        "duplicate_item_count": len(items) - len(set(items)),
        "items_u64le": [hx(value) for value in items],
    }


def parse_png(data: bytes) -> dict[str, Any] | None:
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        return {"format": "PNG", "width": u32be(data, 16), "height": u32be(data, 20)}
    return None


def parse_dds(data: bytes) -> dict[str, Any] | None:
    if len(data) < 128 or data[:4] != b"DDS ":
        return None
    result: dict[str, Any] = {
        "format": "DDS",
        "height": u32le(data, 12),
        "width": u32le(data, 16),
        "mip_count": u32le(data, 28),
        "fourcc": data[84:88].decode("ascii", errors="replace"),
    }
    if data[84:88] == b"DX10" and len(data) >= 148:
        result["dxgi_format"] = u32le(data, 128)
        result["resource_dimension"] = u32le(data, 132)
        result["array_size"] = u32le(data, 140)
    return result


def parse_sfo(data: bytes) -> dict[str, Any] | None:
    if len(data) < 0x14 or data[:4] not in (b"\x00PSF", b"PSF\x00"):
        return None
    key_offset = u32le(data, 8)
    value_offset = u32le(data, 12)
    count = u32le(data, 16)
    if count > 0x10000 or 0x14 + count * 0x10 > len(data):
        return None
    values: dict[str, Any] = {}
    for index in range(count):
        at = 0x14 + index * 0x10
        key_rel, fmt = u16le(data, at), u16le(data, at + 2)
        value_len, value_max, value_rel = u32le(data, at + 4), u32le(data, at + 8), u32le(data, at + 12)
        key_at = key_offset + key_rel
        value_at = value_offset + value_rel
        if key_at >= len(data) or value_at > len(data) or value_len > len(data) - value_at:
            continue
        key_end = data.find(b"\0", key_at)
        if key_end < 0:
            continue
        key = data[key_at:key_end].decode("utf-8", errors="replace")
        raw = data[value_at:value_at + value_len]
        if fmt in (0x0204, 0x0004):
            value: Any = raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
        elif fmt == 0x0404 and len(raw) >= 4:
            value = u32le(raw, 0)
        else:
            value = hex_bytes(raw)
        values[key] = {"format": hx(fmt), "value": value, "max_length": value_max}
    return {"format": "SFO", "values": values}


def parse_npbind(data: bytes) -> dict[str, Any] | None:
    """Validate npbind.dat and expose its public TLV records."""
    if len(data) != 0x214 or data[:4] != bytes.fromhex("D294A018"):
        return None
    stored_digest = data[0x200:0x214]
    records: list[dict[str, Any]] = []
    np_comm_id: str | None = None
    cursor = 0x80
    while cursor + 4 <= 0x200:
        tag, size = u16be(data, cursor), u16be(data, cursor + 2)
        if tag == 0 and size == 0:
            break
        cursor += 4
        if cursor + size > 0x200:
            return {
                "format": "NPBIND",
                "parse_error": f"TLV {hx(tag)} overruns the signed data area",
            }
        value = data[cursor:cursor + size]
        item: dict[str, Any] = {"tag": hx(tag), "size": size, "value_hex": hex_bytes(value)}
        if tag in (0x10, 0x11):
            item["text"] = ascii_z(value)
        if tag == 0x10:
            np_comm_id = ascii_z(value)
        records.append(item)
        cursor += size
    return {
        "format": "NPBIND",
        "version": u32be(data, 4),
        "declared_size": u32be(data, 0x0C),
        "np_communication_id": np_comm_id,
        "records": records,
        "sha1": hex_bytes(stored_digest),
        "sha1_valid": hmac.compare_digest(stored_digest, hashlib.sha1(data[:0x200]).digest()),
    }


def parse_license_dat(data: bytes) -> dict[str, Any]:
    """Classify decrypted license.dat without treating a retail zero slot as a bad RIF."""
    result: dict[str, Any] = {
        "format": "license.dat",
        "size": len(data),
        "expected_size": 0x400,
        "size_valid": len(data) == 0x400,
        "nonzero_byte_count": sum(value != 0 for value in data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
    }
    if len(data) == 0x400 and not any(data):
        result.update({
            "profile": "retail-zero-placeholder",
            "is_zero_placeholder": True,
            "note": (
                "The publisher encrypted an all-zero 0x400-byte license slot. "
                "A user/backend-issued RIF is not present in this PKG entry."
            ),
        })
        return result
    result["is_zero_placeholder"] = False
    if data[:4] == b"RIF\0":
        result.update({
            "profile": "RIF-license-record",
            "magic": "RIF\\0",
            "content_id": ascii_z(data[0x20:0x50]) if len(data) >= 0x50 else "",
        })
    else:
        result["profile"] = "unrecognized-nonzero-license-record"
        result["leading_bytes"] = hex_bytes(data[:16])
    return result


def parse_license_info(data: bytes) -> dict[str, Any]:
    """Expose the known clear fields of a decrypted 0x200-byte license.info."""
    result: dict[str, Any] = {
        "format": "license.info",
        "size": len(data),
        "expected_size": 0x200,
        "size_valid": len(data) == 0x200,
        "sha256": hashlib.sha256(data).hexdigest().upper(),
    }
    if len(data) >= 0x30:
        result["content_id"] = ascii_z(data[:0x30])
    if len(data) >= 0x40:
        result["entitlement_key"] = hex_bytes(data[0x30:0x40])
    return result


def parse_nptitle(data: bytes) -> dict[str, Any] | None:
    """Parse the public framing of a decrypted nptitle.dat descriptor."""
    if len(data) != 0xA0 or data[:4] != b"NPTD":
        return None
    signature_offset = u32be(data, 4)
    return {
        "format": "NPTITLE",
        "magic": "NPTD",
        "size": len(data),
        "signature_offset": signature_offset,
        "signature_offset_valid": signature_offset == 0x80,
        "title_id": ascii_z(data[0x10:0x20]),
        "header_reserved": hex_bytes(data[0x20:min(signature_offset, len(data))]),
        "signature_size": max(0, len(data) - signature_offset) if signature_offset <= len(data) else 0,
        "signature_sha256": (
            hashlib.sha256(data[signature_offset:]).hexdigest().upper()
            if signature_offset <= len(data) else None
        ),
    }


def parse_ucp(data: bytes) -> dict[str, Any] | None:
    """Parse and authenticate a PS5 trophy2/UDS UCP archive."""
    if len(data) < 0x60 or data[:4] != UCP_MAGIC:
        return None
    version = u32be(data, 4)
    total_size = u64be(data, 8)
    count = u32be(data, 0x10)
    record_size = u32be(data, 0x14)
    if version != 1:
        raise PkgError(f"Unsupported UCP version {version}")
    if total_size != len(data):
        raise PkgError(f"UCP size field {total_size} does not match {len(data)} bytes")
    if record_size != 0x40:
        raise PkgError(f"Unexpected UCP record size {hx(record_size)}")
    if count > MAX_ENTRIES or 0x60 + count * record_size > len(data):
        raise PkgError("UCP entry table is outside the archive")

    members: list[dict[str, Any]] = []
    seen: set[str] = set()
    table_end = 0x60 + count * record_size
    for index in range(count):
        record = 0x60 + index * record_size
        name = data[record:record + 0x20].split(b"\0", 1)[0].decode("latin-1")
        offset = u64be(data, record + 0x20)
        size = u64be(data, record + 0x28)
        if not name or name in seen:
            raise PkgError(f"UCP member {index} has an empty or duplicate name")
        safe_name = safe_parts(name)
        if (len(safe_name) != 1 or safe_name[0] != name or name in (".", "..")
                or "/" in name or "\\" in name):
            raise PkgError(f"Unsafe UCP member name: {name!r}")
        if offset < table_end or offset > len(data) or size > len(data) - offset:
            raise PkgError(f"UCP member {name!r} is outside the blob region")
        seen.add(name)
        payload = data[offset:offset + size]
        members.append({
            "index": index,
            "name": name,
            "offset": offset,
            "size": size,
            "sha256": hashlib.sha256(payload).hexdigest().upper(),
            "reserved": hex_bytes(data[record + 0x30:record + 0x40]),
        })

    stored_digest = data[0x1C:0x30]
    digest_input = bytearray(data)
    digest_input[0x1C:0x30] = bytes(20)
    computed_digest = hashlib.sha1(digest_input).digest()
    return {
        "format": "UCP",
        "version": version,
        "total_size": total_size,
        "entry_count": count,
        "entry_record_size": record_size,
        "header_reserved": hex_bytes(data[0x18:0x1C] + data[0x30:0x60]),
        "stored_sha1": hex_bytes(stored_digest),
        "computed_sha1": hex_bytes(computed_digest),
        "sha1_valid": hmac.compare_digest(stored_digest, computed_digest),
        "members": members,
    }


def extract_ucp(data: bytes, destination: Path, np_comm_id: str | None) -> dict[str, Any]:
    """Extract a validated UCP and decode every locally understood member."""
    parsed = parse_ucp(data)
    if parsed is None:
        raise PkgError("Data does not start with a UCP archive")
    destination.mkdir(parents=True, exist_ok=True)
    decoded: list[dict[str, Any]] = []
    for member in parsed["members"]:
        name = member["name"]
        offset, size = int(member["offset"]), int(member["size"])
        payload = data[offset:offset + size]
        target = destination / safe_parts(name)[0]
        target.resolve().relative_to(destination.resolve())
        target.write_bytes(payload)
        item: dict[str, Any] = {"name": name, "output": target.name}
        lower = name.lower()
        if lower.endswith(".json"):
            try:
                value = json.loads(payload.decode("utf-8-sig"))
                decoded_target = target.with_suffix(target.suffix + ".decoded.json")
                json_write(decoded_target, value)
                item.update({"decoded_format": "JSON", "decoded_output": decoded_target.name})
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                item["decode_error"] = str(error)
        elif lower.endswith((".esfm", ".esfm.bin", ".enc")):
            if np_comm_id is None:
                item["decryption_error"] = "NP Communication ID is unavailable"
            else:
                attempts = (("release", TROPHY_MASTER_RELEASE), ("debug", TROPHY_MASTER_DEBUG))
                for profile, key in attempts:
                    try:
                        plaintext = decrypt_trophy_esfm(payload, np_comm_id, key)
                    except PkgError as error:
                        item["decryption_error"] = str(error)
                        break
                    # ESFM has no universal magic. Prefer a result recognizable as
                    # JSON/XML/PNG and otherwise retain both candidates explicitly.
                    recognizable = (
                        plaintext.startswith(b"\x89PNG\r\n\x1a\n")
                        or plaintext.lstrip().startswith((b"{", b"[", b"<"))
                    )
                    out = target.with_name(f"{target.name}.{profile}.decrypted")
                    out.write_bytes(plaintext)
                    item.setdefault("decryption_attempts", []).append({
                        "profile": profile,
                        "output": out.name,
                        "recognizable_plaintext": recognizable,
                    })
                    if recognizable:
                        break
        elif lower.endswith(".pfenc"):
            item["decryption_error"] = (
                "PFENC is an NpTrophy v2 scheme and does not use the public legacy trophy master key"
            )
        decoded.append(item)
    parsed["extracted_members"] = decoded
    json_write(destination / "_ucp_manifest.json", parsed)
    return parsed


def annotate_entry(entry: dict[str, Any], data: bytes) -> dict[str, Any] | None:
    entry_id = entry["id_value"]
    name = entry["name"].lower()
    if entry_id == 0x0001:
        return {
            "digest_count": len(data) // 32,
            "entry_digests_sha3_256": [
                hex_bytes(data[index:index + 32])
                for index in range(0, len(data) - 31, 32)
            ],
        }
    if entry_id == 0x0010:
        return parse_entry_keys(data)
    if entry_id == 0x0020:
        return parse_image_key(data)
    if entry_id == 0x0080:
        return parse_general_digests(data)
    if entry_id == 0x00C0:
        return parse_rlc_index(data)
    if entry_id == 0x0100:
        return parse_meta_records(data)
    if entry_id == 0x0200:
        return parse_name_table(data)
    if entry_id == 0x0400 or name.endswith("license.dat"):
        return parse_license_dat(data)
    if entry_id == 0x0401 or name.endswith("license.info"):
        return parse_license_info(data)
    if entry_id == 0x0402 or name.endswith("nptitle.dat"):
        parsed = parse_nptitle(data)
        if parsed:
            return parsed
    if entry_id == 0x040A or name.endswith("imagedigs.dat"):
        return {
            "outer_block_digest_count": len(data) // 32,
            "stored_reversed_sha3_digests": [hex_bytes(data[i:i + 32]) for i in range(0, len(data) - 31, 32)],
            "normalized_sha3_digests": [hex_bytes(data[i:i + 32][::-1]) for i in range(0, len(data) - 31, 32)],
        }
    if entry_id in (0x0403, 0x2020, 0x2021) or name.endswith("npbind.dat"):
        parsed = parse_npbind(data)
        if parsed:
            return parsed
    if entry_id in UCP_ENTRY_IDS or name.endswith(".ucp"):
        parsed = parse_ucp(data)
        if parsed:
            return parsed
    if entry_id == 0x040C or data[:4] == RLC_MAGIC:
        parsed = parse_rlc_header(data)
        if parsed:
            parsed["role"] = (
                "header-only first RLC record template"
                if not parsed["complete_record_present"]
                else "complete RLC record"
            )
            return parsed
    parsed = parse_playgo_chunk(data)
    if parsed:
        return parsed
    if entry_id == 0x2011 or name.endswith("playgo-ficm.dat"):
        parsed = parse_playgo_ficm(data)
        if parsed:
            return parsed
    if entry_id == 0x2010 or name.endswith("playgo-hash-table.dat"):
        parsed = parse_playgo_hash_table(data)
        if parsed:
            return parsed
    parsed = parse_png(data) or parse_dds(data) or parse_sfo(data)
    if parsed:
        return parsed
    if name.endswith(".json"):
        try:
            return {"format": "JSON", "value": json.loads(data.decode("utf-8-sig"))}
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            return {"format": "JSON", "parse_error": str(error)}
    if name.endswith(".xml"):
        try:
            text = data.decode("utf-8-sig")
            return {"format": "XML", "character_count": len(text)}
        except UnicodeDecodeError as error:
            return {"format": "XML", "parse_error": str(error)}
    return None


def parse_signed_inode64(data: bytes, offset: int) -> dict[str, Any] | None:
    if offset < 0 or len(data) < offset + 0x310:
        return None
    result: dict[str, Any] = {
        "mode": hx(u16le(data, offset)),
        "link_count": u16le(data, offset + 0x02),
        "flags": hx(u32le(data, offset + 0x04)),
        "size": i64le(data, offset + 0x08),
        "compressed_size": i64le(data, offset + 0x10),
        "timestamps_seconds": [i64le(data, offset + 0x18 + index * 8) for index in range(4)],
        "timestamps_nanoseconds": [u32le(data, offset + 0x38 + index * 4) for index in range(4)],
        "uid": u32le(data, offset + 0x48),
        "gid": u32le(data, offset + 0x4C),
        # These words are preserved by every inode conversion path and are zero
        # in generated images; no active filesystem behavior uses them.
        "reserved_inode_word_0": hx(u64le(data, offset + 0x50)),
        "reserved_inode_word_1": hx(u64le(data, offset + 0x58)),
        "block_count": u64le(data, offset + 0x60),
    }

    def block_records(start: int, count: int) -> list[dict[str, Any]]:
        records = []
        for index in range(count):
            at = offset + start + index * 0x28
            signature = data[at:at + 32]
            block = i64le(data, at + 32)
            records.append({
                "index": index,
                "sha3_256": hex_bytes(signature),
                "block": block,
                "populated": block != 0 or any(signature),
            })
        return records

    result["direct_blocks"] = block_records(0x68, 12)
    result["indirect_blocks"] = block_records(0x248, 5)
    return result


def parse_outer_superblock(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "sha3_256": hashlib.sha3_256(data).hexdigest().upper(),
    }
    if len(data) < 0x5A0:
        result["parse_error"] = "Superblock is smaller than 0x5A0 bytes"
        return result
    result.update({
        "version": i64le(data, 0x00),
        "magic": i64le(data, 0x08),
        "id": hx(u64le(data, 0x10)),
        "fmode": hx(data[0x18]),
        "clean": data[0x19],
        "read_only": data[0x1A],
        "mode": hx(u16le(data, 0x1C)),
        # Reserved profile word following the PFS mode flags; builders emit 0.
        "reserved_profile_word": hx(u16le(data, 0x1E)),
        "block_size": u32le(data, 0x20),
        "backup_count": u32le(data, 0x24),
        "block_count": i64le(data, 0x28),
        "dinode_count": i64le(data, 0x30),
        "data_block_count": i64le(data, 0x38),
        "dinode_block_count": i64le(data, 0x40),
        # Selector immediately preceding the seed.  Known writers use 0 or 1;
        # it behaves as a seed/key-profile index, not as encrypted key bytes.
        "seed_key_profile_index": u32le(data, 0x36C),
        "seed": hex_bytes(data[0x370:0x380]),
        "stored_icv": hex_bytes(data[0x380:0x3A0]),
    })
    icv_input = bytearray(data[:0x5A0])
    icv_input[0x380:0x3A0] = bytes(32)
    actual_icv = hashlib.sha3_256(icv_input).digest()
    result["computed_icv"] = hex_bytes(actual_icv)
    result["icv_valid"] = actual_icv == data[0x380:0x3A0]
    result["shape_valid"] = result["version"] == 2 and result["magic"] == 20130315
    root_inode = parse_signed_inode64(data, 0x50)
    if root_inode is not None:
        result["root_inode_and_inode_table_descriptor"] = root_inode
    return result


def _decode_naps_meta18_payload(tag: str, payload: bytes) -> dict[str, Any] | None:
    """Decode every currently modeled publisher NAPS TLV payload."""
    if tag == "phdr" and len(payload) == 0x18:
        values = struct.unpack_from("<6I", payload)
        return {
            "format_version": values[0],
            "header_size": values[1],
            "physical_inner_block_count": values[2],
            "physical_bytes_before_final_block": values[3],
            "image_count": values[4],
            "block_size": values[5],
        }
    if tag == "file" and len(payload) % 0x18 == 0:
        entries = []
        for offset in range(0, len(payload), 0x18):
            entries.append({
                "size": u64le(payload, offset),
                "first_mapping_block": u32le(payload, offset + 0x08),
                "mapping_block_count": u32le(payload, offset + 0x0C),
                "metadata_kind": hx(u32le(payload, offset + 0x10)),
                "is_executable": bool(u32le(payload, offset + 0x14)),
            })
        return {"entry_size": 0x18, "entries": entries}
    if tag == "ftyp" and len(payload) % 0x38 == 0:
        entries = []
        for offset in range(0, len(payload), 0x38):
            entries.append({
                "profile": u64le(payload, offset),
                "logical_size": u64le(payload, offset + 0x08),
                "logical_size_mirror": u64le(payload, offset + 0x10),
                "mapping_block_count": u64le(payload, offset + 0x18),
                "reserved_words": [u64le(payload, offset + item) for item in (0x20, 0x28, 0x30)],
            })
        return {"entry_size": 0x38, "entries": entries}
    if tag == "ibcl":
        histogram: dict[str, int] = {}
        for value in payload:
            name = hx(value)
            histogram[name] = histogram.get(name, 0) + 1
        return {
            "block_count": len(payload),
            "class_histogram": histogram,
            "classes": [hx(value) for value in payload],
        }
    if tag == "i2ob" and len(payload) % 0x28 == 0:
        blocks = []
        for offset in range(0, len(payload), 0x28):
            blocks.append({
                "compressed_offset": u64le(payload, offset),
                "stored_size": u32le(payload, offset + 0x08),
                "plaintext_size": u32le(payload, offset + 0x0C),
                "first_subchunk_size": u32le(payload, offset + 0x10),
                "second_subchunk_size": u32le(payload, offset + 0x14),
                "physical_block_index": u32le(payload, offset + 0x18),
                "reserved": u32le(payload, offset + 0x1C),
                "image_index": u32le(payload, offset + 0x20),
                "block_flags": hx(u32le(payload, offset + 0x24)),
            })
        return {"entry_size": 0x28, "blocks": blocks}
    if tag == "i2op" and len(payload) % 0x10 == 0:
        return {
            "entry_size": 0x10,
            "blocks": [
                {
                    "compressed_offset": u64le(payload, offset),
                    "physical_block_index": u64le(payload, offset + 0x08),
                }
                for offset in range(0, len(payload), 0x10)
            ],
        }
    if tag == "ihsh" and len(payload) % 0x30 == 0:
        return {
            "entry_size": 0x30,
            "blocks": [
                {
                    "weak_checksum": hex_bytes(payload[offset:offset + 8]),
                    "sha3_256": hex_bytes(payload[offset + 8:offset + 0x28]),
                    "kind_or_tail": hx(u64le(payload, offset + 0x28)),
                }
                for offset in range(0, len(payload), 0x30)
            ],
        }
    if tag == "rhsh" and len(payload) % 8 == 0:
        return {
            "entry_size": 8,
            "rolling_hashes": [
                {"raw": hex_bytes(payload[offset:offset + 8]), "value_le": hx(u64le(payload, offset))}
                for offset in range(0, len(payload), 8)
            ],
        }
    if tag == "fstr":
        return {
            "paths": [
                value.decode("ascii", errors="replace")
                for value in payload.split(b"\0")
                if value
            ]
        }
    if tag == "twek" and len(payload) == 0x14:
        values = struct.unpack_from("<5I", payload)
        return {
            "reserved_0": values[0],
            "physical_inner_block_count": values[1],
            "reserved_1": values[2],
            "reserved_2": values[3],
            "reserved_3": values[4],
        }
    if tag == "obdg" and len(payload) % 32 == 0:
        return {
            "digest_size": 32,
            "sha3_256_by_physical_block": [
                hex_bytes(payload[offset:offset + 32])
                for offset in range(0, len(payload), 32)
            ],
        }
    if tag == "obcc" and len(payload) % 4 == 0:
        return {
            "entry_size": 4,
            "crc32c_after_temporary_xts": [
                f"{u32le(payload, offset):08X}" for offset in range(0, len(payload), 4)
            ],
        }
    if tag in {"pgpl", "pgil", "pgpi", "pgpu"} and len(payload) == 48:
        values = struct.unpack_from("<6Q", payload)
        return {
            "record_start_offset": values[0],
            "reserved": values[1],
            "leading_extent_size": values[2],
            "kind_or_version": values[3],
            "leading_extent_size_mirror": values[4],
            "trailing_extent_size": values[5],
        }
    if tag in {"gitt", "gith"}:
        return {"text": ascii_z(payload)}
    if tag == "zero":
        return {"padding_size": len(payload), "all_zero": not any(payload)}
    return None


def parse_naps_meta18_plaintext(plain: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    offset = 0
    occurrences: dict[str, int] = {}
    while offset < len(plain):
        if len(plain) - offset < 16:
            raise PkgError(f"Truncated naps_meta_18 record header at {hx(offset)}")
        tag_bytes = plain[offset:offset + 4][::-1]
        if any(value < 0x20 or value > 0x7E for value in tag_bytes):
            raise PkgError(f"Invalid naps_meta_18 tag at {hx(offset)}: {hex_bytes(tag_bytes)}")
        tag = tag_bytes.decode("ascii")
        version = plain[offset + 4]
        length = u64le(plain, offset + 8)
        payload_offset = offset + 16
        if length > len(plain) - payload_offset:
            raise PkgError(
                f"naps_meta_18 record {tag!r} at {hx(offset)} exceeds the plaintext")
        payload = plain[payload_offset:payload_offset + length]
        occurrences[tag] = occurrences.get(tag, 0) + 1
        record: dict[str, Any] = {
            "index": len(records),
            "tag": tag,
            "occurrence": occurrences[tag],
            "version": version,
            "header_reserved": hex_bytes(plain[offset + 5:offset + 8]),
            "record_offset": offset,
            "payload_offset": payload_offset,
            "payload_size": length,
            "payload_sha256": hashlib.sha256(payload).hexdigest().upper(),
            "_payload": payload,
        }
        decoded = _decode_naps_meta18_payload(tag, payload)
        if decoded is not None:
            record["decoded"] = decoded
        records.append(record)
        offset = payload_offset + length

    paths: list[str] = []
    for record in records:
        if record["tag"] == "fstr" and "decoded" in record:
            paths = record["decoded"]["paths"]
            break
    if paths:
        for record in records:
            decoded = record.get("decoded")
            if record["tag"] in {"file", "ftyp"} and isinstance(decoded, dict):
                for index, entry in enumerate(decoded.get("entries", [])):
                    if index < len(paths):
                        entry["path"] = paths[index]
    return records


def export_naps_meta18(encrypted_path: Path) -> dict[str, Any]:
    encrypted = encrypted_path.read_bytes()
    plain = decrypt_naps_meta18(encrypted)
    records = parse_naps_meta18_plaintext(plain)

    stem = encrypted_path.stem
    plaintext_path = encrypted_path.with_name(f"{stem}.plaintext.bin")
    records_path = encrypted_path.with_name(f"{stem}.records")
    metadata_path = encrypted_path.with_name(f"{stem}.json")
    plaintext_path.write_bytes(plain)
    records_path.mkdir(parents=True, exist_ok=True)

    public_records: list[dict[str, Any]] = []
    for record in records:
        payload = record.pop("_payload")
        suffix = "" if record["occurrence"] == 1 else f"_{record['occurrence']}"
        safe_tag = re.sub(r"[^A-Za-z0-9_-]", "_", record["tag"])
        payload_path = records_path / f"{safe_tag}{suffix}.bin"
        payload_path.write_bytes(payload)
        record["payload_file"] = str(payload_path.relative_to(encrypted_path.parent))
        public_records.append(record)

    result = {
        "ciphertext_size": len(encrypted),
        "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest().upper(),
        "plaintext_size": len(plain),
        "plaintext_sha256": hashlib.sha256(plain).hexdigest().upper(),
        "plaintext_file": plaintext_path.name,
        "record_directory": records_path.name,
        "record_count": len(public_records),
        "records": public_records,
    }
    json_write(metadata_path, result)
    result["metadata_file"] = metadata_path.name
    return result


def safe_extract_zip(zip_path: Path, output: Path) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as archive:
        for info in archive.infolist():
            parts = safe_parts(info.filename)
            target = output.joinpath(*parts)
            target.resolve().relative_to(output.resolve())
            record = {
                "name": info.filename,
                "compressed_size": info.compress_size,
                "size": info.file_size,
                "crc32": f"{info.CRC:08X}",
                "compression": info.compress_type,
                "is_directory": info.is_dir(),
            }
            members.append(record)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            with target.open("rb") as extracted:
                sha256 = hashlib.sha256()
                while True:
                    block = extracted.read(1024 * 1024)
                    if not block:
                        break
                    sha256.update(block)
            record["sha256"] = sha256.hexdigest().upper()
            lower_name = info.filename.lower().replace("\\", "/")
            is_meta18 = lower_name.endswith("naps_meta_18.dat")
            payload: bytes | None = None
            if is_meta18 or info.file_size <= 16 * 1024 * 1024:
                payload = target.read_bytes()
            if is_meta18:
                try:
                    record["decryption"] = export_naps_meta18(target)
                except (PkgError, OSError, ValueError, struct.error) as error:
                    record["decryption_error"] = str(error)
            if payload is not None:
                decoded: dict[str, Any] | None = None
                if lower_name.endswith("playgo-chunk.dat"):
                    decoded = parse_playgo_chunk(payload)
                elif re.search(r"naps_meta_(300|301|302|308)\.dat$", lower_name) and len(payload) == 48:
                    decoded = {
                        "format": "six-u64le",
                        "values": [u64le(payload, index * 8) for index in range(6)],
                    }
                elif lower_name.endswith("playgo-chunk.crc") and len(payload) % 4 == 0:
                    decoded = {
                        "block_count": len(payload) // 4,
                        "crc32c_u32le": [hx(u32le(payload, index)) for index in range(0, len(payload), 4)],
                    }
                elif lower_name.endswith(".json"):
                    try:
                        decoded = {"format": "JSON", "value": json.loads(payload.decode("utf-8-sig"))}
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        decoded = {"format": "JSON", "parse_error": str(error)}
                elif lower_name.endswith(".xml"):
                    try:
                        decoded = {"format": "XML", "character_count": len(payload.decode("utf-8-sig"))}
                    except UnicodeDecodeError as error:
                        decoded = {"format": "XML", "parse_error": str(error)}
                if decoded is not None:
                    record["decoded"] = decoded
    return members


def extract_package(args: argparse.Namespace) -> dict[str, Any]:
    package_path = args.package.resolve()
    output = args.output.resolve()
    if not package_path.is_file():
        raise PkgError(f"PKG was not found: {package_path}")
    if output == package_path:
        raise PkgError("The output directory is the same path as the input PKG")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise PkgError("The output directory already exists and is not empty; use a new or empty directory")
    output.mkdir(parents=True, exist_ok=True)
    file_size = package_path.stat().st_size
    report: dict[str, Any] = {
        "tool": "extract-retail-pkg-public.py",
        "package": str(package_path),
        "file_size": file_size,
        "file_size_hex": hx(file_size),
        "warnings": [],
        "limitations": [
            "Inner PPR-PFS decryption still requires its matching inner-image working key/profile.",
            "Protected CNT entries without a matching derived key remain ciphertext.",
            "The published PKG-metadata RSA key recovers only publisher ENTRY_KEYS index 3; "
            "the other indices remain wrapped unless supplied explicitly or derived from a passcode.",
            "IMAGE_KEY is wrapped under a different mount-image RSA public key whose private key is unavailable.",
            "Outer PFS decryption requires ENTRY_KEYS index 1 (EKPFS) or a matching passcode.",
        ],
    }

    with package_path.open("rb") as stream:
        magic = read_exact_at(stream, 0, 4, file_size)
        fih: dict[str, Any] | None = None
        if magic == FIH_MAGIC:
            if file_size < FIH_SIZE:
                raise PkgError("FIH PKG is shorter than the required 0x10000-byte header")
            fih_bytes = read_exact_at(stream, 0, FIH_SIZE, file_size)
            fih = parse_fih(fih_bytes)
            report["container_type"] = "FIH-retail" if fih["is_retail"] else "FIH-debug-or-other"
            report["fih"] = fih
            (output / "fih").mkdir(exist_ok=True)
            (output / "fih" / "header.bin").write_bytes(fih_bytes)
            (output / "fih" / "retail-finalization-0xF000.bin").write_bytes(fih_bytes[0xF000:0xF300])
            (output / "fih" / "finalization-region-0xF000-0xFFFF.bin").write_bytes(fih_bytes[0xF000:0x10000])
            json_write(output / "fih" / "header.json", fih)
            cnt_base = int(fih["embedded_cnt_offset"])
            pfs_offset = int(fih["pfs_offset"])
            pfs_size = int(fih["pfs_size"])
            if pfs_offset > file_size or pfs_size > file_size - pfs_offset:
                raise PkgError("The outer-PFS range from FIH is outside the file")
            if cnt_base != pfs_offset + pfs_size:
                report["warnings"].append("The embedded CNT does not immediately follow the outer PFS.")
            report["segments"] = {
                "fih": {"offset": 0, "size": FIH_SIZE},
                "outer_pfs": {"offset": pfs_offset, "size": pfs_size},
                "cnt": {"offset": cnt_base},
            }
            if args.dump_outer_pfs:
                copy_range(stream, output / "segments" / "outer-pfs.raw.bin", pfs_offset, pfs_size, file_size)
            if args.hash_outer_pfs:
                report["segments"]["outer_pfs"]["sha256"] = hash_range(stream, pfs_offset, pfs_size, "sha256")

            sb_offset = int(fih["outer_superblock_offset"])
            sb_size = int(fih["outer_superblock_size"])
            if sb_size and sb_offset <= file_size and sb_size <= file_size - sb_offset:
                sb = read_exact_at(stream, sb_offset, sb_size, file_size)
                (output / "outer-pfs").mkdir(exist_ok=True)
                (output / "outer-pfs" / "plaintext-superblock.bin").write_bytes(sb)
                sb_info = parse_outer_superblock(sb)
                sb_info["matches_fih_sblock_digest"] = (
                    sb_info["sha3_256"] == fih["sblock_digest_sha3_256"]
                )
                root_inode = sb_info.get("root_inode_and_inode_table_descriptor")
                if root_inode and root_inode["direct_blocks"]:
                    inode_table_block = root_inode["direct_blocks"][0]["block"]
                    if inode_table_block >= 0:
                        sb_info["inode_table_block"] = inode_table_block
                        sb_info["inode_table_pkg_offset"] = pfs_offset + inode_table_block * int(sb_info["block_size"])
                report["outer_pfs_superblock"] = sb_info
                json_write(output / "outer-pfs" / "plaintext-superblock.json", sb_info)
            else:
                report["warnings"].append("The FIH outer-superblock range is missing or outside the file.")
        elif magic == CNT_MAGIC:
            report["container_type"] = "bare-CNT"
            cnt_base = 0
            report["segments"] = {"cnt": {"offset": 0}}
        else:
            raise PkgError(f"Unknown magic: {magic.hex(' ').upper()}")

        cnt_header = read_exact_at(stream, cnt_base, CNT_HEADER_SIZE, file_size)
        if cnt_header[:4] != CNT_MAGIC:
            raise PkgError(f"No CNT magic at embedded-CNT offset {hx(cnt_base)}")
        cnt = parse_cnt_header(cnt_header)
        cnt["content_id_parts"] = split_content_id(cnt["content_id"])
        entries = parse_entries(stream, file_size, cnt_base, cnt)
        resolve_entry_names(stream, file_size, cnt_base, entries)

        cnt_end = max(
            CNT_HEADER_SIZE,
            int(cnt["entry_table_offset"]) + len(entries) * ENTRY_SIZE,
            int(cnt["body_offset"]) + int(cnt["body_size"]),
        )
        for entry in entries:
            cnt_end = max(cnt_end, entry["data_offset"] + entry["stored_size"])
        cnt_end = align_up(cnt_end, 16)
        if cnt_end > file_size - cnt_base:
            raise PkgError("The computed CNT range is outside the PKG")
        cnt["computed_container_size"] = cnt_end
        report["segments"]["cnt"]["size"] = cnt_end
        report["cnt"] = cnt
        report["entries"] = entries

        cnt_dir = output / "cnt"
        cnt_dir.mkdir(exist_ok=True)
        (cnt_dir / "header-0x5A0.bin").write_bytes(cnt_header)
        fixed_size = min(int(cnt["entry_table_offset"]), cnt_end)
        if fixed_size:
            copy_range(stream, cnt_dir / "fixed-info-through-entry-table.bin", cnt_base, fixed_size, file_size)
        if cnt_end >= 0x1000:
            fixed = read_exact_at(stream, cnt_base, 0x1000, file_size)
            stored_package_digest = fixed[0xFE0:0x1000]
            computed_package_digest = hashlib.sha3_256(fixed[:0xFE0]).digest()
            cnt["package_digest"] = {
                "stored": hex_bytes(stored_package_digest),
                "computed": hex_bytes(computed_package_digest),
                "valid": stored_package_digest == computed_package_digest,
            }
        if cnt_end >= 0x1180:
            authentication = read_exact_at(stream, cnt_base + 0x1000, 0x180, file_size)
            (cnt_dir / "authentication-0x1000.bin").write_bytes(authentication)
            cnt["authentication_sha256"] = hashlib.sha256(authentication).hexdigest().upper()
        if fih is not None:
            cnt_fixed_digest = cnt["pfs_signed_or_fixed_info_digest"]
            cnt["fixed_info_digest_matches_fih"] = cnt_fixed_digest == fih["fih_sha3_256"]

        plaintext_root = cnt_dir / "plaintext"
        protected_root = cnt_dir / "protected-ciphertext"
        decrypted_root = cnt_dir / "decrypted"

        supplied_keys: dict[int, tuple[bytes, str]] = {}
        if args.passcode is not None:
            for key_index in range(7):
                supplied_keys[key_index] = (
                    derive_publisher_key(cnt["content_id"], args.passcode, key_index),
                    "passcode",
                )
        if args.ekpfs is not None:
            supplied_keys[1] = (args.ekpfs, "explicit-ekpfs")
        for key_index, key in args.derived_key:
            supplied_keys[key_index] = (key, "explicit-derived-key")

        usable_keys: dict[int, bytes] = {}
        key_status: list[dict[str, Any]] = []
        entry_keys_entry = next((item for item in entries if item["id_value"] == 0x0010), None)
        stored_key_digests: list[bytes] = []
        entry_keys_data = b""
        if entry_keys_entry is not None and not entry_keys_entry["encrypted"]:
            entry_keys_data = read_exact_at(
                stream, cnt_base + entry_keys_entry["data_offset"],
                entry_keys_entry["logical_size"], file_size)
            if len(entry_keys_data) >= 32 + 7 * 32:
                stored_key_digests = [
                    entry_keys_data[32 + index * 32:64 + index * 32]
                    for index in range(7)
                ]
        metadata_rsa_status: dict[str, Any] = {
            "key_source": "built-in-published-sceshellcore-rsa3072",
            "recovered_indices": [],
        }
        if entry_keys_data:
            recovered_keys = recover_entry_keys_with_metadata_rsa(entry_keys_data)
            metadata_rsa_status["recovered_indices"] = sorted(recovered_keys)
            for key_index, key in recovered_keys.items():
                # Explicit passcode/keys take precedence over automatic recovery.
                supplied_keys.setdefault(key_index, (key, "built-in-published-metadata-rsa"))
        report["metadata_rsa_entry_key_recovery"] = metadata_rsa_status
        for key_index, (key, source) in sorted(supplied_keys.items()):
            valid: bool | None = None
            if len(stored_key_digests) == 7:
                valid = derived_key_digest(key) == stored_key_digests[key_index]
            key_status.append({"index": key_index, "source": source, "digest_valid": valid})
            if valid is not False:
                usable_keys[key_index] = key
            elif source == "passcode" and key_index == 0:
                raise PkgError("The supplied passcode does not match ENTRY_KEYS digest 0")
            else:
                report["warnings"].append(
                    f"Derived key {key_index} from {source} does not match ENTRY_KEYS and was ignored.")
        report["supplied_key_status"] = key_status

        if args.decrypt_outer_pfs and fih is not None and 1 in usable_keys:
            outer_seed = read_exact_at(
                stream, int(fih["outer_superblock_offset"]) + 0x370, 16, file_size)
            decrypted_pfs_path = output / "outer-pfs" / "decrypted.bin"
            outer_result = decrypt_outer_pfs_to_file(
                stream,
                decrypted_pfs_path,
                int(fih["pfs_offset"]),
                int(fih["pfs_size"]),
                int(fih["outer_superblock_offset"]),
                usable_keys[1],
                outer_seed,
            )
            outer_result["output"] = str(decrypted_pfs_path.relative_to(output)).replace("\\", "/")
            report["outer_pfs_decryption"] = outer_result

        annotations: dict[str, Any] = {}
        for entry in entries:
            stored_size = entry["stored_size"]
            data = read_exact_at(stream, cnt_base + entry["data_offset"], stored_size, file_size)
            target_root = protected_root if entry["encrypted"] else plaintext_root
            target = entry_output_path(target_root, entry["id_value"], entry["name"], entry["encrypted"])
            if target.exists():
                target = target.with_name(f"{target.stem}.entry-{entry['id_value']:08X}{target.suffix}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            entry["output"] = str(target.relative_to(output)).replace("\\", "/")
            entry["sha256"] = hashlib.sha256(data).hexdigest().upper()
            entry["sha3_256"] = hashlib.sha3_256(data).hexdigest().upper()
            if not entry["encrypted"]:
                annotation = annotate_entry(entry, data)
                if annotation is not None:
                    annotations[f"{entry['id_value']:08X}:{entry['name']}"] = annotation
            elif entry["key_index"] in usable_keys:
                try:
                    plain = decrypt_cnt_entry(
                        data,
                        bytes.fromhex(entry["metadata_record"]),
                        usable_keys[entry["key_index"]],
                        entry["logical_size"],
                    )
                    decrypted_target = entry_output_path(
                        decrypted_root, entry["id_value"], entry["name"], encrypted=False)
                    if decrypted_target.exists():
                        decrypted_target = decrypted_target.with_name(
                            f"{decrypted_target.stem}.entry-{entry['id_value']:08X}{decrypted_target.suffix}")
                    decrypted_target.parent.mkdir(parents=True, exist_ok=True)
                    decrypted_target.write_bytes(plain)
                    entry["decrypted_output"] = str(decrypted_target.relative_to(output)).replace("\\", "/")
                    entry["decrypted_sha256"] = hashlib.sha256(plain).hexdigest().upper()
                    entry["decryption_key_index"] = entry["key_index"]
                    annotation = annotate_entry(entry, plain)
                    if annotation is not None:
                        annotation["source"] = "decrypted"
                        annotations[f"{entry['id_value']:08X}:{entry['name']}"] = annotation
                except (PkgError, ValueError) as error:
                    entry["decryption_error"] = str(error)
                    report["warnings"].append(
                        f"Could not decrypt CNT entry {entry['id']} ({entry['name']}): {error}")
        report["decoded_entries"] = annotations

        ucp_archives: list[dict[str, Any]] = []
        for entry in entries:
            if entry["id_value"] not in UCP_ENTRY_IDS and not entry["name"].lower().endswith(".ucp"):
                continue
            source_value = entry.get("decrypted_output")
            if source_value is None and not entry["encrypted"]:
                source_value = entry.get("output")
            if source_value is None:
                archive_result = {
                    "id": entry["id"],
                    "name": entry["name"],
                    "status": "protected",
                    "required_key_index": entry["key_index"],
                    "encryption_profile": entry["encryption_profile"],
                }
                ucp_archives.append(archive_result)
                if entry["encryption_profile"] == "sealed-ucp-key0":
                    report["warnings"].append(
                        f"{entry['name']} uses the sealed UCP profile and requires publisher derived key 0; "
                        "supply --derived-key 0:HEX or the package passcode to decrypt and extract it.")
                continue

            source_path = output / source_value
            namespace = "uds" if entry["id_value"] == 0x14A0 or entry["name"].lower().startswith("uds/") else "trophy2"
            npbind_id = 0x2020 if namespace == "uds" else 0x2021
            npbind_entry = next((item for item in entries if item["id_value"] == npbind_id), None)
            np_comm_id: str | None = None
            if npbind_entry is not None:
                npbind_annotation = annotations.get(f"{npbind_id:08X}:{npbind_entry['name']}")
                if isinstance(npbind_annotation, dict):
                    value = npbind_annotation.get("np_communication_id")
                    if isinstance(value, str) and value:
                        np_comm_id = value
            archive_destination = cnt_dir / "ucp-decoded" / namespace / Path(entry["name"]).stem
            try:
                parsed_ucp = extract_ucp(source_path.read_bytes(), archive_destination, np_comm_id)
                ucp_archives.append({
                    "id": entry["id"],
                    "name": entry["name"],
                    "status": "extracted",
                    "np_communication_id": np_comm_id,
                    "sha1_valid": parsed_ucp["sha1_valid"],
                    "entry_count": parsed_ucp["entry_count"],
                    "output": str(archive_destination.relative_to(output)).replace("\\", "/"),
                })
            except (PkgError, OSError, ValueError) as error:
                ucp_archives.append({
                    "id": entry["id"], "name": entry["name"],
                    "status": "error", "error": str(error),
                })
                report["warnings"].append(f"Could not decode {entry['name']}: {error}")
        if ucp_archives:
            report["trophies_and_uds"] = {
                "legacy_trophy_master_keys_available": ["release", "debug"],
                "note": (
                    "The public trophy master keys decrypt legacy IV-prefixed ESFM members. "
                    "Retail PS5 UCP CNT records use publisher derived key index 0 first."
                ),
                "archives": ucp_archives,
            }
            json_write(cnt_dir / "trophies-and-uds.json", report["trophies_and_uds"])

        playgo_ids = [
            0x1001, 0x1002, 0x1003, 0x1008, 0x1009, 0x100A,
            0x2010, 0x2011, 0x3000,
        ]
        playgo_entries = [entry for entry in entries if entry["id_value"] in playgo_ids]
        playgo: dict[str, Any] | None = None
        if playgo_entries:
            playgo = {
                "entries": [
                    {
                        "id": entry["id"],
                        "name": entry["name"],
                        "encrypted": entry["encrypted"],
                        "logical_size": entry["logical_size"],
                        "output": entry.get("decrypted_output", entry.get("output")),
                    }
                    for entry in playgo_entries
                ],
            }

            def playgo_annotation(entry_id: int) -> dict[str, Any] | None:
                entry = next((item for item in playgo_entries if item["id_value"] == entry_id), None)
                if entry is None:
                    return None
                value = annotations.get(f"{entry_id:08X}:{entry['name']}")
                return value if isinstance(value, dict) else None

            chunk_annotation = playgo_annotation(0x1001) or playgo_annotation(0x1008)
            hash_annotation = playgo_annotation(0x2010)
            ficm_annotation = playgo_annotation(0x2011)
            scenario_annotation = playgo_annotation(0x3000)
            if chunk_annotation:
                playgo["chunk_layout"] = {
                    "content_id": chunk_annotation.get("content_id"),
                    "content_id_matches_cnt": chunk_annotation.get("content_id") == cnt["content_id"],
                    "chunk_count": chunk_annotation.get("chunk_count"),
                    "mchunk_attribute_count": len(chunk_annotation.get("mchunk_attributes", [])),
                    "scenario_count": chunk_annotation.get("scenario_count"),
                    "layout_valid": chunk_annotation.get("layout_valid"),
                }
            if hash_annotation and ficm_annotation:
                hash_count = int(hash_annotation.get("item_count", 0))
                file_count = int(ficm_annotation.get("file_count", 0))
                chunk_values = ficm_annotation.get("chunk_id_per_file", [])
                declared_chunk_count = (
                    int(chunk_annotation.get("chunk_count", 0)) if chunk_annotation else 0
                )
                playgo["file_map"] = {
                    "flat_path_hash_count": hash_count,
                    "ficm_file_record_count": file_count,
                    "ficm_has_two_records_per_flat_path_hash": file_count == hash_count * 2,
                    "referenced_chunk_ids": sorted(set(chunk_values)),
                    "all_referenced_chunk_ids_exist": (
                        not chunk_values
                        or declared_chunk_count > 0
                        and max(chunk_values) < declared_chunk_count
                    ),
                }
            if scenario_annotation and scenario_annotation.get("format") == "JSON":
                scenario_value = scenario_annotation.get("value", {})
                if isinstance(scenario_value, dict):
                    playgo["localized_scenario"] = {
                        "scenario_count": scenario_value.get("scenarioCount"),
                        "default_scenario_id": scenario_value.get("scenarioDefaultId"),
                        "default_language": scenario_value.get("scenarioDefaultLanguage"),
                        "supported_chunk_languages": scenario_value.get("chunkSupportedLanguages"),
                    }
            report["playgo"] = playgo

        integrity: dict[str, Any] = {}
        digest_entry = next((item for item in entries if item["id_value"] == 0x0001), None)
        if digest_entry and not digest_entry["encrypted"]:
            digest_data = read_exact_at(
                stream, cnt_base + digest_entry["data_offset"], digest_entry["logical_size"], file_size)
            stored_digests = [digest_data[i:i + 32] for i in range(0, len(digest_data) - 31, 32)]
            checks = []
            for index, entry in enumerate(entries):
                if index >= len(stored_digests):
                    break
                stored = stored_digests[index]
                computed = bytes.fromhex(entry["sha3_256"])
                # Slot zero authenticates the DIGESTS table indirectly and is normally zero.
                checks.append({
                    "entry_index": index,
                    "entry_id": entry["id"],
                    "stored": hex_bytes(stored),
                    "computed": hex_bytes(computed),
                    "valid": None if index == 0 else stored == computed,
                })
            integrity["per_entry_digest_checks"] = checks
            integrity["digest_table_hash"] = {
                "stored": cnt["digest_table_hash"],
                "computed": hashlib.sha3_256(digest_data).hexdigest().upper(),
            }
            integrity["digest_table_hash"]["valid"] = (
                integrity["digest_table_hash"]["stored"] == integrity["digest_table_hash"]["computed"]
            )

        body_offset, body_size = int(cnt["body_offset"]), int(cnt["body_size"])
        if body_size and body_offset <= cnt_end and body_size <= cnt_end - body_offset:
            computed_body = hash_range(stream, cnt_base + body_offset, body_size, "sha3_256")
            integrity["body_digest"] = {
                "stored": cnt["body_digest"],
                "computed": computed_body,
                "valid": cnt["body_digest"] == computed_body,
            }

        playgo_digest_ids = [0x1001, 0x1002, 0x1003, 0x1008, 0x1009, 0x100A, 0x2010, 0x2011, 0x3000]
        playgo_digest_entries = [
            entry for entry_id in playgo_digest_ids
            for entry in entries
            if entry["id_value"] == entry_id and not entry["encrypted"]
        ]
        general_digest_entry = next(
            (entry for entry in entries if entry["id_value"] == 0x0080 and not entry["encrypted"]),
            None,
        )
        required_playgo_ids = {0x1001, 0x2010, 0x2011}
        available_playgo_ids = {entry["id_value"] for entry in playgo_digest_entries}
        if general_digest_entry is not None and required_playgo_ids <= available_playgo_ids:
            general_digest_data = read_exact_at(
                stream,
                cnt_base + general_digest_entry["data_offset"],
                general_digest_entry["logical_size"],
                file_size,
            )
            playgo_slot_offset = 0x20 + GENERAL_DIGEST_NAMES.index("playgo") * 0x20
            if len(general_digest_data) >= playgo_slot_offset + 0x20:
                computed_playgo_digest = hashlib.sha3_256(b"".join(
                    bytes.fromhex(entry["sha3_256"])
                    for entry in playgo_digest_entries
                )).hexdigest().upper()
                stored_playgo_digest = hex_bytes(
                    general_digest_data[playgo_slot_offset:playgo_slot_offset + 0x20])
                integrity["playgo_digest"] = {
                    "entry_ids": [entry["id"] for entry in playgo_digest_entries],
                    "stored": stored_playgo_digest,
                    "computed": computed_playgo_digest,
                    "valid": stored_playgo_digest == computed_playgo_digest,
                }

        sc_by_id = {entry["id_value"]: entry for entry in entries}
        semantic_ids = [0x0010]
        if 0x0020 in sc_by_id:
            semantic_ids.append(0x0020)
        semantic_ids.append(0x0080)
        # Delta-patch CNTs authenticate their RLC record index between the
        # general-digest and metadata entries in both system-entry rollups.
        if 0x00C0 in sc_by_id:
            semantic_ids.append(0x00C0)
        semantic_ids.extend([0x0100, 0x0001])
        if all(entry_id in sc_by_id and not sc_by_id[entry_id]["encrypted"] for entry_id in semantic_ids):
            semantic_data: dict[int, bytes] = {}
            for entry_id in semantic_ids:
                item = sc_by_id[entry_id]
                semantic_data[entry_id] = read_exact_at(
                    stream, cnt_base + item["data_offset"], item["logical_size"], file_size)
            computed_sc1 = hashlib.sha3_256(b"".join(semantic_data[item] for item in semantic_ids)).hexdigest().upper()
            second_parts = []
            for entry_id in semantic_ids[:-1]:
                value = semantic_data[entry_id]
                if entry_id == 0x0100:
                    value = value[:int(cnt["system_entry_count"]) * ENTRY_SIZE]
                second_parts.append(value)
            computed_sc2 = hashlib.sha3_256(b"".join(second_parts)).hexdigest().upper()
            integrity["system_entry_rollups"] = {
                "sc_entries_1": {
                    "stored": cnt["sc_entries_1_hash"], "computed": computed_sc1,
                    "valid": cnt["sc_entries_1_hash"] == computed_sc1,
                },
                "sc_entries_2": {
                    "stored": cnt["sc_entries_2_hash"], "computed": computed_sc2,
                    "valid": cnt["sc_entries_2_hash"] == computed_sc2,
                },
            }
        report["integrity"] = integrity

        with (cnt_dir / "entries.csv").open("w", newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=[
                "index", "id", "name", "encrypted", "encryption_profile", "key_index", "flags1", "flags2",
                "name_table_offset", "data_offset", "logical_size", "stored_size", "sha256", "output",
                "decrypted_sha256", "decrypted_output",
            ])
            writer.writeheader()
            for entry in entries:
                writer.writerow({key: entry.get(key) for key in writer.fieldnames})
        json_write(cnt_dir / "header.json", cnt)
        json_write(cnt_dir / "entries.json", entries)
        json_write(cnt_dir / "decoded-entries.json", annotations)
        json_write(cnt_dir / "integrity.json", integrity)
        if playgo is not None:
            decoded_playgo_root = cnt_dir / "playgo-decoded"
            decoded_playgo_root.mkdir(parents=True, exist_ok=True)
            decoded_playgo_files = []
            for entry in playgo_entries:
                annotation = annotations.get(f"{entry['id_value']:08X}:{entry['name']}")
                if not isinstance(annotation, dict):
                    continue
                safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(entry["name"]).name)
                decoded_name = f"{entry['id_value']:08X}-{safe_name}.json"
                json_write(decoded_playgo_root / decoded_name, annotation)
                decoded_playgo_files.append(f"playgo-decoded/{decoded_name}")
            playgo["decoded_files"] = decoded_playgo_files
            json_write(cnt_dir / "playgo.json", playgo)

        if args.dump_cnt:
            copy_range(stream, output / "segments" / "cnt.bin", cnt_base, cnt_end, file_size)

        supplement_offset = cnt_base + cnt_end
        supplement_size = file_size - supplement_offset
        report["segments"]["supplement"] = {"offset": supplement_offset, "size": supplement_size}
        if supplement_size:
            prefix = read_exact_at(stream, supplement_offset, min(4, supplement_size), file_size)
            raw_si = output / "si" / "supplement.bin"
            copy_range(stream, raw_si, supplement_offset, supplement_size, file_size)
            if prefix.startswith(b"PK"):
                try:
                    members = safe_extract_zip(raw_si, output / "si" / "extracted")
                    report["si"] = {"is_zip": True, "members": members}
                    json_write(output / "si" / "members.json", members)
                except (zipfile.BadZipFile, OSError) as error:
                    report["si"] = {"is_zip": False, "error": str(error)}
                    report["warnings"].append(f"The SI segment resembles ZIP but could not be parsed: {error}")
            elif prefix == RLC_MAGIC:
                rlc_index_entry = next(
                    (item for item in entries if item["id_value"] == 0x00C0 and not item["encrypted"]),
                    None,
                )
                if rlc_index_entry is None:
                    report["si"] = {
                        "is_zip": False,
                        "format": "RLC",
                        "parse_error": "The required plaintext CNT entry 0xC0 is absent",
                    }
                    report["warnings"].append(
                        "The supplement is RLC but its plaintext CNT index entry 0xC0 is absent.")
                else:
                    rlc_index_data = read_exact_at(
                        stream,
                        cnt_base + rlc_index_entry["data_offset"],
                        rlc_index_entry["logical_size"],
                        file_size,
                    )
                    rlc = inspect_rlc_supplement(raw_si, rlc_index_data)
                    report["si"] = {"is_zip": False, **rlc}
                    json_write(output / "si" / "rlc.json", rlc)
                    with (output / "si" / "rlc-records.csv").open(
                            "w", newline="", encoding="utf-8-sig") as csv_file:
                        fieldnames = [
                            "index", "compound_record_id", "offset", "authenticated_size",
                            "gap_before_size", "gap_before_is_zero", "sha3_256_valid",
                            "records_remaining", "selected_index_count", "index_upper_bound",
                            "first_selected_index", "last_selected_index", "payload_layout_valid",
                        ]
                        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                        writer.writeheader()
                        for item in rlc["records"]:
                            header = item.get("header", {})
                            payload = item.get("payload", {})
                            writer.writerow({
                                "index": item.get("index"),
                                "compound_record_id": item.get("compound_record_id"),
                                "offset": item.get("offset"),
                                "authenticated_size": item.get("authenticated_size"),
                                "gap_before_size": item.get("gap_before_size"),
                                "gap_before_is_zero": item.get("gap_before_is_zero"),
                                "sha3_256_valid": item.get("sha3_256_valid"),
                                "records_remaining": header.get("records_remaining"),
                                "selected_index_count": header.get("selected_index_count"),
                                "index_upper_bound": header.get("index_upper_bound"),
                                "first_selected_index": payload.get("first_selected_index"),
                                "last_selected_index": payload.get("last_selected_index"),
                                "payload_layout_valid": payload.get("layout_valid"),
                            })
            else:
                report["si"] = {"is_zip": False, "prefix": hex_bytes(prefix)}
        else:
            report["si"] = {"present": False}

        if args.hash_package:
            report["package_sha256"] = hash_range(stream, 0, file_size, "sha256")

    json_write(output / "report.json", report)
    return report


def print_summary(report: dict[str, Any], output: Path) -> None:
    cnt = report["cnt"]
    entries = report["entries"]
    plaintext = sum(not item["encrypted"] for item in entries)
    protected = len(entries) - plaintext
    decrypted = sum("decrypted_output" in item for item in entries)
    print(f"Type:             {report['container_type']}")
    print(f"PKG size:         {report['file_size']} ({report['file_size_hex']})")
    print(f"Content ID:       {cnt['content_id']}")
    parts = cnt.get("content_id_parts", {})
    if parts.get("valid_shape"):
        print(f"Title ID:         {parts['title_id']}")
        print(f"Label:            {parts['label']}")
    print(f"Content type:     {cnt['content_type']}")
    print(f"DRM type:         {cnt['drm_type']}")
    print(f"CNT entries:      {len(entries)} (plaintext {plaintext}, protected {protected})")
    if decrypted:
        print(f"CNT decrypted:    {decrypted}")
    license_annotation = next((
        value for key, value in report.get("decoded_entries", {}).items()
        if key.startswith("00000400:") and isinstance(value, dict)
    ), None)
    if license_annotation:
        if license_annotation.get("is_zero_placeholder"):
            print("License.dat:      retail zero placeholder (no RIF in this PKG entry)")
        elif license_annotation.get("profile") == "RIF-license-record":
            print(
                "License.dat:      RIF record"
                + (f" for {license_annotation['content_id']}" if license_annotation.get("content_id") else ""))
    trophy_data = report.get("trophies_and_uds", {})
    trophy_archives = trophy_data.get("archives", [])
    if trophy_archives:
        extracted_ucp = sum(item.get("status") == "extracted" for item in trophy_archives)
        protected_ucp = sum(item.get("status") == "protected" for item in trophy_archives)
        print(f"UCP archives:     {len(trophy_archives)} (extracted {extracted_ucp}, protected {protected_ucp})")
    playgo = report.get("playgo", {})
    chunk_layout = playgo.get("chunk_layout", {})
    if chunk_layout:
        print(
            "PlayGo:          "
            f"{chunk_layout.get('chunk_count', 0)} chunks, "
            f"{chunk_layout.get('mchunk_attribute_count', 0)} mchunks, "
            f"{chunk_layout.get('scenario_count', 0)} scenarios")
    file_map = playgo.get("file_map", {})
    if file_map:
        print(
            "PlayGo file map: "
            f"{file_map.get('flat_path_hash_count', 0)} path hashes, "
            f"{file_map.get('ficm_file_record_count', 0)} FICM records")
    if "fih" in report:
        fih = report["fih"]
        print(f"Outer PFS:        {fih['pfs_size']} bytes @ {hx(fih['pfs_offset'])}")
        print(f"NAPS layout size: {fih['naps_layout_size']}")
    print(f"Output:           {output.resolve()}")
    print(f"Full report:      {(output / 'report.json').resolve()}")
    if report["warnings"]:
        print("Warnings:")
        for warning in report["warnings"]:
            print(f"  - {warning}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect and export PS5 retail/debug PKG data, automatically decrypt fixed-key "
            "NAPS metadata, and optionally decrypt protected CNT entries."))
    parser.add_argument("package", type=Path, help="source .pkg file")
    parser.add_argument("output", type=Path, help="output directory")
    parser.add_argument(
        "--dump-outer-pfs", action="store_true",
        help="copy the complete raw outer PFS (may require hundreds of GiB)")
    parser.add_argument(
        "--hash-outer-pfs", action="store_true",
        help="compute SHA-256 of the complete outer PFS (slow for large PKGs)")
    parser.add_argument(
        "--no-dump-cnt", dest="dump_cnt", action="store_false",
        help="do not save an additional complete CNT copy; individual entries are still exported")
    parser.add_argument(
        "--hash-package", action="store_true",
        help="compute SHA-256 of the complete PKG")
    parser.add_argument(
        "--passcode",
        help="32-character package passcode; derives and validates publisher keys 0 through 6")
    parser.add_argument(
        "--ekpfs", type=lambda value: parse_hex_key(value, 32, "EKPFS"),
        help="known 32-byte EKPFS/dk1 in hexadecimal")
    parser.add_argument(
        "--derived-key", action="append", type=parse_derived_key_argument, default=[], metavar="INDEX:HEX",
        help="known 32-byte publisher derived key (repeat for indices 0 through 6)")
    parser.add_argument(
        "--no-decrypt-outer-pfs", dest="decrypt_outer_pfs", action="store_false",
        help="do not automatically dump decrypted outer PFS when a valid passcode/EKPFS is supplied")
    parser.set_defaults(dump_cnt=True, decrypt_outer_pfs=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = extract_package(args)
        print_summary(report, args.output)
        return 0
    except (PkgError, OSError, ValueError, struct.error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
