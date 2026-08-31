"""
Android-tolerant APK container reader and archive-integrity scan (Phase 1).

Every other module reads the APK through `zipfile`, which enforces the ZIP spec.
The Android runtime's own loader does not: it ignores the general-purpose
encryption flag, tolerates entries whose declared sizes disagree with the data,
and reads whichever entry it finds by name. That gap is the attack surface — an
APK can be built that installs and runs on a phone while being unreadable to
every desktop tool that would inspect it. This module reads the archive the way
Android does, and reports the ways in which it lies.

Measured on the 2026-08-27 Bank of India evaluation set, where three of five
samples set the encryption bit on most or all of their entries:

    sample 2   85 of 89 entries encrypted    every asset read raised RuntimeError
    sample 3   85 of 89 entries encrypted    every asset read raised RuntimeError
    sample 4  372 of 372 entries encrypted   classes.dex and the manifest included

`inspect_apk_payloads` swallows a failed `zf.read()` and moves on, so all three
came back with an empty payload inventory, no YARA targets from the inner
streams, and no asset strings for C2 extraction — not because they were clean,
but because nothing could be read. Sample 4's manifest failure also produced an
*empty* APK object rather than an exception, which is how a VPN-installing
dropper scored `low` on a permission component that read zero.

Two things live here, and the split matters:

  * `ApkContainer` — the reader. Its job is to hand back bytes that the phone
    would see. It never judges.
  * `scan_container` — the judgement, as a list of stable anomaly codes in the
    same style as `dropper_signals`. Kept separate because the reader is used on
    every APK, including clean ones, and "I had to work around this" must not
    silently become "this is malicious" anywhere except where a caller asks for
    the scan explicitly.

Anomaly codes are validated against the local corpus before any of them reaches
the scorer — see `scripts/measure_container_anomalies.py`.
"""
import bisect
import os
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Iterator, Optional

from loguru import logger

_LOCAL_HEADER_SIG = b"PK\x03\x04"
_CENTRAL_HEADER_SIG = b"PK\x01\x02"

# Compression methods the Android runtime actually supports for APK entries.
# Anything else cannot be inflated by the platform, so an entry declaring one
# either never gets read at runtime or — far more commonly — is STORED data with
# a scrambled method field, which is what sample 1's AndroidManifest.xml was.
_ANDROID_COMPRESSION_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})

# General-purpose bit 0. Set means "entry is encrypted" per the ZIP spec, which
# would make the file unreadable to the platform too — so on an APK that installs
# and runs, this bit is always a lie told to desktop tooling.
_FLAG_ENCRYPTED = 0x0001

# Ceiling on a single decompressed entry. The declared sizes come from an archive
# we already distrust, so the inflate is bounded by our own number rather than by
# the header's. 256 MiB clears the largest legitimate APK asset by a wide margin.
MAX_ENTRY_BYTES = 256 * 1024 * 1024

# Names whose appearance as a *directory prefix* inside another entry's path is
# never something a build tool produces — `AndroidManifest.xml/..9.png` and
# friends exist to confuse unpackers that split paths, not to hold resources.
_CORE_NAMES = ("androidmanifest.xml", "classes.dex", "resources.arsc")


@dataclass
class ContainerEntry:
    """One ZIP entry, as declared by the archive rather than as validated."""

    name: str
    header_offset: int
    compress_type: int
    compress_size: int
    file_size: int
    flag_bits: int

    @property
    def encrypted_flag(self) -> bool:
        return bool(self.flag_bits & _FLAG_ENCRYPTED)

    @property
    def unsupported_compression(self) -> bool:
        return self.compress_type not in _ANDROID_COMPRESSION_METHODS


@dataclass
class ContainerScan:
    """Result of `scan_container` — anomaly codes plus the counts behind them."""

    anomalies: list[str] = field(default_factory=list)
    entry_count: int = 0
    encrypted_entries: int = 0
    unsupported_methods: list[int] = field(default_factory=list)
    duplicate_names: int = 0
    shadowed_core_names: int = 0
    absolute_or_traversal_names: int = 0
    readable: bool = True

    def to_dict(self) -> dict:
        return {
            "anomalies": list(self.anomalies),
            "entry_count": self.entry_count,
            "encrypted_entries": self.encrypted_entries,
            "unsupported_methods": list(self.unsupported_methods),
            "duplicate_names": self.duplicate_names,
            "shadowed_core_names": self.shadowed_core_names,
            "absolute_or_traversal_names": self.absolute_or_traversal_names,
            "readable": self.readable,
        }


class ApkContainer:
    """
    Reads APK entries by seeking to their local headers, ignoring the flags and
    declared sizes that stop `zipfile` from reading a deliberately malformed
    archive.

    Construction prefers `zipfile`'s central directory for the entry list,
    because it is the authoritative index and is correct even in the samples that
    lie about everything else. When the central directory itself is unusable
    (`BadZipFile`), it falls back to walking raw `PK\\x03\\x04` signatures — the
    same approach `ingest._raw_scan_dex_from_corrupted_zip` already takes for
    DEX recovery, generalised here to every entry.

    Read semantics, in the order the platform would apply them:

      * DEFLATE entries are inflated with a raw `decompressobj` over every byte
        available up to the next header, so an entry that under-declares its own
        compressed size still inflates completely.
      * Anything else — STORED, or a scrambled method field — is returned as the
        raw bytes, taking `file_size` when the archive has room for it. That is
        the case sample 1's manifest needed: method `55217`, `compress_size`
        4089, and 11684 bytes of AXML actually sitting there.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._entries: list[ContainerEntry] = []
        self._by_name: dict[str, ContainerEntry] = {}
        self._size = os.path.getsize(filepath)
        self.central_directory_readable = True

        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                for info in zf.infolist():
                    self._add(
                        ContainerEntry(
                            name=info.filename,
                            header_offset=info.header_offset,
                            compress_type=info.compress_type,
                            compress_size=info.compress_size,
                            file_size=info.file_size,
                            flag_bits=info.flag_bits,
                        )
                    )
        except zipfile.BadZipFile as e:
            # A broken End-Of-Central-Directory record is itself a documented
            # anti-analysis technique: desktop tools refuse the archive outright
            # while Android reads it fine. Fall back to the local headers.
            logger.warning(
                f"Central directory unusable ({e}) — falling back to a raw "
                f"local-header walk of {os.path.basename(filepath)}."
            )
            self.central_directory_readable = False
            self._walk_local_headers()

        # Data offsets need the local header's own name/extra lengths, which the
        # central directory does not carry. Resolved lazily per read.
        self._data_offsets: dict[int, Optional[int]] = {}
        self._sorted_offsets: Optional[list[int]] = None

    # ── entry inventory ──────────────────────────────────────────────────────

    def _add(self, entry: ContainerEntry) -> None:
        self._entries.append(entry)
        # Last writer wins, matching `zipfile.ZipFile.read`, so a caller asking
        # by name gets the same entry the standard reader would have given it.
        self._by_name[entry.name] = entry

    def _walk_local_headers(self) -> None:
        with open(self.filepath, "rb") as fh:
            data = fh.read()

        pos = 0
        while True:
            pos = data.find(_LOCAL_HEADER_SIG, pos)
            if pos < 0 or pos + 30 > len(data):
                break
            try:
                (flag, method, _t, _d, _crc, csize, usize, nlen, xlen) = struct.unpack(
                    "<HHHHIIIHH", data[pos + 6 : pos + 30]
                )
                name = data[pos + 30 : pos + 30 + nlen].decode("utf-8", "replace")
            except Exception:
                pos += 4
                continue
            if name:
                self._add(
                    ContainerEntry(
                        name=name,
                        header_offset=pos,
                        compress_type=method,
                        compress_size=csize,
                        file_size=usize,
                        flag_bits=flag,
                    )
                )
            pos += 4

    def entries(self) -> list[ContainerEntry]:
        return list(self._entries)

    def names(self) -> list[str]:
        return [e.name for e in self._entries]

    def get(self, name: str) -> Optional[ContainerEntry]:
        return self._by_name.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def __iter__(self) -> Iterator[ContainerEntry]:
        return iter(self._entries)

    # ── reading ──────────────────────────────────────────────────────────────

    def _data_offset(self, entry: ContainerEntry) -> Optional[int]:
        """Byte offset of an entry's payload, from its own local header."""
        cached = self._data_offsets.get(entry.header_offset, "miss")
        if cached != "miss":
            return cached  # type: ignore[return-value]

        offset: Optional[int] = None
        try:
            with open(self.filepath, "rb") as fh:
                fh.seek(entry.header_offset)
                header = fh.read(30)
                if len(header) == 30 and header[:4] == _LOCAL_HEADER_SIG:
                    nlen, xlen = struct.unpack("<HH", header[26:30])
                    offset = entry.header_offset + 30 + nlen + xlen
        except OSError as e:
            logger.debug(f"Local header unreadable for {entry.name}: {e}")

        self._data_offsets[entry.header_offset] = offset
        return offset

    def _available_bytes(self, data_offset: int) -> int:
        """
        How far an entry's payload may run: to the next local header, the start
        of the central directory, or end of file — whichever comes first.

        Bounding by the *next header* rather than by the declared compressed size
        is what makes an under-declared entry readable, and it is safe because no
        entry's data can legitimately extend into another's header.
        """
        if self._sorted_offsets is None:
            self._sorted_offsets = sorted(e.header_offset for e in self._entries)
        idx = bisect.bisect_left(self._sorted_offsets, data_offset)
        limit = (
            self._sorted_offsets[idx] if idx < len(self._sorted_offsets) else self._size
        )
        return max(0, min(limit, self._size) - data_offset)

    def read(self, name: str, max_bytes: int = MAX_ENTRY_BYTES) -> Optional[bytes]:
        """
        Return an entry's bytes as the platform would see them, or None when the
        entry is absent or its payload cannot be located at all.

        Never raises for a malformed entry: a container reader that throws is a
        container reader whose callers write `except: continue`, which is the bug
        this module exists to remove.
        """
        entry = self._by_name.get(name)
        if entry is None:
            return None
        return self.read_entry(entry, max_bytes=max_bytes)

    def read_entry(
        self, entry: ContainerEntry, max_bytes: int = MAX_ENTRY_BYTES
    ) -> Optional[bytes]:
        data_offset = self._data_offset(entry)
        if data_offset is None:
            return None

        available = min(self._available_bytes(data_offset), max_bytes)
        if available <= 0:
            return b""

        try:
            with open(self.filepath, "rb") as fh:
                fh.seek(data_offset)
                raw = fh.read(available)
        except OSError as e:
            logger.debug(f"Payload unreadable for {entry.name}: {e}")
            return None

        if entry.compress_type == zipfile.ZIP_DEFLATED:
            try:
                # Raw deflate over everything available rather than over
                # `compress_size` bytes: the decompressor stops itself at the end
                # of the stream, so a compressed size that under-declares the
                # entry still yields the whole thing, and trailing bytes from the
                # next entry are simply never consumed.
                return zlib.decompressobj(-15).decompress(raw, max_bytes)
            except zlib.error as e:
                logger.debug(f"Inflate failed for {entry.name}: {e} — trying stored.")

        # STORED, or a scrambled method field treated as stored. Prefer the
        # declared uncompressed size when the archive actually has that many
        # bytes to give; `compress_size` is the field these samples scramble.
        want = entry.file_size if 0 < entry.file_size <= available else available
        return raw[: min(want, max_bytes)]

    def read_all(
        self, name: str, max_bytes: int = MAX_ENTRY_BYTES
    ) -> list[tuple[ContainerEntry, bytes]]:
        """
        Every entry carrying `name`, not just the one that shadows the rest.

        Duplicate names are one of the tricks in this set (sample 4 ships 25),
        and which copy a tool sees depends on whether it indexes by name or
        iterates. Callers that care — manifest recovery, notably — can inspect
        all of them instead of trusting the winner.
        """
        out: list[tuple[ContainerEntry, bytes]] = []
        for entry in self._entries:
            if entry.name != name:
                continue
            data = self.read_entry(entry, max_bytes=max_bytes)
            if data:
                out.append((entry, data))
        return out


def _is_shadowing_name(lower_name: str) -> bool:
    """`AndroidManifest.xml/..9.png` — a core filename used as a directory."""
    return any(f"{core}/" in lower_name for core in _CORE_NAMES)


def scan_container(container: ApkContainer) -> ContainerScan:
    """
    Report the ways this archive departs from what a build tool produces.

    Each code names one structural fact about the file, is deterministic, and
    costs one pass over the entry table — no decompression. They are written in
    the same `flag:detail` shape as `dropper_signals` so the report and the
    Neo4j write need no special-casing.
    """
    scan = ContainerScan()
    entries = container.entries()
    scan.entry_count = len(entries)
    scan.readable = container.central_directory_readable

    if not container.central_directory_readable:
        scan.anomalies.append("zip_central_directory_unreadable")

    seen: dict[str, int] = {}
    methods: set[int] = set()

    for entry in entries:
        lower = entry.name.lower().replace("\\", "/")

        if entry.encrypted_flag:
            scan.encrypted_entries += 1
        if entry.unsupported_compression:
            methods.add(entry.compress_type)

        seen[entry.name] = seen.get(entry.name, 0) + 1

        if _is_shadowing_name(lower):
            scan.shadowed_core_names += 1
        if lower.startswith("/") or "../" in lower:
            scan.absolute_or_traversal_names += 1

    scan.duplicate_names = sum(n - 1 for n in seen.values() if n > 1)
    scan.unsupported_methods = sorted(methods)

    if scan.encrypted_entries:
        # The strongest of these by a distance. An entry the platform cannot
        # decrypt cannot be loaded, so on an APK that installs and runs the bit
        # is set purely to make `zipfile`, apktool and androguard refuse it.
        scan.anomalies.append(
            f"zip_fake_encryption:{scan.encrypted_entries}/{scan.entry_count}"
        )
    for method in scan.unsupported_methods:
        scan.anomalies.append(f"zip_unsupported_compression:{method}")
    if scan.duplicate_names:
        scan.anomalies.append(f"zip_duplicate_entries:{scan.duplicate_names}")
    if scan.shadowed_core_names:
        scan.anomalies.append(f"zip_core_name_shadowing:{scan.shadowed_core_names}")
    if scan.absolute_or_traversal_names:
        scan.anomalies.append(
            f"zip_absolute_entry_paths:{scan.absolute_or_traversal_names}"
        )

    return scan


def open_and_scan(filepath: str) -> tuple[Optional[ApkContainer], ContainerScan]:
    """
    Convenience for Phase 1: the container plus its integrity scan, with a
    container that could not be opened at all reported as an anomaly rather than
    as an exception.
    """
    try:
        container = ApkContainer(filepath)
    except Exception as e:
        logger.warning(f"APK container unopenable ({e}): {filepath}")
        scan = ContainerScan(readable=False)
        scan.anomalies.append("zip_container_unopenable")
        return None, scan

    return container, scan_container(container)
