"""
Tests for the Android-tolerant container reader and its integrity scan.

The reader exists because `zipfile` enforces the ZIP spec and the Android
runtime does not, so an APK can be built that installs on a phone while being
unreadable to every desktop tool. Each test below constructs one of the
divergences observed on the 2026-08-27 Bank of India evaluation set and asserts
two things about it: that the bytes come back anyway, and that the archive is
reported as tampered rather than silently worked around.
"""
import os
import struct
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from app.analysis.apk_container import (
    ApkContainer,
    open_and_scan,
    scan_container,
)


def _local_entry(
    name: str,
    payload: bytes,
    *,
    method: int = 0,
    flags: int = 0,
    comp_size: int | None = None,
    uncomp_size: int | None = None,
    data: bytes | None = None,
) -> tuple[bytes, dict]:
    """A local file header + its data, plus the central-directory facts."""
    raw = payload if data is None else data
    cs = len(raw) if comp_size is None else comp_size
    us = len(payload) if uncomp_size is None else uncomp_size
    nb = name.encode()
    header = b"PK\x03\x04" + struct.pack(
        "<HHHHHIIIHH", 20, flags, method, 0, 0, 0, cs, us, len(nb), 0
    ) + nb
    return header + raw, {
        "name": nb, "method": method, "flags": flags, "csize": cs, "usize": us
    }


def _build_zip(entries: list[tuple[bytes, dict]]) -> bytes:
    """Assemble local entries plus a matching central directory and EOCD."""
    out = b""
    central = b""
    for blob, meta in entries:
        offset = len(out)
        out += blob
        central += b"PK\x01\x02" + struct.pack(
            "<HHHHHHIIIHHHHHII",
            20, 20, meta["flags"], meta["method"], 0, 0, 0,
            meta["csize"], meta["usize"], len(meta["name"]), 0, 0, 0, 0, 0, offset,
        ) + meta["name"]
    cd_offset = len(out)
    out += central
    out += b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, len(entries), len(entries), len(central), cd_offset, 0
    )
    return out


def _write(tmp_path, data: bytes, name: str = "sample.apk") -> str:
    path = os.path.join(str(tmp_path), name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _deflate(payload: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(payload) + co.flush()


# ── fake encryption ───────────────────────────────────────────────────────────

def test_encryption_flag_entry_is_read_and_reported(tmp_path):
    """
    The trick that cost three of five evaluation samples their entire payload
    inventory: general-purpose bit 0 set on entries the platform loads anyway.
    `zipfile` refuses these with a RuntimeError; the container must not.
    """
    payload = b"dex\n035\x00" + b"P" * 200
    blob = _build_zip([
        _local_entry("classes.dex", payload, method=0, flags=0x0001),
    ])
    path = _write(tmp_path, blob)

    # Baseline: the standard reader genuinely cannot do this.
    with zipfile.ZipFile(path) as zf:
        with pytest.raises(RuntimeError):
            zf.read("classes.dex")

    container, scan = open_and_scan(path)
    assert container is not None
    assert container.read("classes.dex") == payload
    assert any(a.startswith("zip_fake_encryption:1/1") for a in scan.anomalies)


# ── scrambled compression method ──────────────────────────────────────────────

def test_unsupported_compression_method_falls_back_to_stored(tmp_path):
    """
    Sample 1's AndroidManifest.xml: compression method 55217 over data that is
    simply stored. Android ignores the field; so must the reader.
    """
    payload = b"\x03\x00\x08\x00" + b"M" * 300
    blob = _build_zip([_local_entry("AndroidManifest.xml", payload, method=55217)])
    path = _write(tmp_path, blob)

    container, scan = open_and_scan(path)
    assert container.read("AndroidManifest.xml") == payload
    assert "zip_unsupported_compression:55217" in scan.anomalies


def test_under_declared_compressed_size_still_inflates_fully(tmp_path):
    """
    A DEFLATE entry whose header under-declares its own compressed size. Reading
    `compress_size` bytes truncates the stream; reading to the next header does
    not, which is the difference between recovering a manifest and losing one.
    """
    payload = b"A" * 4096
    compressed = _deflate(payload)
    blob = _build_zip([
        _local_entry(
            "AndroidManifest.xml", payload, method=8,
            data=compressed, comp_size=len(compressed) // 3,
        ),
    ])
    path = _write(tmp_path, blob)

    container = ApkContainer(path)
    assert container.read("AndroidManifest.xml") == payload


# ── name games ────────────────────────────────────────────────────────────────

def test_duplicate_and_poisoned_entry_names_are_counted(tmp_path):
    """
    Sample 4 ships 25 duplicate names and dozens of decoys built from core
    filenames used as directories. Both are counted; neither stops a read.
    """
    blob = _build_zip([
        _local_entry("classes.dex", b"dex\n035\x00one"),
        _local_entry("res/a.png", b"first"),
        _local_entry("res/a.png", b"second"),
        _local_entry("AndroidManifest.xml/..9.png", b"decoy"),
        _local_entry("/resources.arsc/x.png", b"decoy2"),
    ])
    path = _write(tmp_path, blob)

    container, scan = open_and_scan(path)
    assert scan.duplicate_names == 1
    assert scan.shadowed_core_names == 2
    assert scan.absolute_or_traversal_names == 1
    assert any(a.startswith("zip_duplicate_entries:1") for a in scan.anomalies)
    assert any(a.startswith("zip_core_name_shadowing:2") for a in scan.anomalies)


def test_read_all_returns_every_copy_of_a_shadowed_name(tmp_path):
    """
    Which duplicate a tool sees depends on whether it indexes by name or
    iterates. Manifest recovery needs to try all of them.
    """
    blob = _build_zip([
        _local_entry("AndroidManifest.xml", b"decoy-not-axml"),
        _local_entry("AndroidManifest.xml", b"\x03\x00\x08\x00real"),
    ])
    path = _write(tmp_path, blob)

    container = ApkContainer(path)
    copies = [data for _entry, data in container.read_all("AndroidManifest.xml")]
    assert len(copies) == 2
    assert b"decoy-not-axml" in copies
    assert any(c.startswith(b"\x03\x00\x08\x00") for c in copies)


# ── the clean case ────────────────────────────────────────────────────────────

def test_well_formed_archive_reports_nothing_and_reads_identically(tmp_path):
    """
    The property that makes the anomaly codes scoreable: a normal APK trips
    none of them, and the container returns exactly what `zipfile` returns.

    This is the unit-level statement of the corpus measurement in
    scripts/measure_container_anomalies.py, which found 0 of 533 clean apps
    tripping any code.
    """
    path = os.path.join(str(tmp_path), "clean.apk")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest-bytes")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"C" * 500)
        zf.writestr("assets/config.json", b'{"a": 1}')

    container, scan = open_and_scan(path)
    assert scan.anomalies == []

    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            assert container.read(name) == zf.read(name), name


def test_unreadable_central_directory_falls_back_to_local_headers(tmp_path):
    """
    A broken EOCD is its own anti-analysis technique — desktop tools refuse the
    archive while Android reads it. The local headers are still there.
    """
    blob = _build_zip([_local_entry("classes.dex", b"dex\n035\x00payload")])
    truncated = blob[: blob.rindex(b"PK\x05\x06")] + b"\x00" * 8
    path = _write(tmp_path, truncated)

    with pytest.raises(zipfile.BadZipFile):
        zipfile.ZipFile(path)

    container, scan = open_and_scan(path)
    assert container is not None
    assert container.read("classes.dex") == b"dex\n035\x00payload"
    assert "zip_central_directory_unreadable" in scan.anomalies


def test_scan_of_an_empty_archive_is_not_an_anomaly(tmp_path):
    """An empty-but-valid ZIP is degenerate, not tampered — no codes."""
    path = os.path.join(str(tmp_path), "empty.apk")
    with zipfile.ZipFile(path, "w"):
        pass
    container = ApkContainer(path)
    assert scan_container(container).anomalies == []
