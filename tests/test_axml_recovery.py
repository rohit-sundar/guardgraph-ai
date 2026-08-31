"""
Tests for AndroidManifest.xml recovery.

Three separate manifest-level tricks are covered, matching the three the Bank of
India evaluation set used: an AXML chunk that lies about its own size, an
attribute whose name is the empty string, and a manifest whose element tree
cannot be rebuilt at all but whose string pool is intact.

The last one carries the rule this module is most careful about: the string pool
records that a name is present, never which element declared it, so recovered
components must come back unattributed rather than guessed into
activities/services/receivers.
"""
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from app.analysis.apk_container import ApkContainer
from app.analysis.axml_recovery import (
    EMPTY_NAME_PLACEHOLDER,
    RecoveredManifest,
    _normalise_axml_header,
    _package_from_pool,
    install_axml_tolerance,
    recover_manifest,
)

AXML_MAGIC = b"\x03\x00\x08\x00"


def _axml(body: bytes, declared_size: int | None = None) -> bytes:
    """An AXML blob whose header may or may not tell the truth about its size."""
    total = 8 + len(body)
    return (
        AXML_MAGIC
        + struct.pack("<I", total if declared_size is None else declared_size)
        + body
    )


# ── header normalisation ──────────────────────────────────────────────────────

def test_over_declared_size_is_rewritten_to_the_real_length():
    """Androguard rejects the file outright; the platform reads what is there."""
    data = _axml(b"body-bytes", declared_size=999_999)
    fixed = _normalise_axml_header(data)
    assert struct.unpack("<I", fixed[4:8])[0] == len(data)
    assert fixed[8:] == data[8:]


def test_under_declared_size_is_also_rewritten():
    data = _axml(b"body-bytes" * 10, declared_size=4)
    fixed = _normalise_axml_header(data)
    assert struct.unpack("<I", fixed[4:8])[0] == len(data)


def test_consistent_header_is_left_alone():
    data = _axml(b"body-bytes")
    assert _normalise_axml_header(data) is data


def test_non_axml_bytes_pass_through_untouched():
    data = b"not an axml file at all"
    assert _normalise_axml_header(data) == data


# ── empty-attribute-name tolerance ────────────────────────────────────────────

def test_tolerance_substitutes_only_for_an_empty_name():
    """
    The patch must turn a crash into a parse and change nothing else — a
    well-formed manifest has to keep parsing byte-identically.
    """
    install_axml_tolerance()
    from androguard.core.axml import AXMLPrinter

    printer = AXMLPrinter.__new__(AXMLPrinter)
    assert printer._fix_name("", "") == ("", EMPTY_NAME_PLACEHOLDER)
    # A normal name still takes androguard's own code path.
    assert printer._fix_name("", "package")[1] == "package"


def test_tolerance_is_idempotent():
    """Called on every recovery attempt; must not stack patches."""
    install_axml_tolerance()
    from androguard.core.axml import AXMLPrinter

    first = AXMLPrinter._fix_name
    install_axml_tolerance()
    assert AXMLPrinter._fix_name is first


# ── package recovery from generated strings ───────────────────────────────────

def test_package_recovered_from_a_generated_permission_name():
    """
    aapt2 appends this suffix to the application id verbatim, so stripping it
    back off is a derivation rather than a guess.
    """
    pool = [
        "android.permission.INTERNET",
        "com.tomo.tozy.naki.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
        "com.qmvxhkjp.rnbtzwlc.ExMi8LrJcWdP",
    ]
    assert _package_from_pool(pool) == "com.tomo.tozy.naki"


def test_package_recovered_from_the_androidx_startup_authority():
    pool = ["com.example.app.androidx-startup", "androidx.startup"]
    assert _package_from_pool(pool) == "com.example.app"


def test_no_generated_marker_means_no_package_rather_than_a_guess():
    pool = ["android.permission.INTERNET", "SomeClass", "com.vendor.Thing"]
    assert _package_from_pool(pool) is None


# ── end to end through a container ────────────────────────────────────────────

def _apk_with_manifest(tmp_path, manifest: bytes, name: str = "m.apk") -> str:
    path = os.path.join(str(tmp_path), name)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"x" * 100)
    return path


def test_unreadable_manifest_recovers_nothing_and_says_so(tmp_path):
    """
    A manifest that is genuinely not AXML must return None — a reported gap, not
    an empty result dressed up as an answer.
    """
    path = _apk_with_manifest(tmp_path, b"this is not a manifest at all")
    assert recover_manifest(ApkContainer(path)) is None


def test_missing_manifest_entry_returns_none(tmp_path):
    path = os.path.join(str(tmp_path), "no-manifest.apk")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00")
    assert recover_manifest(ApkContainer(path)) is None


# ── the honesty contract on string-pool results ───────────────────────────────

def test_string_pool_results_never_populate_the_classified_lists():
    """
    The pool cannot say whether a class name was an activity, a service or a
    receiver. Filling those lists from it would invent an attribution the file
    does not contain, so the count lives on `components` instead.
    """
    recovered = RecoveredManifest(
        source="string_pool",
        package="com.example.app",
        permissions=["android.permission.INTERNET"],
        components=["com.example.app.A", "com.example.app.B"],
    )
    assert recovered.activities == []
    assert recovered.services == []
    assert recovered.receivers == []
    assert recovered.component_count == 2
    assert not recovered.is_empty


def test_tree_results_count_the_classified_lists():
    recovered = RecoveredManifest(
        source="tree",
        package="com.example.app",
        activities=["A"],
        services=["S"],
        receivers=["R1", "R2"],
    )
    assert recovered.component_count == 4


def test_a_recovery_with_nothing_in_it_reads_as_empty():
    assert RecoveredManifest(source="tree").is_empty
