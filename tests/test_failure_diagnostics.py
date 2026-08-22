"""
Tests for failure_diagnostics.probable_cause — the plain-English failure
classification used by routes._unparseable_report so an analyst sees "this
looks like a corrupted DEX" instead of a bare exception repr.
"""
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.failure_diagnostics import probable_cause


def test_bad_zip_file_is_recognized():
    try:
        with zipfile.ZipFile(__file__):  # this test file isn't a zip
            pass
    except zipfile.BadZipFile as e:
        label, explanation = probable_cause(e)
    assert label == "Corrupted or non-standard ZIP structure"
    assert "packer" in explanation.lower()


def test_axml_module_failure_is_recognized():
    """
    Reproduces the exact real-world crash this project hit: AXMLPrinter's
    _fix_name() indexes name[0] with no empty-string guard. A fully-garbage
    buffer doesn't reach this path (AXMLPrinter logs and bails earlier), so
    this calls the vulnerable method directly with the degenerate input that
    triggers it — same as the live IndexError traced back to axml/__init__.py.
    """
    from unittest.mock import MagicMock
    from androguard.core.axml import AXMLPrinter

    fake_self = MagicMock()
    try:
        AXMLPrinter._fix_name(fake_self, "some_uri", "")  # (self, prefix, name) — empty name triggers it
    except IndexError as e:
        label, explanation = probable_cause(e)
        assert label == "Malformed AndroidManifest.xml (AXML)"
        assert "desync" in explanation.lower()
    else:
        raise AssertionError("expected _fix_name('') to raise IndexError")


def test_memory_error_is_recognized():
    try:
        raise MemoryError("simulated allocation failure")
    except MemoryError as e:
        label, explanation = probable_cause(e)
    assert label == "Resource-exhaustion pattern"
    assert "dos" in explanation.lower() or "exhaust" in explanation.lower()


def test_recursion_error_is_recognized():
    try:
        raise RecursionError("maximum recursion depth exceeded")
    except RecursionError as e:
        label, explanation = probable_cause(e)
    assert label == "Pathologically deep/nested structure"


def test_unrecognized_exception_gets_honest_fallback_not_a_guess():
    label, explanation = probable_cause(ValueError("something totally novel"))
    assert label == "Unrecognized parser failure"
    assert "unverified" in explanation.lower()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
