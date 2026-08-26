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


def test_av_quarantine_is_recognized_and_not_blamed_on_the_sample():
    """
    Observed live: Defender quarantined the staged copy of a malware sample
    mid-analysis, so compute_sha256's open() raised EINVAL on a file that was
    perfectly intact on disk. Before this signature existed the analyst was told
    the failure "may be a genuinely novel anti-analysis technique" — pointing at
    the sample instead of at the host AV that actually caused it.
    """
    try:
        raise OSError(22, "Invalid argument")
    except OSError as e:
        label, explanation = probable_cause(e)
    assert label == "Sample removed by host antivirus (not an APK defect)"
    assert "antivirus" in explanation.lower()
    assert "upload_staging_dir" in explanation


def test_av_quarantine_outranks_the_parser_frame_it_surfaced_in():
    """
    AV can pull the file while a parser is mid-read, so the traceback carries
    BOTH an antivirus signature and a DEX one. The antivirus is the cause and
    the parser frame is only where it surfaced — reporting "corrupted DEX" here
    would send the analyst after a defect that isn't in the file.
    """
    try:
        raise OSError(22, "Invalid argument", r"androguard\core\dex\payload.dex")
    except OSError as e:
        label, _ = probable_cause(e)
    assert label == "Sample removed by host antivirus (not an APK defect)"


def test_unrecognized_exception_gets_honest_fallback_not_a_guess():
    label, explanation = probable_cause(ValueError("something totally novel"))
    assert label == "Unrecognized parser failure"
    assert "unverified" in explanation.lower()


def test_missing_eocd_is_recognised_as_a_corrupt_zip():
    """
    Androguard reports a broken central directory as a plain ValueError naming
    the EOCD, not as BadZipFile, so it matched no signature and surfaced as
    "possibly novel" — for a technique this project already handles elsewhere.
    """
    try:
        raise ValueError("End of central directory record (EOCD) signature not found")
    except ValueError as e:
        label, explanation = probable_cause(e)
    assert label == "Corrupted or non-standard ZIP structure"
    assert "central directory" in explanation.lower()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
