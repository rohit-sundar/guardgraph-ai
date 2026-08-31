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


def test_axml_empty_attribute_name_no_longer_crashes_the_parser():
    """
    Regression guard for app/analysis/axml_recovery.install_axml_tolerance.

    AXMLPrinter._fix_name() indexes name[0] with no empty-string guard, and a
    manifest carrying an attribute whose name resolves to "" walked straight
    into an IndexError — a crash rather than a parse failure, losing the whole
    APK object over one malformed attribute. Sample 1 of the 2026-08-27 Bank of
    India evaluation set does exactly that.

    The patch must fix that one case and change nothing else, so this asserts
    both halves.
    """
    from unittest.mock import MagicMock
    from androguard.core.axml import AXMLPrinter

    from app.analysis.axml_recovery import (
        EMPTY_NAME_PLACEHOLDER,
        install_axml_tolerance,
    )

    install_axml_tolerance()
    fake_self = MagicMock()

    prefix, name = AXMLPrinter._fix_name(fake_self, "some_uri", "")
    assert name == EMPTY_NAME_PLACEHOLDER

    # A well-formed name still takes androguard's own code path untouched.
    assert AXMLPrinter._fix_name(fake_self, "some_uri", "package")[1] == "package"


def test_axml_module_failure_is_recognized():
    """
    probable_cause must still classify an AXML-layer IndexError, which remains
    reachable from the many other ways a corrupted manifest desyncs the parser —
    the empty-attribute-name case above is one route into it, not the only one.

    Raised from a frame that names the module rather than by re-breaking
    androguard, so this tests the classifier instead of depending on a bug the
    project now deliberately prevents.
    """
    def androguard_core_axml_fix_name():
        raise IndexError("string index out of range")

    try:
        androguard_core_axml_fix_name()
    except IndexError as e:
        label, explanation = probable_cause(e)
        assert label == "Malformed AndroidManifest.xml (AXML)"
        assert "desync" in explanation.lower()
    else:
        raise AssertionError("expected the helper to raise IndexError")


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
