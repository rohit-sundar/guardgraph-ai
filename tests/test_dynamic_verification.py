"""
Unit tests for the dynamic-verification confirm/refute diffing logic and its
scoring-floor integration. No emulator/Frida needed — these test the pure
functions; the adb/Frida orchestration itself was validated live against a
real AVD (see app/analysis/frida_scripts/README.md).
"""
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app.analysis.dynamic_verification as dv
from app.analysis.dynamic_verification import (
    _diff_against_predictions,
    _broadcast_declared_actions,
    _dismiss_blocking_dialog,
    _dismiss_blocking_dialogs,
    run_dynamic_verification,
    DynamicVerificationOutcome,
)
from app.reports.scoring import compute_risk_score, DYNAMIC_CONFIRMATION_SCORE_FLOOR
from app.core.schemas import ObfuscationSignal


def _empty_obfuscation() -> ObfuscationSignal:
    return ObfuscationSignal(
        string_entropy_score=0.0,
        flattening_suspected=False,
        method_parse_failure_rate=0.0,
        coverage_note="",
    )


def test_diff_confirms_matching_network_indicator():
    events = [
        {"kind": "network", "value": "1.2.3.4:443"},
        {"kind": "hook_installed", "value": "network"},
    ]
    outcome = _diff_against_predictions(events, {"c2_indicators": ["1.2.3.4:443"], "dcl_targets": []})
    assert outcome.ran is True
    assert outcome.network_confirmed == ["1.2.3.4:443"]
    assert outcome.network_predicted_not_seen == []


def test_diff_reports_unpredicted_network_contact_in_observed_all():
    # A real connection to an address nothing statically predicted must still
    # show up somewhere — this is the gap that made "nothing confirmed" runs
    # look broken even when the app genuinely did something.
    events = [{"kind": "network", "value": "9.9.9.9:80"}]
    outcome = _diff_against_predictions(events, {"c2_indicators": [], "dcl_targets": []})
    assert outcome.network_confirmed == []
    assert outcome.network_observed_all == ["9.9.9.9:80"]


def test_diff_reports_ioc_urls_files_commands():
    events = [
        {"kind": "url_accessed", "value": "http://evil.example.com/panel/gate.php"},
        {"kind": "file_written", "value": "/data/data/com.evil.app/files/payload.dex"},
        {"kind": "command_executed", "value": "chmod 755 /data/local/tmp/x"},
    ]
    outcome = _diff_against_predictions(events, {})
    assert outcome.urls_accessed == ["http://evil.example.com/panel/gate.php"]
    assert outcome.files_written == ["/data/data/com.evil.app/files/payload.dex"]
    assert outcome.commands_executed == ["chmod 755 /data/local/tmp/x"]


def test_diff_reports_actual_sms_accessibility_crypto_values():
    # sms_api_invoked/accessibility_bound/crypto_invoked are booleans — these
    # carry the real value the hook captured, which used to be discarded.
    events = [
        {"kind": "sms_send", "value": "+19005551234"},
        {"kind": "accessibility_bound", "value": "com.evil.KeyloggerService"},
        {"kind": "crypto_invoked", "value": "DES/ECB/PKCS5Padding"},
    ]
    outcome = _diff_against_predictions(events, {})
    assert outcome.sms_api_invoked is True
    assert outcome.sms_destinations == ["+19005551234"]
    assert outcome.accessibility_bound is True
    assert outcome.accessibility_services == ["com.evil.KeyloggerService"]
    assert outcome.crypto_invoked is True
    assert outcome.crypto_algorithms == ["DES/ECB/PKCS5Padding"]


def test_diff_reports_crypto_output_preview_and_mode():
    # Cheap substitute for real parameterized string-decryption (see
    # hooks.js's hookCrypto docstring): the actual doFinal() return value,
    # captured live, plus Cipher.init's encrypt/decrypt mode. Reported as
    # independent observations, not correlated per-Cipher-instance.
    events = [
        {"kind": "crypto_invoked", "value": "AES/CBC/PKCS5Padding"},
        {"kind": "crypto_output", "value": "http://evil.example.com/gate.php", "algorithm": "AES/CBC/PKCS5Padding"},
        {"kind": "crypto_mode", "value": "decrypt", "algorithm": "AES/CBC/PKCS5Padding"},
    ]
    outcome = _diff_against_predictions(events, {})
    assert outcome.crypto_outputs == [
        {"algorithm": "AES/CBC/PKCS5Padding", "preview": "http://evil.example.com/gate.php"}
    ]
    assert outcome.crypto_modes_observed == ["decrypt"]


def test_diff_crypto_output_absent_when_no_crypto_events():
    outcome = _diff_against_predictions([{"kind": "network", "value": "1.2.3.4:443"}], {})
    assert outcome.crypto_outputs == []
    assert outcome.crypto_modes_observed == []


def test_diff_event_summary_counts_by_kind():
    events = [
        {"kind": "hook_installed", "value": "network"},
        {"kind": "hook_installed", "value": "sms"},
        {"kind": "network", "value": "1.2.3.4:443"},
        {"kind": "network", "value": "5.6.7.8:80"},
        {"kind": "ready", "value": True},
    ]
    outcome = _diff_against_predictions(events, {})
    assert outcome.event_summary == {"hook_installed": 2, "network": 2, "ready": 1}


def test_diff_extracts_event_triggered_screenshots():
    events = [
        {"kind": "overlay_window", "value": "type=2007", "t": 100},
        {
            "kind": "event_screenshot",
            "value": "overlay_window",
            "url": "/static/screenshots/abc_event_overlay_window.png",
            "t": 101,
        },
        {"kind": "sms_intercepted", "value": "+15551234567", "t": 200},
        {
            "kind": "event_screenshot",
            "value": "sms_intercepted",
            "url": "/static/screenshots/abc_event_sms_intercepted.png",
            "t": 201,
        },
    ]
    outcome = _diff_against_predictions(events, {})
    assert outcome.event_screenshots == [
        {"kind": "overlay_window", "url": "/static/screenshots/abc_event_overlay_window.png", "t": 101},
        {"kind": "sms_intercepted", "url": "/static/screenshots/abc_event_sms_intercepted.png", "t": 201},
    ]
    # The synthetic event_screenshot entries themselves show up in the
    # timeline too — they're real, timestamped occurrences, not noise.
    assert any(e["kind"] == "event_screenshot" for e in outcome.timeline)


def test_diff_ignores_event_screenshot_with_no_url():
    events = [{"kind": "event_screenshot", "value": "overlay_window", "url": None, "t": 100}]
    outcome = _diff_against_predictions(events, {})
    assert outcome.event_screenshots == []


def test_diff_reports_not_seen_for_unmatched_prediction():
    events = [{"kind": "network", "value": "9.9.9.9:80"}]
    outcome = _diff_against_predictions(events, {"c2_indicators": ["evil.example.com"], "dcl_targets": []})
    assert outcome.network_confirmed == []
    assert outcome.network_predicted_not_seen == ["evil.example.com"]


def test_diff_dcl_payload_executed_matches_substring():
    events = [{"kind": "dcl_class_load", "value": "com.evil.Payload"}]
    outcome = _diff_against_predictions(
        events, {"c2_indicators": [], "dcl_targets": ['DexClassLoader("com.evil.Payload")']}
    )
    assert outcome.dcl_payload_executed is True
    assert outcome.dcl_classes_loaded == ["com.evil.Payload"]


def test_diff_dcl_not_executed_when_no_classes_loaded():
    outcome = _diff_against_predictions([], {"c2_indicators": [], "dcl_targets": ["anything"]})
    assert outcome.dcl_payload_executed is False


def test_diff_sms_accessibility_crypto_flags():
    events = [
        {"kind": "sms_send", "value": "+1555"},
        {"kind": "accessibility_bound", "value": "com.evil.Service"},
        {"kind": "crypto_invoked", "value": "AES"},
    ]
    outcome = _diff_against_predictions(events, {})
    assert outcome.sms_api_invoked is True
    assert outcome.accessibility_bound is True
    assert outcome.crypto_invoked is True


def test_diff_confirms_native_library_matching_prediction():
    events = [{"kind": "native_library_loaded", "value": "foo"}]
    outcome = _diff_against_predictions(
        events, {"native_targets": ['System.loadLibrary("foo") -> libfoo.so, 12 dynamic symbols']}
    )
    assert outcome.native_libraries_loaded == ["foo"]
    assert outcome.native_library_confirmed is True


def test_diff_native_library_not_confirmed_when_prediction_does_not_match():
    events = [{"kind": "native_library_loaded", "value": "bar"}]
    outcome = _diff_against_predictions(
        events, {"native_targets": ['System.loadLibrary("foo") -> libfoo.so, 12 dynamic symbols']}
    )
    assert outcome.native_libraries_loaded == ["bar"]
    assert outcome.native_library_confirmed is False


def test_diff_native_library_confirmed_with_no_static_prediction():
    # No static prediction to diff against (e.g. cache-hit record predating
    # RE-deepdive persistence) — a genuinely observed load still counts.
    events = [{"kind": "native_library_loaded", "value": "foo"}]
    outcome = _diff_against_predictions(events, {})
    assert outcome.native_library_confirmed is True


def test_diff_extracts_crash_logcat_tail():
    events = [
        {"kind": "target_crashed", "value": "process exited/crashed mid-capture"},
        {"kind": "crash_logcat", "value": "line one\nline two\nline three"},
    ]
    outcome = _diff_against_predictions(events, {})
    assert outcome.crash_logcat_tail == ["line one", "line two", "line three"]
    # A multi-line log dump has no place cluttering the compact timeline.
    assert all(e["kind"] != "crash_logcat" for e in outcome.timeline)


def test_diff_crash_logcat_tail_empty_without_crash():
    outcome = _diff_against_predictions([{"kind": "network", "value": "1.2.3.4:443"}], {})
    assert outcome.crash_logcat_tail == []


def test_broadcast_declared_actions_filters_and_survives_failures(monkeypatch):
    calls = []

    def fake_adb(args, timeout=30):
        calls.append(args)
        if "android.intent.action.PROTECTED" in args:
            raise dv._DynamicVerificationError("permission denied")
        return ""

    monkeypatch.setattr(dv, "_adb", fake_adb)
    sent = _broadcast_declared_actions(
        "com.example.evil",
        [
            "android.intent.action.BOOT_COMPLETED",
            "com.example.evil.CUSTOM_ACTION",  # not android./com.google. — skipped
            "android.intent.action.PROTECTED",  # fails — must not abort the loop
            "com.google.android.c2dm.intent.RECEIVE",
            None,  # defensive: must not crash on a falsy entry
        ],
    )
    # Only the well-known-prefixed actions were attempted; the failing one
    # still counted as attempted but not as "sent".
    attempted = [c[-1] for c in calls]
    assert attempted == [
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.PROTECTED",
        "com.google.android.c2dm.intent.RECEIVE",
    ]
    assert sent == 2
    # Every broadcast is scoped to the target package.
    assert all("-p" in c and "com.example.evil" in c for c in calls)


_COMPAT_DIALOG_XML = """<?xml version="1.0"?>
<hierarchy>
  <node text="This app was built for an older version of Android" clickable="false" bounds="[0,300][1080,600]" />
  <node text="OK" clickable="true" bounds="[880,700][1000,780]" />
</hierarchy>
"""

_NO_DIALOG_XML = """<?xml version="1.0"?>
<hierarchy>
  <node text="" clickable="true" bounds="[0,0][100,100]" />
</hierarchy>
"""


def test_dismiss_blocking_dialog_taps_center_of_matching_button(monkeypatch):
    calls = []

    def fake_adb(args, timeout=30):
        calls.append(args)
        if args[:2] == ["shell", "cat"]:
            return _COMPAT_DIALOG_XML
        return ""

    monkeypatch.setattr(dv, "_adb", fake_adb)
    dismissed = _dismiss_blocking_dialog()
    assert dismissed is True
    tap_calls = [c for c in calls if "tap" in c]
    assert len(tap_calls) == 1
    # Center of bounds [880,700][1000,780] -> (940, 740).
    assert tap_calls[0][-2:] == ["940", "740"]


def test_dismiss_blocking_dialog_returns_false_when_nothing_matches(monkeypatch):
    def fake_adb(args, timeout=30):
        if args[:2] == ["shell", "cat"]:
            return _NO_DIALOG_XML
        return ""

    monkeypatch.setattr(dv, "_adb", fake_adb)
    assert _dismiss_blocking_dialog() is False


def test_dismiss_blocking_dialog_survives_adb_failure(monkeypatch):
    def fake_adb(args, timeout=30):
        raise dv._DynamicVerificationError("device offline")

    monkeypatch.setattr(dv, "_adb", fake_adb)
    assert _dismiss_blocking_dialog() is False


def test_dismiss_blocking_dialog_survives_malformed_xml(monkeypatch):
    def fake_adb(args, timeout=30):
        if args[:2] == ["shell", "cat"]:
            return "not valid xml <<<"
        return ""

    monkeypatch.setattr(dv, "_adb", fake_adb)
    assert _dismiss_blocking_dialog() is False


def test_dismiss_blocking_dialogs_stops_once_nothing_left_to_dismiss(monkeypatch):
    # First two dumps still show the dialog (simulating a second dialog
    # appearing right behind the first); third dump shows nothing left.
    responses = iter([_COMPAT_DIALOG_XML, _COMPAT_DIALOG_XML, _NO_DIALOG_XML])
    dump_count = 0

    def fake_adb(args, timeout=30):
        nonlocal dump_count
        if args[:2] == ["shell", "cat"]:
            dump_count += 1
            return next(responses)
        return ""

    monkeypatch.setattr(dv, "_adb", fake_adb)
    dv._dismiss_blocking_dialogs(max_attempts=5)
    # Stopped after the third dump found nothing — did not run all 5 attempts.
    assert dump_count == 3


def test_diff_hook_errors_surface_in_coverage_note():
    events = [{"kind": "hook_error", "value": "crypto: ClassNotFoundException"}]
    outcome = _diff_against_predictions(events, {})
    assert "hook(s) failed to install" in outcome.coverage_note


def test_run_dynamic_verification_fails_closed_without_package_name():
    result = run_dynamic_verification(
        apk_path="does_not_matter.apk", package_name=None, static_predictions={}
    )
    assert result["ran"] is False
    assert "no package name" in result["coverage_note"]


def test_run_dynamic_verification_fails_closed_on_adb_failure():
    # No real adb/AVD in a CI environment (or if adb_path is misconfigured) —
    # this must degrade to ran=False, never raise.
    result = run_dynamic_verification(
        apk_path="does_not_matter.apk",
        package_name="com.example.doesnotexist",
        static_predictions={},
        timeout_s=1,
    )
    assert result["ran"] is False
    assert isinstance(result["coverage_note"], str) and result["coverage_note"]


def test_outcome_to_dict_round_trip():
    outcome = DynamicVerificationOutcome(ran=True, duration_s=12.345, sms_api_invoked=True)
    d = outcome.to_dict()
    assert d["ran"] is True
    assert d["duration_s"] == 12.35  # rounded
    assert d["sms_api_invoked"] is True


def test_dynamic_confirmation_floor_raises_verdict_on_confirmed_c2():
    # Every weighted component near-zero; only the dynamic confirmation should
    # push this above the weighted total.
    score = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=_empty_obfuscation(),
        entropy_threshold=7.2,
        classifier_evidence_present=False,
        dynamic_verification={"ran": True, "network_confirmed": ["evil.example.com"]},
    )
    assert score.dynamic_confirmation_floor_applied is True
    assert score.total_score >= DYNAMIC_CONFIRMATION_SCORE_FLOOR["c2_contact_confirmed"]


def test_dynamic_verification_not_run_never_lowers_or_raises_score():
    baseline = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=_empty_obfuscation(),
        entropy_threshold=7.2,
        classifier_evidence_present=False,
    )
    with_not_run = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=_empty_obfuscation(),
        entropy_threshold=7.2,
        classifier_evidence_present=False,
        dynamic_verification={"ran": False, "coverage_note": "no AVD"},
    )
    assert with_not_run.total_score == baseline.total_score
    assert with_not_run.dynamic_confirmation_floor_applied is False


def test_dynamic_verification_ran_but_empty_never_lowers_score():
    baseline = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=_empty_obfuscation(),
        entropy_threshold=7.2,
        classifier_evidence_present=False,
    )
    with_empty = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=_empty_obfuscation(),
        entropy_threshold=7.2,
        classifier_evidence_present=False,
        dynamic_verification={"ran": True, "network_confirmed": [], "dcl_payload_executed": False},
    )
    assert with_empty.total_score == baseline.total_score


# ─── AVD auto-boot (Phase 8 no longer requires a hand-started emulator) ───────
# A booted AVD used to be a precondition a human had to satisfy before every
# dynamic run. These lock in the parts that must not regress: an already-online
# device costs nothing, an ambiguous AVD choice refuses rather than guessing
# (picking a google_apis_playstore image silently breaks Frida injection much
# later), and a boot that never completes fails cleanly instead of hanging.

def _boom(*args, **kwargs):
    """Stand-in for a call that must NOT happen on the path under test."""
    raise AssertionError(f"unexpected call: args={args} kwargs={kwargs}")


_DEVICES_ONLINE = "List of devices attached\nemulator-5554\tdevice\n"
_DEVICES_NONE = "List of devices attached\n"
_DEVICES_OFFLINE = "List of devices attached\nemulator-5554\toffline\n"


def test_ensure_device_booted_is_a_noop_when_a_device_is_already_online(monkeypatch):
    calls = []

    def fake_adb(args, timeout=30):
        calls.append(args)
        return _DEVICES_ONLINE

    monkeypatch.setattr(dv, "_adb", fake_adb)
    # Would raise OSError if it tried to launch anything.
    monkeypatch.setattr(dv.subprocess, "Popen", _boom)
    dv._ensure_device_booted()
    assert calls == [["devices"]]


def test_ensure_device_booted_does_not_count_an_offline_device(monkeypatch):
    # A half-attached emulator accepts a connection but fails every real
    # command — it must not be mistaken for a usable device.
    monkeypatch.setattr(dv, "_adb", lambda args, timeout=30: _DEVICES_OFFLINE)
    assert dv._device_is_online() is False


def test_ensure_device_booted_refuses_when_auto_boot_is_disabled(monkeypatch):
    monkeypatch.setattr(dv, "_adb", lambda args, timeout=30: _DEVICES_NONE)
    monkeypatch.setattr(dv.settings, "dynamic_analysis_auto_boot", False)
    monkeypatch.setattr(dv.subprocess, "Popen", _boom)
    with pytest.raises(dv._DynamicVerificationError, match="auto-boot is disabled"):
        dv._ensure_device_booted()


def test_resolve_avd_name_refuses_to_guess_between_several_avds(monkeypatch):
    monkeypatch.setattr(dv.settings, "avd_name", "")
    monkeypatch.setattr(dv, "_list_avds", lambda: ["Pixel_5", "Pixel_10_Pro_XL"])
    with pytest.raises(dv._DynamicVerificationError) as exc:
        dv._resolve_avd_name()
    # Names them, so the fix is obvious, and warns about the Play-signed trap.
    assert "Pixel_5" in str(exc.value) and "Pixel_10_Pro_XL" in str(exc.value)
    assert "AVD_NAME" in str(exc.value)


def test_resolve_avd_name_auto_selects_the_only_installed_avd(monkeypatch):
    monkeypatch.setattr(dv.settings, "avd_name", "")
    monkeypatch.setattr(dv, "_list_avds", lambda: ["guardgraph_test"])
    assert dv._resolve_avd_name() == "guardgraph_test"


def test_resolve_avd_name_prefers_the_configured_name_over_autodetection(monkeypatch):
    monkeypatch.setattr(dv.settings, "avd_name", "Pixel_5")
    monkeypatch.setattr(dv, "_list_avds", _boom)
    assert dv._resolve_avd_name() == "Pixel_5"


def test_ensure_device_booted_waits_for_boot_completed_not_just_attachment(monkeypatch):
    # `adb devices` reports `device` well before the framework is up; installing
    # into that window fails in confusing ways, so boot_completed is the signal.
    states = iter([
        (_DEVICES_NONE, None),
        (_DEVICES_ONLINE, "0"),   # attached but still booting
        (_DEVICES_ONLINE, "1"),   # ready
    ])
    current = {"devices": _DEVICES_NONE, "booted": None}

    def fake_adb(args, timeout=30):
        if args == ["devices"]:
            current["devices"], current["booted"] = next(states)
            return current["devices"]
        if args[:2] == ["shell", "getprop"]:
            return current["booted"] or ""
        return ""

    monkeypatch.setattr(dv, "_adb", fake_adb)
    monkeypatch.setattr(dv.settings, "dynamic_analysis_auto_boot", True)
    monkeypatch.setattr(dv.settings, "avd_name", "Pixel_5")
    monkeypatch.setattr(dv.subprocess, "Popen", lambda *a, **k: None)
    monkeypatch.setattr(dv.time, "sleep", lambda s: None)
    dv._ensure_device_booted()  # returns only once getprop reports "1"


def test_ensure_device_booted_times_out_instead_of_hanging(monkeypatch):
    monkeypatch.setattr(dv, "_adb", lambda args, timeout=30: _DEVICES_NONE)
    monkeypatch.setattr(dv.settings, "dynamic_analysis_auto_boot", True)
    monkeypatch.setattr(dv.settings, "avd_name", "Pixel_5")
    monkeypatch.setattr(dv.settings, "avd_boot_timeout_seconds", 0)
    monkeypatch.setattr(dv.subprocess, "Popen", lambda *a, **k: None)
    monkeypatch.setattr(dv.time, "sleep", lambda s: None)
    with pytest.raises(dv._DynamicVerificationError, match="did not finish booting"):
        dv._ensure_device_booted()
