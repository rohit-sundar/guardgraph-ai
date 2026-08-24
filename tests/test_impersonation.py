"""
Tests for app/analysis/impersonation.py — the "fraudulent app" checks.

The module answers a different question from the rest of the engine ("is this app
pretending to be a different, legitimate app?"), so these tests are about *identity*,
not payload. Two properties matter most and are tested hardest:

  1. It must FAIL CLOSED. Every check needs its reference datum. A brand with no
     recorded certificate must produce no certificate finding — silence, not a guess —
     because the alternative is accusing a genuine app of being a clone.
  2. It must not fire on the real app. The legitimate publisher's own APK matches its
     own package, label and icon, and must come back clean on all four checks.

The pHash tests build their images in-memory rather than shipping fixtures, so they
exercise the actual transform (rescale, recompress, recolour) instead of asserting a
stored constant.

Fully offline — no APKs, no model, no Neo4j.
"""
import io

import pytest

from app.analysis.impersonation import (
    ICON_MATCH_MAX_DISTANCE,
    Brand,
    detect_impersonation,
    edit_distance,
    hamming_distance,
    normalize_confusables,
    perceptual_hash,
)

PIL = pytest.importorskip("PIL", reason="Pillow is required for icon hashing")


# ── fixtures ──────────────────────────────────────────────────────────────────

REAL_CERT = "a" * 64
CLONE_CERT = "b" * 64


def brand(**overrides) -> Brand:
    base = dict(
        name="PhonePe",
        category="upi",
        packages=["com.phonepe.app"],
        labels=["PhonePe"],
        icon_phash=None,
        cert_sha256=[REAL_CERT],
        verified=True,
    )
    base.update(overrides)
    return Brand(**base)


def _icon(seed: int, size: int = 192, fmt: str = "PNG") -> bytes:
    """A deterministic, structured test icon — not flat noise, which hashes unstably."""
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (size, size), (250, 250, 250))
    draw = ImageDraw.Draw(img)
    rng = (seed * 37) % 200
    draw.ellipse([size * 0.1, size * 0.1, size * 0.9, size * 0.9],
                 fill=(rng, (rng * 3) % 255, (rng * 7) % 255))
    draw.rectangle([size * 0.3, size * 0.35, size * 0.7, size * 0.5],
                   fill=(255 - rng, 40, (rng * 2) % 255))
    draw.polygon([(size * 0.5, size * 0.55), (size * 0.75, size * 0.85),
                  (size * 0.25, size * 0.85)], fill=(20, 200 - (rng % 150), 90))
    buffer = io.BytesIO()
    img.save(buffer, format=fmt)
    return buffer.getvalue()


def _rescaled(data: bytes, size: int, fmt: str = "JPEG", quality: int = 70) -> bytes:
    """What a repackager's icon actually looks like: resized and recompressed."""
    from PIL import Image

    with Image.open(io.BytesIO(data)) as img:
        out = img.convert("RGB").resize((size, size), Image.LANCZOS)
    buffer = io.BytesIO()
    out.save(buffer, format=fmt, quality=quality)
    return buffer.getvalue()


# ── perceptual hash ───────────────────────────────────────────────────────────

def test_phash_is_stable_across_rescale_and_recompression():
    """The whole point: a clone that resizes and re-encodes the icon still matches."""
    original = perceptual_hash(_icon(1))
    clone = perceptual_hash(_rescaled(_icon(1), 96))
    assert original is not None and clone is not None
    assert hamming_distance(original, clone) <= ICON_MATCH_MAX_DISTANCE


def test_phash_separates_different_icons():
    a = perceptual_hash(_icon(1))
    b = perceptual_hash(_icon(9))
    assert hamming_distance(a, b) > ICON_MATCH_MAX_DISTANCE


def test_phash_ignores_transparency_background():
    """
    An RGBA logo and the same logo flattened onto white must hash alike — otherwise a
    reference icon captured one way never matches a sample captured the other.
    """
    from PIL import Image

    with Image.open(io.BytesIO(_icon(3))) as img:
        rgba = img.convert("RGBA")
    buffer = io.BytesIO()
    rgba.save(buffer, format="PNG")
    assert hamming_distance(perceptual_hash(_icon(3)),
                            perceptual_hash(buffer.getvalue())) <= ICON_MATCH_MAX_DISTANCE


def test_phash_returns_none_on_non_image_bytes():
    """Adaptive-icon XML is the common real case — a gap, never a match."""
    assert perceptual_hash(b'<?xml version="1.0"?><adaptive-icon/>') is None
    assert perceptual_hash(b"") is None


# ── string normalisation ──────────────────────────────────────────────────────

@pytest.mark.parametrize("spoofed,genuine", [
    ("PhonePe", "phonepe"),
    ("РhonePe", "phonepe"),        # Cyrillic Er
    ("Ph0nePe", "phonepe"),        # zero for o
    ("P h o n e P e", "phonepe"),  # spacing
    ("ＰhonePe", "phonepe"),        # fullwidth
])
def test_confusable_normalisation_folds_spoofed_brand_strings(spoofed, genuine):
    assert normalize_confusables(spoofed) == normalize_confusables(genuine)


def test_multichar_confusables_fold():
    assert normalize_confusables("rnodi") == normalize_confusables("modi")


def test_edit_distance_respects_its_cap():
    assert edit_distance("abcdef", "abcdef", 2) == 0
    assert edit_distance("abcdef", "abcdeg", 2) == 1
    assert edit_distance("abcdef", "zzzzzz", 2) == 3  # cap + 1, abandoned early


# ── the four checks ───────────────────────────────────────────────────────────

def test_genuine_app_produces_no_findings():
    """The property that protects real banks: its own APK must come back clean."""
    icon = perceptual_hash(_icon(2))
    result = detect_impersonation(
        package_name="com.phonepe.app",
        app_label="PhonePe",
        cert_sha256=REAL_CERT,
        icon_phash=icon,
        brands=[brand(icon_phash=icon)],
    )
    assert result.findings == []


def test_certificate_mismatch_on_exact_package():
    result = detect_impersonation(
        package_name="com.phonepe.app",
        app_label="PhonePe",
        cert_sha256=CLONE_CERT,
        brands=[brand()],
    )
    assert [f.kind for f in result.findings] == ["certificate_mismatch"]
    assert result.max_severity == 1.0


def test_certificate_check_is_silent_without_a_reference_certificate():
    """Fail closed. No recorded cert means no opinion, not an accusation."""
    result = detect_impersonation(
        package_name="com.phonepe.app",
        app_label="PhonePe",
        cert_sha256=CLONE_CERT,
        brands=[brand(cert_sha256=[])],
    )
    assert result.findings == []
    assert any("no signing certificate" in note for note in result.coverage)


def test_certificate_check_is_silent_when_the_sample_is_unsigned():
    result = detect_impersonation(
        package_name="com.phonepe.app",
        cert_sha256=None,
        brands=[brand()],
    )
    assert [f.kind for f in result.findings] != ["certificate_mismatch"]
    assert any("signing certificate unavailable" in n for n in result.coverage)


def test_icon_reuse_flagged_on_a_foreign_package():
    icon = perceptual_hash(_icon(4))
    result = detect_impersonation(
        package_name="com.free.wallet.rewards",
        app_label="Free Wallet",
        icon_phash=perceptual_hash(_rescaled(_icon(4), 72)),
        brands=[brand(icon_phash=icon)],
    )
    assert [f.kind for f in result.findings] == ["icon_reuse"]


def test_icon_check_is_silent_without_a_reference_icon():
    result = detect_impersonation(
        package_name="com.free.wallet.rewards",
        icon_phash=perceptual_hash(_icon(4)),
        brands=[brand(icon_phash=None)],
    )
    assert result.findings == []
    assert any("no icon hash" in note for note in result.coverage)


@pytest.mark.parametrize("squat", [
    "com.phonpe.app",       # dropped character
    "com.ph0nepe.app",      # zero for o
    "com.phonepe.aap",      # transposition
])
def test_package_typosquat_detected(squat):
    result = detect_impersonation(package_name=squat, brands=[brand()])
    assert [f.kind for f in result.findings] == ["package_typosquat"]


def test_unrelated_package_is_not_a_typosquat():
    result = detect_impersonation(
        package_name="org.videolan.vlc", app_label="VLC", brands=[brand()]
    )
    assert result.findings == []


def test_label_impersonation_on_a_foreign_package():
    result = detect_impersonation(
        package_name="com.rewards.cashback.free",
        app_label="PhonePe",
        brands=[brand()],
    )
    assert [f.kind for f in result.findings] == ["label_impersonation"]


def test_short_labels_are_compared_exactly_only():
    """
    'BHIM' is 4 characters; a fuzzy match at distance 2 would swallow unrelated
    four-letter names, so short labels require exact (normalised) equality.
    """
    bhim = brand(name="BHIM", packages=["in.org.npci.upiapp"], labels=["BHIM"])
    assert detect_impersonation(
        package_name="com.some.other.app", app_label="BHAT", brands=[bhim]
    ).findings == []
    assert detect_impersonation(
        package_name="com.some.other.app", app_label="bhim", brands=[bhim]
    ).findings != []


def test_one_finding_per_brand_strongest_first():
    """A cert mismatch already implies the package matched — don't double-count it."""
    result = detect_impersonation(
        package_name="com.phonepe.app",
        app_label="PhonePe",
        cert_sha256=CLONE_CERT,
        icon_phash=perceptual_hash(_icon(5)),
        brands=[brand(icon_phash=perceptual_hash(_icon(5)))],
    )
    assert len(result.findings) == 1
    assert result.findings[0].kind == "certificate_mismatch"


def test_findings_sorted_by_severity_across_brands():
    other = brand(name="Paytm", packages=["net.one97.paytm"], labels=["Paytm"],
                  cert_sha256=[REAL_CERT])
    result = detect_impersonation(
        package_name="net.one97.paytm",     # exact package of Paytm -> cert mismatch
        app_label="PhonePe",                # label of PhonePe       -> impersonation
        cert_sha256=CLONE_CERT,
        brands=[brand(), other],
    )
    kinds = [f.kind for f in result.findings]
    assert kinds == ["certificate_mismatch", "label_impersonation"]


# ── coverage reporting ────────────────────────────────────────────────────────

def test_empty_reference_reports_no_coverage_rather_than_all_clear():
    result = detect_impersonation(package_name="com.anything", brands=[])
    assert result.findings == []
    assert result.brands_checked == 0
    assert any("no protected-brand reference" in n for n in result.coverage)


def test_unparsed_manifest_reports_the_gap():
    result = detect_impersonation(package_name=None, brands=[brand()])
    assert any("package name unavailable" in n for n in result.coverage)


def test_shipped_reference_table_loads_and_is_self_consistent():
    """The committed table must parse, and must not contain duplicate packages."""
    from app.analysis.impersonation import load_reference

    brands = load_reference()
    assert brands, "data/reference/protected_brands.json failed to load"
    seen: dict[str, str] = {}
    for b in brands:
        assert b.packages or b.labels, f"{b.name} has neither a package nor a label"
        for package in b.packages:
            assert package not in seen, f"{package} claimed by {seen[package]} and {b.name}"
            seen[package] = b.name


def test_shipped_reference_brands_do_not_collide_with_each_other():
    """
    No genuine brand may look like a typosquat of another genuine brand — that would
    flag both real apps.
    """
    from app.analysis.impersonation import load_reference

    brands = load_reference()
    for b in brands:
        for package in b.packages:
            result = detect_impersonation(
                package_name=package,
                app_label=b.labels[0] if b.labels else None,
                brands=brands,
            )
            assert result.findings == [], (
                f"genuine package {package} ({b.name}) was flagged: "
                f"{[f.to_dict() for f in result.findings]}"
            )


def test_no_label_is_an_unresolved_resource_reference():
    """
    An app installed from a bundle keeps its strings in a language split, so parsing
    base.apk alone resolves the label to a raw resource id — "@7F124DF6", or
    "<0x5120, type 0x00>". Both were written into the table as display names when it was
    first populated from pulled APKs. _check_label then fuzzy-matches real app names
    against that garbage, so it must never be recorded.
    """
    import re

    from app.analysis.impersonation import load_reference

    unresolved = re.compile(r"^(@[0-9A-Fa-f]+|<0x[0-9A-Fa-f]+,.*>)$")
    for b in load_reference():
        for label in b.labels:
            assert not unresolved.match(label), (
                f"{b.name} carries an unresolved resource reference as a label: {label!r}. "
                "scripts/build_brand_reference.py filters these; it was regenerated with an "
                "older copy, or the value was hand-edited in."
            )
            assert label.strip(), f"{b.name} has a blank label"


def test_verified_means_a_certificate_was_recorded():
    """
    `verified` is what the status line and the README count, so it has to mean one thing:
    a signing certificate came off a real APK. It deliberately does NOT also require an
    icon hash — most modern apps ship an adaptive (XML) launcher icon, which has no pixels
    to hash, so requiring it would pin `verified: false` forever on brands whose
    certificate check works perfectly.
    """
    import json
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "data", "reference",
                        "protected_brands.json")
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)

    for entry in raw["brands"]:
        has_cert = bool(entry.get("cert_sha256"))
        assert bool(entry.get("verified")) == has_cert, (
            f"{entry['brand']}: verified={entry.get('verified')} but "
            f"{len(entry.get('cert_sha256') or [])} certificate(s) recorded"
        )


def test_every_package_of_a_certified_brand_is_covered():
    """
    Once a brand carries any certificate, EVERY package listed under it is checked against
    that list — so a package whose own signing key was never recorded makes the genuine app
    on it read as a clone of itself. Measured: a two-package brand with one recorded key
    flags the genuine sibling as certificate_mismatch.

    There is no way to tell from the file alone whether one key legitimately covers several
    packages (publishers often sign every variant with one key) — so this asserts the weaker
    invariant that actually catches the mistake: a certified brand must not list more
    packages than it has recorded keys, unless a human recorded that they share a key.
    """
    import json
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "data", "reference",
                        "protected_brands.json")
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)

    for entry in raw["brands"]:
        certs = entry.get("cert_sha256") or []
        packages = entry.get("packages") or []
        if not certs or len(packages) <= 1:
            continue
        assert len(certs) >= len(packages) or entry.get("shared_signing_key") is True, (
            f"{entry['brand']} lists {len(packages)} packages but only {len(certs)} "
            f"certificate(s). Either record a key for each package, drop the unverified "
            f"ones, or set \"shared_signing_key\": true if the publisher genuinely signs "
            f"them all with one key."
        )


# ── scoring integration ───────────────────────────────────────────────────────

def _obfuscation():
    from app.core.schemas import ObfuscationSignal

    return ObfuscationSignal(
        string_entropy_score=0.0, flattening_suspected=False,
        flattening_outlier_nodes=[], reflection_call_count=0,
        unresolved_reflection_targets=0, method_parse_failure_rate=0.0,
        coverage_note="",
    )


def _score(findings):
    from app.reports.scoring import compute_risk_score

    return compute_risk_score(
        {}, [], _obfuscation(), 7.2, impersonation_findings=findings
    )


def test_impersonation_floor_lands_in_its_intended_band():
    """
    Pins the floors against the band boundaries they are derived from, so moving a
    boundary cannot silently demote an impersonation verdict.
    """
    from app.reports.scoring import (
        IMPERSONATION_FLOOR_BAND,
        IMPERSONATION_SCORE_FLOOR,
        _band_for,
    )

    assert set(IMPERSONATION_SCORE_FLOOR) == set(IMPERSONATION_FLOOR_BAND)
    for kind, floor in IMPERSONATION_SCORE_FLOOR.items():
        assert _band_for(floor) == IMPERSONATION_FLOOR_BAND[kind], (
            f"{kind} floor {floor} reads as {_band_for(floor)}, "
            f"not {IMPERSONATION_FLOOR_BAND[kind]}"
        )


def test_near_inert_clone_of_a_bank_app_is_not_reported_low():
    """
    The case the floor exists for. A cloned banking app can carry an unremarkable
    payload — every weighted component near zero — and the weighted total alone would
    file it as `low`, which is the worst possible answer for the highest-harm app in
    the queue.
    """
    clean = _score(None)
    clone = _score([{"kind": "certificate_mismatch", "brand": "PhonePe"}])

    assert clean.verdict_band == "low"
    assert clone.verdict_band == "malicious"
    assert clone.impersonation_floor_applied is True
    assert clone.weighted_score == clean.total_score


def test_floor_never_lowers_a_score_the_behaviour_earned():
    """A clone that is also obvious malware keeps the higher arithmetic verdict."""
    from app.reports.scoring import compute_risk_score

    strong = dict(
        predicted_ttps={"T1471": 0.95, "T1417": 0.9, "T1636": 0.9},
        permissions=["android.permission.RECEIVE_SMS", "android.permission.READ_SMS"],
        obfuscation=_obfuscation(),
        entropy_threshold=7.2,
        matched_anchor_behaviors={"STEALTH_SMS_INTERCEPTION", "OTP_INTERCEPTION"},
        permission_matrix_flags=["SMS_OTP_STEALER_PATTERN"],
        is_known_malware=True,
    )
    without = compute_risk_score(**strong)
    with_weak = compute_risk_score(
        **strong, impersonation_findings=[{"kind": "label_impersonation"}]
    )
    assert with_weak.total_score == without.total_score
    assert with_weak.impersonation_floor_applied is False


def test_strongest_finding_sets_the_floor():
    both = _score([
        {"kind": "label_impersonation"},
        {"kind": "certificate_mismatch"},
    ])
    assert both.verdict_band == "malicious"


def test_unknown_finding_kind_sets_no_floor():
    """A finding kind with no mapped floor must not silently score zero-or-anything."""
    result = _score([{"kind": "some_future_check"}])
    assert result.impersonation_floor_applied is False
    assert result.verdict_band == "low"


def test_no_findings_leaves_the_weighted_score_untouched():
    result = _score([])
    assert result.impersonation_floor_applied is False
    assert result.total_score == result.weighted_score


# ── package_namespace_squat ───────────────────────────────────────────────────
# A package that is a protected package plus a suffix. Added after measuring the
# malware corpus: three samples wear org.telegram.messenger.<random> and NONE of
# the four original checks fired on any of them — the typosquat check cannot see
# them, because appending ".wgstjg" is an edit distance of 6-7 against a cap of 2.


def test_namespace_squat_is_caught_where_the_typosquat_check_cannot_reach():
    from app.analysis.impersonation import PACKAGE_MAX_EDIT_DISTANCE, edit_distance

    squat = "com.phonepe.app.wgstjg"
    # The premise: this is genuinely out of the typosquat check's range, so the new
    # check is covering a real gap rather than duplicating an existing one.
    assert edit_distance(
        squat.replace(".", ""), "comphonepeapp", PACKAGE_MAX_EDIT_DISTANCE
    ) > PACKAGE_MAX_EDIT_DISTANCE

    result = detect_impersonation(
        package_name=squat, app_label="Redeem Code", brands=[brand()]
    )
    assert [f.kind for f in result.findings] == ["package_namespace_squat"]
    assert result.findings[0].expected == "com.phonepe.app"


def test_a_brands_own_extended_package_is_not_a_squat():
    """
    The false positive this check could most easily create. Telegram ships
    org.telegram.messenger.beta itself; listing a brand's own extended builds in
    `packages` is what keeps them exempt.
    """
    result = detect_impersonation(
        package_name="com.phonepe.app.beta",
        app_label="PhonePe",
        brands=[brand(packages=["com.phonepe.app", "com.phonepe.app.beta"])],
    )
    assert result.findings == []


def test_a_longer_package_sharing_only_a_prefix_is_not_a_squat():
    """
    The dot is the whole point. `com.phonepe.application` starts with the brand's
    package as a *string* but does not extend its *namespace*, so it must not be
    reported — this is why the check runs on the raw package rather than the
    confusable-normalised form, which strips the dots that mark the boundary.
    """
    result = detect_impersonation(
        package_name="com.phonepe.application", app_label="Something Else",
        brands=[brand()],
    )
    assert [f.kind for f in result.findings] != ["package_namespace_squat"]


def test_namespace_squat_floors_the_verdict_at_high():
    """
    Floored the same as a typosquat, for a stronger reason: a package cannot reach
    "<brand's full namespace>.<random>" by mistyping.
    """
    result = _score([{"kind": "package_namespace_squat", "brand": "PhonePe"}])
    assert result.impersonation_floor_applied is True
    assert result.verdict_band == "high"


def test_a_genuine_package_is_not_accused_by_a_similarly_named_brand():
    """
    Two protected brands can have similar names, and then each one's REAL app reads
    as impersonating the other. Found the moment Bank of India was added: "BOI Mobile"
    is an edit distance of 2 from ICICI's "iMobile", so the genuine BOI APK was
    reported as impersonating ICICI iMobile.

    A package listed in the reference table is a known-genuine app, so the name-based
    checks are silenced for it.
    """
    boi = brand(name="Bank of India", packages=["com.boi.ua.android"],
                labels=["BOI Mobile"], cert_sha256=[], verified=False)
    icici = brand(name="ICICI iMobile", packages=["com.csam.icici.bank.imobile"],
                  labels=["iMobile"], cert_sha256=[], verified=False)

    result = detect_impersonation(
        package_name="com.boi.ua.android", app_label="BOI Mobile", brands=[boi, icici]
    )
    assert result.findings == []


def test_silencing_a_genuine_package_does_not_silence_the_evidence_checks():
    """
    The other half of that fix, and the more important half. Name-based checks are
    suppressed for a known-genuine package; certificate and icon checks are NOT —
    a wrong signing key on a genuine package name is precisely the clone this module
    exists to catch, and no amount of brand-name similarity can produce one.
    """
    result = detect_impersonation(
        package_name="com.phonepe.app", app_label="PhonePe",
        cert_sha256=CLONE_CERT, brands=[brand()],
    )
    assert [f.kind for f in result.findings] == ["certificate_mismatch"]


def test_a_disproven_owner_stops_silencing_the_other_brands():
    """
    The narrowing that makes the rule above safe. A package is only known-genuine
    while nothing contradicts it — a wrong signing key does contradict it, and then
    an APK wearing one brand's package while displaying another's name must still
    report both findings.
    """
    phonepe = brand()
    paytm = brand(name="Paytm", packages=["net.one97.paytm"], labels=["Paytm"],
                  cert_sha256=[REAL_CERT])
    result = detect_impersonation(
        package_name="net.one97.paytm", app_label="PhonePe",
        cert_sha256=CLONE_CERT, brands=[phonepe, paytm],
    )
    assert [f.kind for f in result.findings] == ["certificate_mismatch", "label_impersonation"]
