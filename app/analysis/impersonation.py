"""
Brand-impersonation detection — the "fraudulent app" half of the problem statement.

Everything else in this package answers "is this malware?". This module answers a
different question: **is this app pretending to be a different, legitimate app?** A
cloned banking or UPI app is fraud whether or not its payload trips a single forensic
anchor — the attack is the identity theft of the brand, and a repackaged clone with a
modest payload can score `low` on every other component in the engine while being the
single most damaging thing a user could install.

Four independent checks, in descending order of how hard they are to explain away:

  1. CERTIFICATE MISMATCH — the package name IS a protected brand's package, but the
     APK is signed by a different key. Android identifies publishers by signing key,
     not by package string, so this is not a heuristic: either the legitimate
     publisher signed it or somebody else did. A repackaged clone cannot avoid this.
  2. ICON REUSE — the launcher icon is perceptually the brand's icon, on a package
     that is not the brand's. Survives rescaling, recompression and minor recolouring.
  3. PACKAGE TYPOSQUAT — the package name is a near-miss of a protected package
     (`com.phonpe.app`), including confusable-character substitutions (rn/m, l/I/1,
     o/0) that read identically at a glance in a permissions dialog.
  4. LABEL IMPERSONATION — the app's display name is a brand's name (or a confusable
     rendering of it) on a package that is not the brand's. This is what the victim
     actually reads on the home screen.

FAIL CLOSED, like the rest of the analysis package. Every check needs its reference
datum to be present: if the reference table carries no certificate for a brand, the
certificate check returns nothing rather than asserting a mismatch it cannot see, and
`coverage` records which checks could not run. A brand entry with only a package name
still powers checks 3 and 4 — it simply cannot power 1 and 2, and says so.

The reference table lives in data/reference/protected_brands.json and is built by
scripts/build_brand_reference.py from real APKs. See that file's header: package names
alone are not enough to run this module at full strength, and unverified entries are
marked as such rather than trusted.

A FIFTH check runs when the four above find nothing: a LIVE lookup against the real
Google Play Store (app/analysis/brand_lookup.py), which generalizes checks 3/4 beyond
whatever happens to be in the static table — any real app, not just a pre-registered
66. It cannot do what checks 1/2 do (Play does not expose another developer's signing
key publicly), so it is deliberately scored weaker than every static-table finding and
its verdict floor never exceeds `suspicious` (see IMPERSONATION_SCORE_FLOOR in
app/reports/scoring.py). It only runs when no static finding already fired, mirroring
the local-first-then-online pattern in app/analysis/signatures.py.

A SIXTH, unconditional check answers a different question entirely: not "is this app
pretending to be a specific real company" (checks 1-5), but "does its label come from
the well-documented vocabulary of generic, trust-inspiring names — "Customer Support",
"System Update" — that Android RATs/spyware use to look innocuous during sideloaded
installation, with no single real company behind the name for checks 1-5 to compare
against" (see GENERIC_BAIT_LABELS). It is curated, not corpus-calibrated, and scored
and floored accordingly: the weakest severity in the module, and no verdict floor at
all — advisory only.
"""
from __future__ import annotations

import io
import json
import os
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import numpy as np
from loguru import logger

from app.analysis import brand_lookup
from app.core.config import settings

REFERENCE_PATH = os.path.join("data", "reference", "protected_brands.json")

# ── Perceptual hash ───────────────────────────────────────────────────────────
# 64-bit DCT ("pHash"), not the cheaper average hash: aHash keys on absolute
# brightness and a clone that lightens the icon a few percent walks straight past it,
# while the DCT's low-frequency coefficients describe the icon's *structure*. 32x32
# input reduced to the top-left 8x8 coefficient block is the standard construction.
PHASH_SIDE = 32
PHASH_BITS = 8

# Hamming distance at or below which two 64-bit pHashes are called the same image.
# 0-4 is "visually identical after recompression"; 10+ starts admitting unrelated
# icons that share a dominant shape. 8 keeps rescaled/recoloured clones while staying
# clear of generic round-logo collisions. Re-derive with
# `python scripts/build_brand_reference.py --collisions` after adding brands, which
# prints the pairwise distance matrix over the reference set itself — no two distinct
# brands should sit within this threshold of each other.
ICON_MATCH_MAX_DISTANCE = 8

# ── String similarity ─────────────────────────────────────────────────────────
# Levenshtein distance at or below which two package names are "confusably similar"
# AFTER confusable normalisation. 1-2 covers the realistic typosquat space
# (com.phonpe.app, com.phonepe.aap); beyond that the strings stop reading alike.
PACKAGE_MAX_EDIT_DISTANCE = 2
LABEL_MAX_EDIT_DISTANCE = 2
# Below this length, an edit distance of 2 can turn one real word into another, so
# short labels are compared for exact (normalised) equality only.
MIN_LABEL_LEN_FOR_FUZZY = 6

SEVERITY = {
    "certificate_mismatch": 1.0,
    "icon_reuse": 0.9,
    "package_namespace_squat": 0.85,
    "package_typosquat": 0.85,
    "label_impersonation": 0.75,
    # Live Play Store checks (see the module docstring's "FIFTH check" note and
    # brand_lookup.py) — weaker than every static-table finding above on
    # purpose: no verified certificate, a scraped title comparison rather than
    # a hand-verified reference entry.
    "package_identity_mismatch_live": 0.6,
    "label_impersonation_live": 0.6,
    # Weakest of all seven — see _check_generic_bait_label. Advisory only:
    # deliberately carries no entry in IMPERSONATION_SCORE_FLOOR, so it cannot
    # move a verdict band by itself.
    "generic_bait_label": 0.3,
}

# A SIXTH, different check from the five above (see module docstring): not "is
# this app pretending to be a specific real company", but "does its label come
# from the well-documented vocabulary of generic, trust-inspiring names Android
# RATs/spyware use to look innocuous during sideloaded installation" — SpyNote
# and its many clones are frequently seen under exactly names like these. No
# single real "Customer Support" exists to compare against, which is precisely
# why checks 1-5 cannot catch this case (confirmed live 2026-08-25: a synthetic
# SpyNote sample labeled "Customer Support" produced zero findings from every
# check above).
#
# CURATED, NOT CORPUS-CALIBRATED — unlike every severity above, this list was
# not measured against the project's calibration corpus (see the README's
# "What's real vs stubbed" table for what that process looks like). That is
# exactly why it carries the lowest severity here and no verdict-floor entry
# in app/reports/scoring.py's IMPERSONATION_SCORE_FLOOR at all: it is a visible,
# advisory-only signal for an analyst to weigh, not something this engine
# trusts enough to move a verdict band on its own. Widen or prune this list
# once it has been run against real corpus data, not by guesswork.
GENERIC_BAIT_LABELS = {
    # System/update/utility disguises — the classic RAT-sideloading vocabulary.
    "system update", "security update", "software update", "device update",
    "firmware update", "update service", "system service", "system optimizer",
    "battery optimizer", "storage cleaner", "cache cleaner", "memory booster",
    "cpu cooler", "phone booster", "speed booster", "google play update",
    "play store update", "chrome update", "flash player", "adobe flash player",
    "whatsapp update", "google service", "google services", "android update",
    "app update", "system settings", "device manager", "play protect",
    "security scan", "virus scan", "antivirus", "mobile security",
    "phone security",
    # Support/help-desk disguises.
    "customer support", "support service", "support center", "customer service",
    "help desk", "live chat support", "technical support", "tech support",
    # Courier/delivery lures — a staple of Indian smishing-to-APK campaigns
    # (a fake tracking/delivery-status app is a very common banking-fraud
    # dropper vector), which is this project's stated threat domain.
    "speed post", "india post", "parcel delivery", "courier service",
    "package delivery", "delivery status", "track order", "track parcel",
    "fedex", "dhl", "bluedart", "ecom express", "delhivery",
    # Government/KYC/tax lures — same domain, India-specific.
    "income tax", "income tax department", "kyc update", "kyc verification",
    "aadhaar update", "pan card update", "digital arrest", "court notice",
    "cyber crime", "cyber police", "e-challan", "traffic challan",
    "electricity bill", "bill payment",
    # Loan/credit lures.
    "loan approval", "instant loan", "personal loan", "credit score",
    "cibil score",
    # Job/reward/prize lures.
    "job offer", "work from home", "part time job", "lucky draw",
    "prize winner", "cashback offer",
    # Fake verification/certificate prompts.
    "install certificate", "security certificate", "app verification",
    "identity verification",
}

# Latin lookalikes for characters commonly used to spoof a brand string. Cyrillic and
# Greek homoglyphs are folded first (they are visually identical, not merely similar),
# then the multi-character Latin confusables that survive a glance at small sizes.
_CONFUSABLE_CHARS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",  # Cyrillic
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "ν": "v", "ι": "i",            # Greek
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}
_CONFUSABLE_PAIRS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"))


@dataclass
class ImpersonationFinding:
    """One reason to believe this APK is pretending to be `brand`."""
    kind: str
    brand: str
    severity: float
    detail: str
    observed: str
    expected: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "brand": self.brand,
            "severity": self.severity,
            "detail": self.detail,
            "observed": self.observed,
            "expected": self.expected,
        }


@dataclass
class ImpersonationResult:
    findings: list[ImpersonationFinding] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)
    brands_checked: int = 0

    @property
    def max_severity(self) -> float:
        return max((f.severity for f in self.findings), default=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "coverage": self.coverage,
            "brands_checked": self.brands_checked,
            "max_severity": self.max_severity,
        }


# ── perceptual hashing ────────────────────────────────────────────────────────

def _dct_2d(matrix: np.ndarray) -> np.ndarray:
    """
    Separable DCT-II via matrix multiplication.

    Hand-rolled rather than pulled from scipy/imagehash: the transform is one matrix
    product at this size, and neither dependency is otherwise needed by the project.
    """
    n = matrix.shape[0]
    k = np.arange(n).reshape(1, n)
    i = np.arange(n).reshape(n, 1)
    basis = np.cos(np.pi * (2 * i + 1) * k / (2 * n))
    return basis.T @ matrix @ basis


def perceptual_hash(image_bytes: bytes) -> Optional[int]:
    """
    64-bit pHash of an icon, or None if the bytes are not a decodable image.

    Adaptive-icon XML and other non-raster launcher icons decode to nothing — that is
    a coverage gap, not a match, and the caller reports it as one.
    """
    try:
        from PIL import Image

        with Image.open(io.BytesIO(image_bytes)) as img:
            # Flatten transparency onto white first: an RGBA icon converted straight
            # to greyscale drops alpha, so a transparent-background logo and a
            # white-background one hash differently for no visual reason.
            if img.mode in ("RGBA", "LA", "P"):
                img = img.convert("RGBA")
                flat = Image.new("RGBA", img.size, (255, 255, 255, 255))
                flat.alpha_composite(img)
                img = flat
            grey = img.convert("L").resize((PHASH_SIDE, PHASH_SIDE), Image.LANCZOS)
            pixels = np.asarray(grey, dtype=float)
    except Exception as exc:
        logger.debug(f"[impersonation] icon not decodable as a raster image: {exc}")
        return None

    low_freq = _dct_2d(pixels)[:PHASH_BITS, :PHASH_BITS]
    # The DC term encodes overall brightness, not structure; including it makes the
    # median a function of exposure.
    coefficients = low_freq.flatten()[1:]
    median = np.median(coefficients)

    bits = 0
    for index, value in enumerate(low_freq.flatten()):
        if value > median:
            bits |= 1 << index
    return bits


def hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


# ── string normalisation ──────────────────────────────────────────────────────

def normalize_confusables(text: str) -> str:
    """
    Folds a string to the form a victim actually perceives.

    NFKC first (so fullwidth and ligature forms collapse), then case, then the
    homoglyph map, then the multi-character Latin pairs. `PayTM`, `Ρaytm` (Greek rho)
    and `Payt m` all land on the same key — which is the point: the fraud works
    because these render alike, so the comparison has to treat them as alike.
    """
    if not text:
        return ""
    folded = unicodedata.normalize("NFKC", text).casefold()
    folded = "".join(_CONFUSABLE_CHARS.get(ch, ch) for ch in folded)
    for pair, replacement in _CONFUSABLE_PAIRS:
        folded = folded.replace(pair, replacement)
    return "".join(ch for ch in folded if ch.isalnum())


def edit_distance(a: str, b: str, cap: int) -> int:
    """
    Levenshtein distance, abandoned once it provably exceeds `cap`.

    The cap matters: this runs over every reference brand for every upload, and the
    answer is only ever compared against a small threshold.
    """
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if a == b:
        return 0

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,          # deletion
                current[j - 1] + 1,       # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


# ── reference table ───────────────────────────────────────────────────────────

@dataclass
class Brand:
    name: str
    category: str
    packages: list[str]
    labels: list[str]
    # Every launcher icon this brand is known to ship, not one.
    #
    # A brand is not one app. Bank of India publishes `com.boi.mpay`,
    # `com.boi.ua.android` and `com.boi.erupee.prod`, each with its own icon, and
    # a single stored hash silently means "clones of the other two are invisible".
    # Measured on the 2026-08-27 evaluation set, where the stored hash belonged to
    # a sibling app: the genuine BOI Mobile icon was Hamming 26 from its own
    # brand's reference — three times the match threshold — so the real app failed
    # its own check while three clones carrying BOI artwork (34, 40 and 42 away)
    # were never going to match either.
    icon_phashes: list[int]
    cert_sha256: list[str]
    verified: bool

    @property
    def normalized_packages(self) -> list[str]:
        return [normalize_confusables(p) for p in self.packages]

    @property
    def icon_phash(self) -> Optional[int]:
        """First known icon, for callers that predate the multi-icon table."""
        return self.icon_phashes[0] if self.icon_phashes else None

    def closest_icon(self, phash: int) -> Optional[tuple[int, int]]:
        """`(distance, matched_reference_hash)` for the nearest known icon."""
        if not self.icon_phashes:
            return None
        return min(
            ((hamming_distance(phash, ref), ref) for ref in self.icon_phashes),
            key=lambda pair: pair[0],
        )


def load_reference(path: str = REFERENCE_PATH) -> list[Brand]:
    """
    Loads the protected-brand table. Returns [] when it is absent or unreadable —
    impersonation checks then report zero coverage rather than blocking an analysis.
    """
    if not os.path.exists(path):
        logger.warning(
            f"[impersonation] no reference table at {path} — impersonation checks "
            "will not run. Build one with scripts/build_brand_reference.py."
        )
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception as exc:
        logger.error(f"[impersonation] reference table at {path} is unreadable: {exc}")
        return []

    brands: list[Brand] = []
    for entry in raw.get("brands", []):
        # `icon_phashes` (list) is the current shape; `icon_phash` (scalar) is the
        # original one and still loads, so an un-migrated table keeps working.
        raw_hashes = entry.get("icon_phashes")
        if raw_hashes is None:
            raw_hashes = [entry.get("icon_phash")]
        hashes: list[int] = []
        for value in raw_hashes:
            if isinstance(value, str):
                try:
                    hashes.append(int(value, 16))
                except ValueError:
                    logger.warning(
                        f"[impersonation] {entry.get('brand')}: icon hash "
                        f"{value!r} is not hex — skipped."
                    )
            elif isinstance(value, int):
                hashes.append(value)

        brands.append(Brand(
            name=entry.get("brand", "?"),
            category=entry.get("category", "unknown"),
            packages=[p for p in entry.get("packages", []) if p],
            labels=[l for l in entry.get("labels", []) if l],
            icon_phashes=hashes,
            cert_sha256=[c.lower() for c in entry.get("cert_sha256", []) if c],
            verified=bool(entry.get("verified", False)),
        ))
    return brands


# ── the four checks ───────────────────────────────────────────────────────────

def _check_certificate(brand: Brand, package: str, cert_sha256: Optional[str]
                       ) -> Optional[ImpersonationFinding]:
    """
    Exact package match signed by a key the brand does not use.

    Deliberately requires an EXACT package match. A near-miss package signed by an
    unknown key is a typosquat, which check 3 already reports with its own wording —
    calling it a certificate mismatch would overstate it, because a different app is
    entitled to a different key.
    """
    if package not in brand.packages:
        return None
    if not brand.cert_sha256 or not cert_sha256:
        return None
    if cert_sha256.lower() in brand.cert_sha256:
        return None
    return ImpersonationFinding(
        kind="certificate_mismatch",
        brand=brand.name,
        severity=SEVERITY["certificate_mismatch"],
        detail=(
            f"declares the package name of {brand.name} but is signed by a key that "
            f"publisher does not use. Android identifies a publisher by signing key, "
            f"so this APK cannot be an update to the real app — it is a separate app "
            f"wearing its package name."
        ),
        observed=cert_sha256.lower(),
        expected=" | ".join(brand.cert_sha256),
    )


def _check_icon(brand: Brand, package: str, icon_phash: Optional[int]
                ) -> Optional[ImpersonationFinding]:
    if not brand.icon_phashes or icon_phash is None:
        return None
    if package in brand.packages:
        return None  # the real app is allowed to use its own icon
    nearest = brand.closest_icon(icon_phash)
    if nearest is None:
        return None
    distance, matched = nearest
    if distance > ICON_MATCH_MAX_DISTANCE:
        return None
    return ImpersonationFinding(
        kind="icon_reuse",
        brand=brand.name,
        severity=SEVERITY["icon_reuse"],
        detail=(
            f"launcher icon is perceptually {brand.name}'s icon (Hamming distance "
            f"{distance} of 64, threshold {ICON_MATCH_MAX_DISTANCE}) on a package that "
            f"is not {brand.name}'s. On the home screen this is indistinguishable from "
            f"the real app."
        ),
        observed=f"{icon_phash:016x} ({package})",
        expected=f"{matched:016x} ({', '.join(brand.packages) or 'n/a'})",
    )


def _check_package(brand: Brand, package: str) -> Optional[ImpersonationFinding]:
    if not package or package in brand.packages:
        return None
    observed = normalize_confusables(package)

    # A package that is a protected package plus a suffix — org.telegram.messenger.wgstjg
    # — is checked before the typosquat loop below, because the typosquat check cannot
    # see it: appending ".wgstjg" is an edit distance of 7 against a threshold of 2.
    # Measured on the malware corpus: three samples wear exactly this shape and none of
    # the four checks fired on any of them.
    #
    # It is treated as at least as strong as a typosquat rather than weaker. A typo is
    # something a careless developer could produce by accident; a package that reproduces
    # a brand's namespace in full and then appends random characters is not reachable by
    # accident. Android still resolves it as an unrelated app, so the store listing and
    # the signing key are somebody else's.
    #
    # The brand's own extended builds must be listed in `packages` to stay exempt — the
    # guard above is what makes org.telegram.messenger.beta not a finding.
    #
    # Compared raw rather than confusable-normalised, because normalisation strips the
    # dots and the dot is the whole point: it is what marks the namespace boundary
    # between "the brand's package, extended" and "a longer string that merely starts
    # with the same letters". Nothing is lost by skipping normalisation here — Android
    # package names are Java identifiers, so they cannot contain a confusable to begin
    # with, and the typosquat loop below still covers homoglyph substitution.
    for original in brand.packages:
        if original and package.startswith(original + "."):
            return ImpersonationFinding(
                kind="package_namespace_squat",
                brand=brand.name,
                severity=SEVERITY["package_namespace_squat"],
                detail=(
                    f"package name is {original} with '.{package[len(original) + 1:]}' "
                    f"appended. That reproduces {brand.name}'s namespace exactly and then "
                    f"extends it, which Android resolves as a different app entirely — "
                    f"the listing and the signing key belong to somebody else."
                ),
                observed=package,
                expected=original,
            )

    for reference, original in zip(brand.normalized_packages, brand.packages):
        if not reference:
            continue
        distance = edit_distance(observed, reference, PACKAGE_MAX_EDIT_DISTANCE)
        if distance == 0:
            detail = (
                f"package name is not {original} but normalises to it — the difference "
                f"is confusable characters only, which render identically at a glance."
            )
        elif distance <= PACKAGE_MAX_EDIT_DISTANCE:
            detail = (
                f"package name is {distance} character(s) from {original} after "
                f"confusable normalisation — the shape of a typosquat."
            )
        else:
            continue
        return ImpersonationFinding(
            kind="package_typosquat",
            brand=brand.name,
            severity=SEVERITY["package_typosquat"],
            detail=detail,
            observed=package,
            expected=original,
        )
    return None


def _check_label(brand: Brand, package: str, label: Optional[str]
                 ) -> Optional[ImpersonationFinding]:
    if not label or package in brand.packages:
        return None
    observed = normalize_confusables(label)
    if not observed:
        return None
    for reference, original in zip((normalize_confusables(l) for l in brand.labels),
                                   brand.labels):
        if not reference:
            continue
        if observed == reference:
            detail = (f"displays the name {original} on a package that is not "
                      f"{brand.name}'s. This is the name the victim reads.")
        elif (len(reference) >= MIN_LABEL_LEN_FOR_FUZZY
              and edit_distance(observed, reference, LABEL_MAX_EDIT_DISTANCE)
              <= LABEL_MAX_EDIT_DISTANCE):
            detail = (f"display name is a near-miss of {original} on a package that "
                      f"is not {brand.name}'s.")
        else:
            continue
        return ImpersonationFinding(
            kind="label_impersonation",
            brand=brand.name,
            severity=SEVERITY["label_impersonation"],
            detail=detail,
            observed=label,
            expected=original,
        )
    return None


def _check_package_identity_live(
    package: str, label: Optional[str]
) -> Optional[ImpersonationFinding]:
    """
    Live counterpart to certificate_mismatch, for packages not in the static
    table at all. If this exact package name is a real Play listing but the
    APK's declared display name doesn't plausibly match what Play says the
    app is actually called, something is wrong — either the manifest label
    is bogus, or this is a package-name-reuse situation. Weaker than a
    certificate check on purpose: Play does not expose another app's signing
    key publicly, so this is what live verification can do instead.
    """
    if not package or not label:
        return None
    listing, status = brand_lookup.fetch_play_listing(package)
    if status != "found" or listing is None:
        return None
    if brand_lookup.labels_plausibly_match(label, listing.title):
        return None
    return ImpersonationFinding(
        kind="package_identity_mismatch_live",
        brand=listing.title,
        severity=SEVERITY["package_identity_mismatch_live"],
        detail=(
            f"package name {package} is a real Play Store listing titled "
            f"{listing.title!r}, but this APK declares the display name "
            f"{label!r} instead. Live Play Store lookup, not the static "
            f"brand table."
        ),
        observed=label,
        expected=listing.title,
    )


def _check_label_live(package: str, label: Optional[str]) -> Optional[ImpersonationFinding]:
    """
    Live counterpart to label_impersonation, for brands not in the static
    table at all. Searches Play for real apps sharing this APK's declared
    display name; if a close title match turns up under a DIFFERENT
    package, this APK is very likely wearing someone else's name — Play's
    own search ranking having surfaced that other app as the real one for
    this name is the evidence, not a hand-curated reference entry.
    """
    if not package or not label:
        return None
    results, status = brand_lookup.search_play_by_title(label)
    if status != "ok":
        return None
    for candidate in results:
        if candidate.package_name == package:
            continue  # this IS the real app for this name — nothing to report
        if not brand_lookup.labels_plausibly_match(label, candidate.title):
            continue
        return ImpersonationFinding(
            kind="label_impersonation_live",
            brand=candidate.title,
            severity=SEVERITY["label_impersonation_live"],
            detail=(
                f"displays the name {label!r}, which a live Play Store search "
                f"finds as the real title of {candidate.package_name} — a "
                f"different package than this APK's. Live search match, not "
                f"the static brand table."
            ),
            observed=f"{label} ({package})",
            expected=f"{candidate.title} ({candidate.package_name})",
        )
    return None


def _check_generic_bait_label(label: Optional[str]) -> Optional[ImpersonationFinding]:
    """
    See the GENERIC_BAIT_LABELS docstring above — a different question from
    every other check in this module (generic disguise vocabulary, not a
    specific stolen identity), scored and floored accordingly.

    Substring match, not exact — real bait labels routinely carry a tagline or
    year appended ("Speed Post - Track Your Parcel", "Income Tax Refund 2026"),
    the same real-world pattern already handled for Play listing titles in
    brand_lookup.labels_plausibly_match.
    """
    if not label:
        return None
    normalized = " ".join(label.strip().lower().split())
    if not normalized:
        return None
    matched = next((phrase for phrase in GENERIC_BAIT_LABELS if phrase in normalized), None)
    if matched is None:
        return None
    return ImpersonationFinding(
        kind="generic_bait_label",
        brand="(no specific brand — generic disguise label)",
        severity=SEVERITY["generic_bait_label"],
        detail=(
            f"display name {label!r} contains {matched!r}, drawn from a "
            f"vocabulary of generic, trust-inspiring labels repeatedly "
            f"documented as installer-stage social-engineering bait for "
            f"Android RATs/spyware. Not evidence of impersonating a specific "
            f"brand — a legitimate niche app can share this wording "
            f"coincidentally. Advisory only; contributes no verdict floor."
        ),
        observed=label,
        expected="(a specific legitimate app's real name, or an unrelated label)",
    )


def detect_impersonation(
    package_name: Optional[str],
    app_label: Optional[str] = None,
    cert_sha256: Optional[str] = None,
    icon_phash: Optional[int] = None,
    brands: Optional[Iterable[Brand]] = None,
) -> ImpersonationResult:
    """
    Runs the four static-table checks against every protected brand, then — only if
    none of them fired — a live Play Store check (see module docstring).

    At most one static finding per (brand, kind) — the checks are ordered by strength
    inside each brand, and a certificate mismatch already implies the package matched,
    so reporting a typosquat for the same brand would be double-counting the same fact.
    """
    reference = list(brands) if brands is not None else load_reference()
    result = ImpersonationResult(brands_checked=len(reference))

    package = (package_name or "").strip()

    if not reference:
        result.coverage.append(
            "no protected-brand reference table loaded — static-table impersonation "
            "checks were not assessed; the live Play Store check ran independently, "
            "if enabled"
        )
    else:
        if not package:
            result.coverage.append(
                "package name unavailable (unparsed or corrupted manifest) — package "
                "and certificate checks could not run"
            )
        if icon_phash is None:
            result.coverage.append(
                "launcher icon not recovered as a raster image — icon comparison did "
                "not run"
            )
        if not cert_sha256:
            result.coverage.append(
                "signing certificate unavailable — certificate comparison did not run"
            )

        with_cert = sum(1 for b in reference if b.cert_sha256)
        with_icon = sum(1 for b in reference if b.icon_phashes)
        if with_cert < len(reference):
            result.coverage.append(
                f"{len(reference) - with_cert} of {len(reference)} reference brands "
                "carry no signing certificate — a clone of those cannot be caught by "
                "certificate mismatch"
            )
        if with_icon < len(reference):
            result.coverage.append(
                f"{len(reference) - with_icon} of {len(reference)} reference brands "
                "carry no icon hash — a clone of those cannot be caught by icon reuse"
            )

        # Which brand, if any, genuinely owns this package. Each check already exempts
        # the brand it is comparing against, but that is per-brand and the name-based
        # checks are cross-brand: two protected brands can have similar names, and then
        # each one's real app reads as impersonating the other. Observed as soon as
        # Bank of India was added — "BOI Mobile" is an edit distance of 2 from ICICI's
        # "iMobile", so the genuine BOI APK was reported as impersonating ICICI.
        #
        # A package listed in the reference table is a known-genuine app by definition,
        # so the NAME-based checks are silenced for it. The evidence-based ones are
        # not: a certificate mismatch or a reused icon on a genuine package is exactly
        # the clone this module exists to catch, and neither can be produced by two
        # brands merely having similar names.
        owner = next((b for b in reference if package and package in b.packages), None)

        # Evidence-based checks run for every brand, unconditionally.
        evidence = [
            _check_certificate(brand, package, cert_sha256)
            or _check_icon(brand, package, icon_phash)
            for brand in reference
        ]

        # ...and if one of them contradicts the owner — a wrong signing key or a
        # reused icon on the package it claims — then the package is NOT that brand's
        # app after all, so nothing is silenced. An APK wearing Paytm's package,
        # signed by somebody else and displaying "PhonePe", must still report the
        # PhonePe label finding.
        owner_disproven = owner is not None and evidence[reference.index(owner)] is not None

        for brand, evidence_finding in zip(reference, evidence):
            finding = evidence_finding
            if finding is None and (owner is None or owner_disproven or owner is brand):
                finding = _check_package(brand, package) or _check_label(
                    brand, package, app_label
                )
            if finding:
                result.findings.append(finding)

    result.findings.sort(key=lambda f: -f.severity)

    # Live Play Store check — a fifth, independent signal (see module docstring).
    # Only attempted when the static table found nothing for this APK, mirroring the
    # local-first-then-online pattern in app/analysis/signatures.py: a known clone
    # never needs a network round trip to be confirmed twice, and a package already
    # vouched for by its own entry in `reference` is not re-verified live either.
    already_known_genuine = package and any(package in b.packages for b in reference)
    if not settings.brand_live_lookup_enabled:
        result.coverage.append(
            "live Play Store lookup disabled (brand_live_lookup_enabled=false)"
        )
    elif result.findings or already_known_genuine:
        pass
    else:
        try:
            live_finding = _check_package_identity_live(
                package, app_label
            ) or _check_label_live(package, app_label)
        except Exception as exc:
            logger.warning(f"[impersonation] live Play Store lookup failed: {exc}")
            live_finding = None
            result.coverage.append(f"live Play Store lookup failed: {exc}")
        if live_finding:
            result.findings.append(live_finding)

    # Sixth, unconditional check (see GENERIC_BAIT_LABELS) — orthogonal to
    # everything above, offline, and cheap enough to always run regardless of
    # whether a static/live brand finding already fired.
    bait_finding = _check_generic_bait_label(app_label)
    if bait_finding:
        result.findings.append(bait_finding)

    result.findings.sort(key=lambda f: -f.severity)
    return result


# Entry names that hold a launcher icon in a normally-built APK. Used only by the
# container fallback below, where androguard's resource resolution is unavailable.
_LAUNCHER_ICON_HINTS = ("ic_launcher", "mipmap", "app_icon", "ic_app")
_RASTER_SUFFIXES = (".png", ".webp", ".jpg", ".jpeg")


def extract_icon_phash_from_container(container) -> Optional[int]:
    """
    Recover a launcher-icon hash straight from the archive when resource
    resolution cannot run.

    Needed because the resolution path depends on a parsed manifest and a
    readable `resources.arsc`, and an APK that poisons its entry names has
    neither — sample 4 of the Bank of India set keeps its 432x432 launcher icon
    at `res/values/colors.xml///.webp`, which no resource lookup will ever
    return, so the icon check was skipped on the one sample in the set that
    ships 22 image assets byte-identical to the genuine bank app's.

    Picks the largest raster entry whose path still looks like a launcher icon,
    because the highest-density copy is the one closest to the artwork a brand
    reference was built from. Returns None when nothing qualifies — a coverage
    gap, reported as one, never a match.
    """
    if container is None:
        return None

    candidates = []
    for entry in container.entries():
        lower = entry.name.lower().replace("\\", "/")
        if not lower.endswith(_RASTER_SUFFIXES):
            continue
        if not any(hint in lower for hint in _LAUNCHER_ICON_HINTS):
            continue
        candidates.append(entry)

    if not candidates:
        # Nothing named like an icon survived the renaming. Fall back to the
        # largest raster in res/ — on a poisoned archive that is where the
        # adaptive-icon foreground ends up, and a wrong guess costs nothing: it
        # either matches a protected brand's artwork or it does not.
        candidates = [
            e for e in container.entries()
            if e.name.lower().endswith(_RASTER_SUFFIXES)
            and e.name.lower().replace("\\", "/").startswith("res/")
        ]
    if not candidates:
        return None

    for entry in sorted(candidates, key=lambda e: -e.file_size)[:5]:
        data = container.read_entry(entry, max_bytes=8 * 1024 * 1024)
        if not data:
            continue
        phash = perceptual_hash(data)
        if phash is not None:
            logger.debug(
                f"[impersonation] launcher icon recovered from container entry "
                f"{entry.name!r} ({entry.file_size} bytes)."
            )
            return phash
    return None


def extract_icon_phash(apk_obj) -> Optional[int]:
    """
    pHash of the APK's launcher icon, or None when there isn't a raster one.

    Modern APKs frequently ship an adaptive icon — an XML document referencing
    foreground and background drawables — which has no pixels to hash. That is a real
    coverage gap and is reported as one rather than being silently treated as "no match".
    """
    try:
        icon_path = apk_obj.get_app_icon()
        if not icon_path:
            return None
        data = apk_obj.get_file(icon_path)
    except Exception as exc:
        logger.debug(f"[impersonation] could not read launcher icon: {exc}")
        return None
    if not data:
        return None
    return perceptual_hash(data)
