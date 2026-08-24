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
    icon_phash: Optional[int]
    cert_sha256: list[str]
    verified: bool

    @property
    def normalized_packages(self) -> list[str]:
        return [normalize_confusables(p) for p in self.packages]


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
        phash = entry.get("icon_phash")
        brands.append(Brand(
            name=entry.get("brand", "?"),
            category=entry.get("category", "unknown"),
            packages=[p for p in entry.get("packages", []) if p],
            labels=[l for l in entry.get("labels", []) if l],
            icon_phash=int(phash, 16) if isinstance(phash, str) else phash,
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
    if brand.icon_phash is None or icon_phash is None:
        return None
    if package in brand.packages:
        return None  # the real app is allowed to use its own icon
    distance = hamming_distance(icon_phash, brand.icon_phash)
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
        expected=f"{brand.icon_phash:016x} ({', '.join(brand.packages) or 'n/a'})",
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


def detect_impersonation(
    package_name: Optional[str],
    app_label: Optional[str] = None,
    cert_sha256: Optional[str] = None,
    icon_phash: Optional[int] = None,
    brands: Optional[Iterable[Brand]] = None,
) -> ImpersonationResult:
    """
    Runs all four checks against every protected brand.

    At most one finding per (brand, kind) — the checks are ordered by strength inside
    each brand, and a certificate mismatch already implies the package matched, so
    reporting a typosquat for the same brand would be double-counting the same fact.
    """
    reference = list(brands) if brands is not None else load_reference()
    result = ImpersonationResult(brands_checked=len(reference))

    if not reference:
        result.coverage.append(
            "no protected-brand reference table loaded — impersonation was not assessed"
        )
        return result

    package = (package_name or "").strip()
    if not package:
        result.coverage.append(
            "package name unavailable (unparsed or corrupted manifest) — package and "
            "certificate checks could not run"
        )
    if icon_phash is None:
        result.coverage.append(
            "launcher icon not recovered as a raster image — icon comparison did not run"
        )
    if not cert_sha256:
        result.coverage.append(
            "signing certificate unavailable — certificate comparison did not run"
        )

    with_cert = sum(1 for b in reference if b.cert_sha256)
    with_icon = sum(1 for b in reference if b.icon_phash is not None)
    if with_cert < len(reference):
        result.coverage.append(
            f"{len(reference) - with_cert} of {len(reference)} reference brands carry no "
            "signing certificate — a clone of those cannot be caught by certificate mismatch"
        )
    if with_icon < len(reference):
        result.coverage.append(
            f"{len(reference) - with_icon} of {len(reference)} reference brands carry no "
            "icon hash — a clone of those cannot be caught by icon reuse"
        )

    # Which brand, if any, genuinely owns this package. Each check already exempts the
    # brand it is comparing against, but that is per-brand and the name-based checks are
    # cross-brand: two protected brands can have similar names, and then each one's real
    # app reads as impersonating the other. Observed as soon as Bank of India was added —
    # "BOI Mobile" is an edit distance of 2 from ICICI's "iMobile", so the genuine BOI
    # APK was reported as impersonating ICICI.
    #
    # A package listed in the reference table is a known-genuine app by definition, so
    # the NAME-based checks are silenced for it. The evidence-based ones are not: a
    # certificate mismatch or a reused icon on a genuine package is exactly the clone
    # this module exists to catch, and neither can be produced by two brands merely
    # having similar names.
    owner = next((b for b in reference if package and package in b.packages), None)

    # Evidence-based checks run for every brand, unconditionally.
    evidence = [
        _check_certificate(brand, package, cert_sha256)
        or _check_icon(brand, package, icon_phash)
        for brand in reference
    ]

    # ...and if one of them contradicts the owner — a wrong signing key or a reused
    # icon on the package it claims — then the package is NOT that brand's app after
    # all, so nothing is silenced. An APK wearing Paytm's package, signed by somebody
    # else and displaying "PhonePe", must still report the PhonePe label finding.
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
    return result


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
