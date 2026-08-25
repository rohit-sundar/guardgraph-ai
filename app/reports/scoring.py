"""
Deterministic risk score, 0-100, per the design doc's weighted formula.

Original formula (paper spec):
    0.30 * classifier_probability
  + 0.20 * permission_api_risk
  + 0.20 * ttp_severity
  + 0.15 * graph_obfuscation_score
  + 0.10 * reputation_score
  + 0.05 * ioc_score

Revised formula (§9.3 fix — forensic anchors added as first-class component):
    0.25 * classifier_confidence
  + 0.20 * permission_api_risk
  + 0.15 * ttp_severity
  + 0.15 * forensic_anchor          ← NEW: deterministic behavioral evidence
  + 0.15 * obfuscation / coverage
  + 0.05 * reputation
  + 0.05 * ioc

Rationale for rebalancing: GUARD paper SHAP analysis (§10.1) found that
deterministic behavioral flags are the strongest predictors in a structurally
comparable system — weighted at least as heavily as classifier confidence.
Classifier weight reduced from 0.30→0.25 to make room; ttp_severity reduced
from 0.20→0.15 (it was already dead-weight before the FAMILY_TO_TTPS fix);
obfuscation raised from 0.15→0.15 (unchanged); reputation reduced 0.10→0.05.

Every component function below is a real, if simple, calculation — not a
placeholder returning a constant. Tune the internals as you validate
against your demo set, but the formula weights themselves shouldn't drift
without a documented reason.
"""
import math

from app.core.config import TTP_SEVERITY_WEIGHTS, TACTIC_SEVERITY
from app.core.schemas import RiskScoreBreakdown, ObfuscationSignal
from app.ml.labels import TECHNIQUE_TACTIC

# Zero-day indicator thresholds (§zero-day): strong deterministic/structural evidence
# while model familiarity is low ⇒ flag as a possible novel/first-seen variant.
ZERO_DAY_ANCHOR_MIN = 0.5   # forensic_anchor_component (0-1) at/above this = strong proven evidence
ZERO_DAY_OBF_MIN = 0.5      # obfuscation_component (0-1) at/above this = strong evasion/coverage signal
ZERO_DAY_CONF_MAX = 0.4     # classifier_confidence_component (0-1) below this = weak model familiarity

# ── Calibration constants (N6-N8) ─────────────────────────────────────────────
# Every number in this block was picked by measuring the corpus, not by intuition.
# Re-derive them with `python scripts/score_corpus.py` after any change to the
# analysis stages; the script prints the same tables the values below were chosen
# from.
#
# Re-measured 2026-08-24 against the rebuilt corpus: **633 rows, 299 F-Droid
# benign / 334 MalwareBazaar malware across 21 families** (was 618 = 300/318, and
# 353 = 220/133 before that). Reproduce with
# `python scripts/score_corpus.py --out data/corpus_scores_v3.json`.
# The benign side is two disjoint seeded selections — apps under 12 MB plus a set
# between 12 and 60 MB — because the original <=12 MB cap is why the clean corpus
# was all small utilities. A further 30 large apps are held out of training
# entirely (data/benign_holdout) and are what distinguishes a real boundary from
# one fitted to the corpus.
#
# The malware side is 334, not 344: ten APKs on disk are permanently unparseable
# (six truncated DEX, two corrupt ZIP EOCD, two that surface as a TypeError deeper
# in the parse). Confirmed 2026-08-24 from two independent directions — they are
# exactly the ten with no row in data/ttp_dataset.csv, and exactly the ten the
# corpus scorer fails on. 334 is the ceiling, not a sampling choice.
#
# **These boundaries were derived with online reputation DISABLED**
# (settings.online_lookups_enabled = False), so `signature_match_count` is 0 and
# `is_known_malware` is False for every sample — re-verified on this corpus: max
# signature_matches across all 633 scored samples was 0, and the reputation
# component took exactly one distinct value (1.5 = the 0.3 unknown-sample prior
# x its 5.0 cap) for every sample in the run. That makes them conservative rather than
# optimistic: VirusTotal only returns a verdict when malicious > 0, so enabling
# reputation can push malware totals up and never benign ones. It also makes the
# run deterministic, which the two-run variance noted in earlier revisions of this
# block was not.

# classifier_confidence_component (N8). Fallback decision boundary for a technique
# the trained bundle carries no calibrated threshold for — matches
# pipeline.TTP_PREDICT_THRESHOLD, which decides what reaches this function.
DEFAULT_TTP_THRESHOLD = 0.5
# Summed threshold margin at which confidence reaches 1 - 1/e ≈ 0.63. Re-counted
# over the 618-row corpus: malware predicts a median of 7 techniques (mass well
# past this), while the clean median is 0 — most clean apps predict nothing at all.
# The separation this constant assumes is intact, so it is unchanged.
CONFIDENCE_SATURATION_MASS = 2.5

# ttp_severity_component / forensic_anchor_component (N9). Both used to return the
# *mean* severity of what was found, which made every component non-monotonic in
# evidence: each additional corroborating technique or behavior pulled the average
# down. Measured over the 364-row dataset (220 benign / 144 malware) by running the
# trained BR bundle over the stored feature vectors — reproduce with
# `python scripts/measure_saturation.py`:
#
#   ttp_severity (mean)      benign p95 0.006  max 0.941 | malware p50 0.727 max 0.810
#                            ^ the highest-scoring sample in the corpus was BENIGN,
#                              because one severe technique averages to its own
#                              severity while eight techniques average to the middle.
#   forensic_anchor (mean)   benign p50 0.600  p95 0.800 | malware p25 0.550 p50 0.767
#                            ^ separation (malware p50 - benign p95) = -0.033. The
#                              component discriminated BACKWARDS: a clean app matching
#                              one DYNAMIC_REFLECTION anchor scored 0.600, while
#                              malware matching {CRYPTOGRAPHY, REFLECTION, C2} averaged
#                              0.583 — the mean penalised malware for also doing the
#                              benign things.
#
# Both now sum severity into an evidence mass and squash it, the same shape
# classifier_confidence_component uses. The two constants are NOT shared, because
# the two masses live on different scales (malware median mass 5.905 for techniques
# against 1.700 for anchors).
#
# TTP: chosen so the malware median is unchanged (0.727 -> 0.731), which keeps the
# existing verdict bands valid, while the benign outlier collapses 0.941 -> 0.381.
TTP_SEVERITY_SATURATION_MASS = 4.5
# Anchors: chosen for maximum separation across the candidates measured (1.5-4.0);
# at 1.5 the sign flips positive (+0.046) and benign p50 halves (0.600 -> 0.330)
# while malware p50 moves only 0.767 -> 0.678. Both corpora move DOWN, benign
# roughly three times as far as malware — the conservative direction for bands that
# were derived as "above where clean apps top out".
ANCHOR_SATURATION_MASS = 1.5

# obfuscation_component (N7). Measured over the corpus, all four original inputs
# were useless: string-pool entropy tops out at 3.47 against a 7.2 threshold and runs
# the wrong way (benign 3.28 vs malware 2.78); `flattening_suspected` is an
# existential over every analysed method and fired on 30/30 sampled clean apps;
# `unresolved_reflection_targets` was a documented stub pinned at 0 WHEN N7 RAN --
# it has since been implemented, which is exactly how its 0.10 weight came to fire
# on 88% of clean apps unnoticed (see UNRESOLVED_REFLECTION_WEIGHT);
# `method_parse_failure_rate` was 0.0 on all 353 then, and on all 616 now. So the
# component was a constant
# 6.00/15 for 216 of 220 clean apps and 108 of 133 malware — 39.3% of cap for benign
# against 32.5% for malware, an inverted constant.
#
# Reading flattening as a prevalence instead does not rescue it: over the full corpus
# the share of analysed methods that look flattened is benign p75 0.119 against
# malware p75 0.118, and every candidate threshold from 0.05 to 0.50 gives a lift
# between 0.79 and 1.07. It is measured and reported, and it is not scored.
#
# What is left is the thing the component exists for: evidence that the analyser was
# denied the code.
CODE_NOT_RECOVERED_WEIGHT = 0.60
# An Android class that exists at all costs a constructor and at least one lifecycle
# override, so a manifest declaring N components needs on the order of 2N methods
# before anything else. Below that the recovered DEX cannot be the app the manifest
# describes — a loader stub whose payload is decrypted at runtime. Re-measured over
# 299 clean apps (2026-08-21), the lowest ratio is still 56.85 dex methods per
# declared component — the identical app and ratio as the 219-app corpus — leaving
# 28.4x of margin above this floor; on the malware side 37 of 318 samples fall
# below it, one declaring 539 activities, 42 services and 49 receivers with 57
# methods in its DEX.
MIN_METHODS_PER_DECLARED_COMPONENT = 2.0
# Measured and reported, NOT scored — the same verdict N7 reached for string
# entropy and flattening prevalence, for the same reason.
#
# This weight was calibrated while `unresolved_reflection_targets` was a stub that
# always returned 0, and the branch was, in the original comment's words, "wired so
# that implementing the taint pass turns it on rather than requiring a second change
# here". tests/test_reflection_resolution.py then replaced that stub with a real
# resolver — and the weight silently armed itself with nobody re-measuring it.
#
# Measured over the 2026-08-25 corpus run (631 scored), the obfuscation component
# took exactly these values:
#
#            0.00      1.50      9.00     10.50
#   benign   11.8%     88.2%        0%        0%
#   malware   6.6%     76.9%     11.4%      5.1%
#
# 1.50 is this term firing alone, and it fires on 88.2% of CLEAN apps against 76.9%
# of malware — a near-constant pointing the wrong way, which is precisely what N7
# deleted three other inputs for. Every bit of real signal in this component lives
# in the 9.00/10.50 rows, which are CODE_NOT_RECOVERED_WEIGHT and are malware-only.
#
# Unresolved reflection is genuinely useful to an ANALYST — "12 reflection call
# targets not statically resolved" tells them how much of the app was opaque — so
# it stays on ObfuscationSignal and stays in the coverage note. It just does not
# move the score. The constant is kept (not deleted) so this reasoning has somewhere
# to live and the next person does not re-add the branch.
UNRESOLVED_REFLECTION_WEIGHT = 0.10
# Same magnitude as CODE_NOT_RECOVERED_WEIGHT — both represent the analyser
# being structurally denied the evidence it needs, not a measured prevalence
# like entropy/flattening. A corrupted manifest has no benign explanation (no
# build tool produces one), so unlike those two this doesn't need corpus
# measurement to justify scoring it — see obfuscation_component's docstring.
MANIFEST_CORRUPTED_WEIGHT = 0.60
# Total method-parse failure: the analyser recovered ZERO control-flow graphs from
# a DEX too small to be a real app. Both halves are required, and the second half is
# what keeps this honest — `analyzed_method_count == 0` ALONE is not evasion. It is
# also what a small clean app looks like when cfg.py's relevance pre-filter finds
# nothing touching the forensic dictionary, which ObfuscationSignal.dex_method_count
# documents and test_relevance_filter_selecting_nothing_is_not_evasion pins.
#
# Measured 2026-08-25 over a full corpus run on current code (631 scored), of the
# rows with no recovered CFGs at all:
#
#   benign    2 / 297  dex_method_count 117, 1444
#   malware   2 / 334  dex_method_count 20, 61
#
# Those ranges do not overlap — malware tops out at 61 methods, the lowest clean
# app is 117 — so OPAQUE_DEX_MAX_METHODS sits in measured empty space, on the same
# principle as BAND_MEDIUM_CEILING and not fitted to either side.
#
# **This population used to be 20x larger, and shrank for a good reason.** On the
# 2026-08-24 corpus (data/corpus_scores_v3.json) it was 39 malware and 3 benign,
# with the gap at 87→117. Commit 323dd2c then added Cipher.getInstance /
# SecretKeySpec.<init> / IvParameterSpec.<init> / System.loadLibrary to the API set
# that selects methods for CFG construction, and 37 of those 39 malware went from
# 0 recovered CFGs to 1 — enough to satisfy has_deterministic_evidence and un-gate
# classifier_confidence + ttp_severity. 02c08ec2… (41/77 VirusTotal engines
# malicious, 59 DEX methods), the sample that opened this whole issue at 22.63
# `low`, scores 47.88 `suspicious` on current code from that change alone, before
# anything here applies.
#
# So this weight is NOT what fixed that sample, and should not be credited with it.
# What it does is close the structural hole underneath: zero recovered CFGs means
# the three code-derived components (classifier_confidence 25, ttp_severity 15,
# forensic_anchor 15) all read 0 together, so 55 of 100 points are unreachable and
# the component that exists to measure evasion was reading 0.0 on exactly the
# samples that defeated the analyser. Widening the CFG dictionary shrank that
# population; it cannot guarantee the next packer leaves a recognised API behind.
#
# 0.60 is the same magnitude as CODE_NOT_RECOVERED_WEIGHT and
# MANIFEST_CORRUPTED_WEIGHT — all three say "the analyser was denied the code", and
# none should outrank the others. Chosen for that consistency, not fitted to a
# sample. Measured effect on the 2026-08-25 corpus run: it fires on 2 malware and
# 0 benign, moving one malware sample `low` -> `medium` and changing nothing else.
# Every benign band count is byte-identical before and after.
TOTAL_METHOD_PARSE_FAILURE_WEIGHT = 0.60
# The upper edge of "too small to be a real app", placed in the measured 87-to-117
# gap above. A DEX larger than this with no analysed methods is the pre-filter
# finding nothing interesting, which is not evidence of anything.
#
# **The gap does not fully generalize, same caveat as BAND_MEDIUM_CEILING.** On the
# 30 never-trained holdout apps, 1 falls inside it: player.efis.data.ant.spl, 60
# methods and no recovered CFGs — a data-only package that declares no permissions
# at all. It is charged this weight and moves 2.12 -> 11.12, still `low` with 18.9
# points of headroom. Reported rather than designed away, because widening the
# boundary to exclude it would fit it to the holdout and destroy the only
# independent check these constants have.
#
# That case is also why this weight is safe on its own: a clean app in this state
# has nothing ELSE firing, so 9 points cannot carry it anywhere. The signal only
# changes a verdict when it corroborates other evidence — which is exactly what a
# coverage-gap signal should do, and why the band-changing work is done by
# OPAQUE_REPUTATION_SCORE_FLOOR, which additionally requires an external hash hit
# no clean app receives.
OPAQUE_DEX_MAX_METHODS = 100

# ioc_component (N6). The old tiers let three weak signals saturate the cap: a
# YARA term of severity * 0.3 * min(n, 3) paid 0.765 to any app matching three
# rules at severity 0.85, and clean apps match a mean of 10.8 community rules at
# exactly that severity (re-measured over 300 clean apps: 14.03 rules at mean max
# severity 0.84 — the breadth grew, which is exactly why it must not multiply). Rule-declared severity is author metadata, not a measure of
# specificity, so YARA breadth no longer multiplies. Evidence is split: signals that
# identify *this* sample can reach the cap alone; ubiquitous ones share a small
# allowance and can never carry a verdict by themselves.
IOC_SIGNATURE_WEIGHT = 0.50         # per hash/cert signature hit
IOC_EXTRACTED_C2_WEIGHT = 0.35      # per exact extracted IoC (bot token, .onion, …)
IOC_EXTRACTED_C2_CAP = 0.70
IOC_SECONDARY_DEX_WEIGHT = 0.20     # per hidden/secondary DEX payload
IOC_SECONDARY_DEX_CAP = 0.40
IOC_YARA_WEIGHT = 0.25              # * max rule severity, no count multiplier
IOC_CERT_ANOMALY_WEIGHT = 0.10
IOC_DROPPER_WEIGHT = 0.10
IOC_FORENSIC_C2_WEIGHT = 0.10
IOC_CIRCUMSTANTIAL_CAP = 0.35       # joint ceiling on the four weak terms above

# ── Verdict band boundaries ───────────────────────────────────────────────────
# Each boundary answers a different question, so each is set by its own criterion
# rather than by cutting 0-100 into four. Measured *after* the N5-N8 component fixes,
# over two full corpus runs; reproduce with `python scripts/score_corpus.py`.
#
# Measured 2026-08-24 with online lookups disabled, so the run is deterministic —
# earlier revisions of this block quoted a range across two runs because live
# VirusTotal/MalwareBazaar answers moved malware totals by about four points a day.
# That variance is gone, not averaged over.
#
#   clean corpus:   median 10.83, p95 26.00, max 71.54      (299 apps scored)
#   malware corpus: p25 57.44, median 67.81, max 76.50      (334 samples)
#   holdout:        median 11.71, p95 41.75, max 43.37      (30 apps, never trained on)
#
# The holdout is the check that matters, and it is the reason the three boundaries
# below did not move even though the corpus did: holdout median 11.71 against the full
# clean corpus's 10.83, p75 19.36 against 17.01. The never-trained apps sit marginally
# HIGHER than the trained ones, which is the direction that cannot flatter the
# boundaries.
#
# The holdout is used to VALIDATE these boundaries, never to set them. Refitting to it
# would leave no independent check at all, so where it disagrees with the training
# corpus (see BAND_MEDIUM_CEILING) the disagreement is reported, not designed away.
#
# `low` — "costs no analyst time". Above the clean corpus's 95th percentile (26.00),
# leaving 291 of 299 clean apps here, and 27 of the 30 never-trained holdout apps.
# Malware lands here too (43 of 334); every one of those recovered no forensic evidence
# at all, which is a limit on analysis depth that no boundary can move.
BAND_LOW_CEILING = 30.0
# `medium` — the clean apps that clear `low` are not spread evenly through the old
# `suspicious` range: the 7 above 30 top out at 37.05, and the lowest malware score
# above that is 40.28 — an empty 3.23-point gap with nothing in it, benign or malware.
# BAND_MEDIUM_CEILING sits in that gap. This exists to stop labelling that clean-app
# tail `suspicious`, which was overstating it — an analyst-trust fix, not a new
# detection boundary: 2 malware samples fall in this band alongside the 7 benign ones,
# so `medium` reads as "ambiguous", not "clean".
#
# **Two honest caveats, both new on the 2026-08-24 corpus.**
#
# 1. The gap narrowed from ~5 points to 3.23, and 40.0 now sits only 0.28 below the
#    nearest malware sample (40.28). It is still inside the gap, so it is unchanged,
#    but it no longer has room: a small upward shift in that one sample makes it read
#    `medium`. That is the tolerable direction (`medium` means ambiguous, and the
#    sample is still surfaced), but it is no longer a comfortable margin.
#
# 2. **The gap does not generalize.** It is a property of the 299-app training clean
#    corpus. On the 30 never-trained holdout apps, 2 score ABOVE the 40.28 that defines
#    the gap's upper edge — top.yztz.msggo at 43.37 and org.prauga.messages at 41.75 —
#    so 2 of 30 unseen clean apps read `suspicious`, not `medium`. Both are SMS apps
#    whose permission component is capped at 20.0/20 and which match
#    STEALTH_SMS_INTERCEPTION / OTP_INTERCEPTION, i.e. the same capability overlap
#    documented at BAND_SUSPICIOUS_CEILING below. The boundary is kept at 40.0 anyway,
#    because moving it to swallow those two would be fitting to the holdout and would
#    destroy the only independent check these constants have.
BAND_MEDIUM_CEILING = 40.0
# `suspicious` — the ceiling below which the tool never asserts a verdict. Youden's J
# peaks far lower, at 27.0 (J=0.933); that difference is deliberately spent on almost
# never showing an analyst a clean app marked `high`.
#
# "Almost", as of the 2026-08-24 corpus. The original criterion was "above the highest
# score any clean app reaches", and on the 220-app corpus that was 53.33. Exactly ONE
# app in the clean corpus now exceeds this ceiling, and it is kept as a known exception
# rather than designed around:
#
#   com.jens.automation2         71.54   43 permissions, ACCESSIBILITY_FULL_CONTROL,
#                                        OVERLAY_ATTACK_PATTERN, OVERLAY_BOOT_PERSISTENCE,
#                                        BANKING_TARGET_ENUMERATION, STEALTH_SMS_INTERCEPTION,
#                                        DYNAMIC_CODE_LOADING, 10 predicted techniques
#
# It is clean, and it genuinely holds the capability surface of a banking trojan — a
# Tasker-style automation app really does intercept SMS, read OTPs, draw overlays and
# persist across boot. This is capability overlap, not a scoring defect, and no boundary
# separates it: raising this ceiling above 71.54 would reclassify most of the malware
# corpus as merely `suspicious`. The rest of the clean corpus is nowhere near — the next
# highest score is 37.05, and 298 of 299 clean apps sit at or below it.
#
# **dev.kerballone.spamblocker was the second exception here at 61.90 and no longer is
# — it scores 34.88 on this corpus and reads `medium`.** The exception list went from two
# to one without this boundary being touched. Nothing was done to that app specifically;
# the forensic-dictionary and model changes since 2026-08-21 moved it on their own.
#
# Every clean app that clears `low` on either corpus is an SMS, automation or
# accessibility tool. That is worth stating plainly rather than treating each as a
# one-off: the false-positive tail is not noise, it is a well-defined class whose
# legitimate function IS the banking-trojan capability surface, which is also why a
# bank deploying this would whitelist by publisher certificate rather than by score.
BAND_SUSPICIOUS_CEILING = 60.0
# `high` — the criterion is "placed above every known clean score", so that `malicious`,
# the tool's strongest assertion, is unreachable by a clean app. 2026-08-22 that meant
# 70.0, the smallest round number clearing the then-highest clean score of 69.19.
#
# **Raised to 72.0 on 2026-08-24, because 70.0 stopped satisfying its own criterion.**
# com.jens.automation2 rose 69.19 -> 71.54 on the rebuilt corpus, so at 70.0 a clean app
# read `malicious` — exactly the outcome this boundary exists to prevent. 72.0 is the
# smallest round number clearing 71.54, which is the identical rule that produced 70.0.
#
# Measured tradeoff (data/corpus_scores_v3.json, malware n=334): `malicious` goes from
# reachable by 1 of 299 clean apps to 0, and malware at `malicious` drops 118 -> 88
# (35.3% -> 26.3%). **Nothing drops below `high`:** malware at `high`-or-above is
# unchanged at 240/334 (71.9%) either way — this only moves which of the two top labels
# a malware sample gets. Accepted deliberately, on the same judgment as before: a false
# `malicious` verdict on a legitimate app is worse than a real trojan reading `high`.
#
# **Two things to know before touching this number again.**
#
# 1. **It is not a separating boundary and cannot be made into one.** There is no gap
#    anywhere in (69, 76] larger than 0.5 points — the malware distribution is
#    continuously dense there — and the nearest malware sample sits at 71.55, i.e. 0.01
#    ABOVE the clean app at 71.54. The two classes are interleaved at that resolution.
#    72.0 is a value judgment about one sample, not a discovered threshold, and the 0.46
#    points of margin above 71.54 is all the room there is.
#
# 2. **That clean app is tracking upward with retraining** — 69.19 under the 364-row
#    model, 71.54 under the 633-row one, driven by its classifier component reaching
#    23.21/25. The retrained model is MORE confident that a clean automation app is
#    malware. If it clears 72.0 on a future retrain, **do not keep raising this ceiling**:
#    each raise costs real malware recall to accommodate one app that no boundary
#    separates. Add it to the named-exception list at BAND_SUSPICIOUS_CEILING instead and
#    leave the boundary where it is.
BAND_HIGH_CEILING = 72.0

# ── Brand impersonation (N11) ─────────────────────────────────────────────────
# Impersonation enters the score as a FLOOR, not as an eighth weighted component.
# Two reasons, and the second is the one that matters:
#
#   1. An eighth slot would mean redistributing the 100 points across all seven
#      existing components and re-deriving all four band boundaries — a large change
#      to a calibration that was measured, in order to accommodate a signal that
#      averages badly.
#   2. It averages badly because it is categorically different evidence. Every other
#      component estimates how malicious the CODE looks. This one asserts a fact about
#      the app's IDENTITY: "this APK carries PhonePe's package name and is signed by a
#      key PhonePe does not use." A weighted sum lets a clone with a deliberately
#      modest payload read `low` — which is exactly the app a fraud team most needs to
#      see, since the payload is not the attack. The brand is.
#
# So the weighted total still says what the code looks like, and the floor says what
# the verdict cannot fall below given who the app is pretending to be. Each floor is a
# band boundary rather than an invented number, so the floor states a VERDICT and lets
# the arithmetic supply the score above it.

# _band_for uses `total <= ceiling`, so a floor placed exactly ON a boundary lands in
# the band BELOW it. Each floor is therefore the boundary plus this epsilon — small
# enough that the floor still reads as the boundary it was derived from, large enough
# to survive the round(total, 2) applied to the final score.
_JUST_ABOVE = 0.01

# ── Dynamic verification (Phase 8) ────────────────────────────────────────────
# Same floor pattern as impersonation, not an eighth weighted component: dynamic
# confirmation has no comparable measured corpus yet (impersonation's floors were
# derived from what Android's own trust model guarantees; these two are simply
# "this is strong enough evidence that it shouldn't read as a low weighted score
# just because a static component happened to be quiet"). A `not_observed` dynamic
# result must NEVER lower a verdict — see compute_risk_score below, where only a
# confirmed positive contributes a floor at all.
DYNAMIC_CONFIRMATION_SCORE_FLOOR = {
    # A statically-extracted C2 indicator (Telegram bot, Discord webhook, raw
    # IP:port, .onion, etc.) that the app actually connected to at runtime —
    # this is live, observed contact with attacker infrastructure, not a string
    # sitting unused in the binary.
    "c2_contact_confirmed": BAND_SUSPICIOUS_CEILING + _JUST_ABOVE,   # -> `high`
    # A DexClassLoader/PathClassLoader target the static pass could only
    # resolve to a path actually got loaded and executed at runtime — the
    # exact "predicted but unseen payload" gap the static-only README already
    # documents as a known limitation, closed by direct observation.
    "dcl_payload_executed": BAND_SUSPICIOUS_CEILING + _JUST_ABOVE,   # -> `high`
}


def dynamic_confirmation_floor(dynamic_verification: dict | None) -> float:
    """
    Extracted so the hot (cache-hit) path in routes.py can apply the exact
    same floor logic when a request explicitly asks for dynamic verification
    on an already-cached sample — dynamic behavior is a runtime property, not
    something a static-analysis cache hit should silently skip just because
    the SHA-256 was seen before.

    Only a CONFIRMED positive contributes — a `ran: False` (pass didn't
    complete) or an all-empty `ran: True` (nothing confirmed) result must
    never lower a score, so both read as 0.0 here, identical to "no dynamic
    evidence available" rather than "checked, found nothing malicious".
    """
    floor = 0.0
    if dynamic_verification and dynamic_verification.get("ran"):
        if dynamic_verification.get("network_confirmed"):
            floor = max(floor, DYNAMIC_CONFIRMATION_SCORE_FLOOR.get("c2_contact_confirmed", 0.0))
        if dynamic_verification.get("dcl_payload_executed"):
            floor = max(floor, DYNAMIC_CONFIRMATION_SCORE_FLOOR.get("dcl_payload_executed", 0.0))
    return floor


# Third floor, same pattern and the same reason as the two above: strong evidence
# that must not read as a low weighted score merely because the weighted components
# had nothing to work with.
#
# The gap this closes: when static parsing recovers nothing, classifier_confidence
# (25), ttp_severity (15) and forensic_anchor (15) all go to zero together — 55 of
# 100 points structurally unreachable — while the only component that can still
# speak to "other people have seen this exact file and called it malware" is
# reputation, capped at 5.0. So a sample that is BOTH externally flagged AND opaque
# enough to defeat the analyser scored lower than a transparent, mildly odd one.
# Found live: 02c08ec2…, 41 of 77 VirusTotal engines malicious, scored 29.8 `low`.
#
# `suspicious`, deliberately not `high`. Internal analysis contributed nothing here;
# the assertion being made is "a human should look at this", which is exactly what
# `suspicious` means. Claiming `high` on someone else's verdict plus an absence of
# our own evidence would be overreach.
#
# Trigger is a hash hit (is_known_malware — local signature DB, VirusTotal or
# MalwareBazaar), which identifies THIS file. YARA breadth is deliberately NOT a
# trigger: clean apps match a mean of 14 community rules (see IOC_YARA_WEIGHT), so
# admitting YARA here would fire the floor on benign apps that merely parse badly —
# the exact false-positive mode this scoring system exists to avoid.
OPAQUE_REPUTATION_SCORE_FLOOR = {
    "known_malware_no_static_coverage": BAND_MEDIUM_CEILING + _JUST_ABOVE,  # -> `suspicious`
}


def no_code_analysed(obfuscation: ObfuscationSignal) -> bool:
    """
    The analyser recovered no control-flow graphs from a DEX too small to be a real
    app — see TOTAL_METHOD_PARSE_FAILURE_WEIGHT for the corpus measurement and for
    why BOTH halves are required. Shared by obfuscation_component and
    opaque_reputation_floor so the two cannot drift apart.

    `dex_method_count is None` means not measured, and returns False: absence of a
    measurement is not evidence, exactly as it is for the ratio test.
    """
    if obfuscation.dex_method_count is None:
        return False
    return (
        obfuscation.analyzed_method_count == 0
        and obfuscation.dex_method_count <= OPAQUE_DEX_MAX_METHODS
    )


def opaque_reputation_floor(is_known_malware: bool, obfuscation: ObfuscationSignal) -> float:
    """
    Floor for "externally confirmed AND we could not read it".

    BOTH halves are required. External reputation alone needs no floor — a sample
    the analyser could read scores on its own evidence. Degraded coverage alone must
    never raise a score, or every APK this parser struggles with becomes suspicious
    on nothing more than our own failure to parse it.

    Degraded coverage means no_code_analysed (so the three code-derived components
    all read 0), or a corrupt manifest. Both are the same situation for scoring: the
    feature vector the weighted components need was never produced. It deliberately
    does NOT include "the relevance pre-filter selected nothing on a normal-sized
    app" — see no_code_analysed.
    """
    if not is_known_malware:
        return 0.0
    if no_code_analysed(obfuscation) or obfuscation.manifest_parse_failed:
        return OPAQUE_REPUTATION_SCORE_FLOOR["known_malware_no_static_coverage"]
    return 0.0


IMPERSONATION_SCORE_FLOOR = {
    # Definitive: Android identifies publishers by signing key. Either the real
    # publisher signed this or somebody else did, and there is no third case.
    "certificate_mismatch": BAND_HIGH_CEILING + _JUST_ABOVE,         # -> `malicious`
    # Strong but not definitive: an icon can be coincidentally similar, and the
    # reference hash could have been captured from a bad source APK.
    "icon_reuse": BAND_SUSPICIOUS_CEILING + _JUST_ABOVE,             # -> `high`
    "package_typosquat": BAND_SUSPICIOUS_CEILING + _JUST_ABOVE,      # -> `high`
    # Same floor as a typosquat, for a stronger reason: a package cannot arrive at
    # "<brand's full namespace>.<random>" by mistyping. See _check_package.
    "package_namespace_squat": BAND_SUSPICIOUS_CEILING + _JUST_ABOVE,  # -> `high`
    # Weakest of the four: display names are not unique, and a genuine third-party
    # companion app may legitimately carry a brand's name.
    "label_impersonation": BAND_MEDIUM_CEILING + _JUST_ABOVE,        # -> `suspicious`
}

# The band each floor is meant to guarantee. Pinned by
# test_impersonation_floor_lands_in_its_intended_band so that moving a band boundary
# cannot silently demote an impersonation verdict — the floors are expressed in terms
# of the boundaries, and this is what proves the arithmetic still agrees.
IMPERSONATION_FLOOR_BAND = {
    "certificate_mismatch": "malicious",
    "icon_reuse": "high",
    "package_namespace_squat": "high",
    "package_typosquat": "high",
    "label_impersonation": "suspicious",
}

RISKY_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 1.0,
    "android.permission.READ_SMS": 0.8,
    "android.permission.RECEIVE_SMS": 0.8,
    "android.permission.SEND_SMS": 0.7,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.6,
    "android.permission.REQUEST_INSTALL_PACKAGES": 0.5,
    "android.permission.PACKAGE_USAGE_STATS": 0.55,
    "android.permission.QUERY_ALL_PACKAGES": 0.5,
    "android.permission.BIND_DEVICE_ADMIN": 0.7,
    "android.permission.RECEIVE_BOOT_COMPLETED": 0.35,
}

# Per-behavior severity weights for the forensic anchor component (§9.3).
# Higher = more directly indicative of active banking fraud capability.
BEHAVIOR_SEVERITY = {
    "STEALTH_SMS_INTERCEPTION": 1.0,  # proven SMS interception API present
    "OTP_INTERCEPTION":         0.95,  # OTP theft string + SMS permissions
    "CREDENTIAL_HARVESTING":    0.9,   # accessibility/webview overlay pattern
    "ACCESSIBILITY_ABUSE":      0.9,   # keylogging / gesture control capability
    "C2_BEHAVIOR":              0.75,  # high-signal C2 channels (telegram/firebase/onion)
    "DYNAMIC_CODE_LOADING":     0.7,   # dropper / stage-2 loading
    "DYNAMIC_REFLECTION":       0.6,   # evasion capability
    "CRYPTOGRAPHY_USAGE":       0.4,   # present in many benign apps too
}

# Permission-matrix flag severity (banking-trojan combo patterns from apk_static).
MATRIX_FLAG_SEVERITY = {
    "OVERLAY_ATTACK_PATTERN":         0.95,
    "OVERLAY_BOOT_PERSISTENCE":       0.8,
    "SMS_OTP_STEALER_PATTERN":        1.0,
    "SMS_OTP_SENDER_PATTERN":         0.9,
    "DROPPER_STAGE2_PATTERN":         0.85,
    "DEVICE_ADMIN_PERSISTENCE":       0.75,
    "BANKING_TARGET_ENUMERATION":     0.7,
    "ACCESSIBILITY_FULL_CONTROL":     0.95,
    "ACCESSIBILITY_WINDOW_CONTENT":   0.9,
    "ACCESSIBILITY_GESTURE_CONTROL":  0.85,
    "ACCESSIBILITY_KEYLOGGING_MASK":  0.95,
}


def classifier_confidence_component(
    predicted_ttps: dict[str, float],
    evidence_present: bool = True,
    ttp_thresholds: dict[str, float] | None = None,
) -> float:
    """
    Turns the multi-label TTP model's output into one calibrated 0-1 confidence.

    `evidence_present=False` zeroes the component outright. The model has a benign
    class now, but it still cannot be asked "is this malware?" — it answers "which
    techniques does this sample exhibit?" — so a sample that yielded no parsed code
    and no forensic anchors gets no vote at all rather than the label prior's
    opinion (see pipeline.has_deterministic_evidence).

    N8: this used to return `max(predicted_ttps.values())`, which discards the two
    things that actually distinguish a real TTP profile from a lucky label:

      * **Where the probability sits relative to its own decision boundary.** The
        per-label thresholds calibrated at training time range from 0.10 to 0.90
        (`ttp_metrics.json`), because label prevalence ranges from 0.02 to 0.75. A
        0.98 on T1516, whose boundary is 0.10, is not the same evidence as a 0.98
        on T1471, whose boundary is 0.90. Each probability is therefore rescaled to
        its margin past its own threshold.
      * **Breadth.** Measured over the 353-sample corpus, malware predicts a median
        of 8 techniques and 213 of 220 clean apps predict none. One technique, however
        confident, is a thin basis for a 25-point component — `com.symeonchen.wakeupscreen`
        drew 24.57 of 25 from a single label. Margins are summed into an evidence
        mass and squashed, so confidence grows with corroborating techniques and
        saturates once there are enough of them.

    A clean app that the model genuinely reads as multi-technique malware still scores
    high here; that is a training-data problem (the negatives are 220 F-Droid
    utilities) and no scoring function can talk it out of its own prediction.
    """
    if not evidence_present or not predicted_ttps:
        return 0.0

    thresholds = ttp_thresholds or {}
    mass = 0.0
    for technique, prob in predicted_ttps.items():
        thr = thresholds.get(technique, DEFAULT_TTP_THRESHOLD)
        headroom = max(1e-6, 1.0 - thr)
        mass += min(1.0, max(0.0, (prob - thr) / headroom))

    return 1.0 - math.exp(-mass / CONFIDENCE_SATURATION_MASS)


def permission_api_risk_component(
    permissions: list[str],
    permission_matrix_flags: list[str] | None = None,
) -> float:
    """
    Single-permission risk plus multi-permission matrix combos
    (overlay attack, OTP stealer, dropper patterns from apk_static).
    """
    if not permissions and not permission_matrix_flags:
        return 0.0
    scores = [RISKY_PERMISSIONS.get(p, 0.0) for p in (permissions or [])]
    matched = [s for s in scores if s > 0]
    base = 0.0
    if matched:
        base = min(1.0, sum(matched) / len(matched) + 0.1 * (len(matched) - 1))

    # Matrix flags are stronger than individual perms — boost toward 1.0
    matrix_boost = 0.0
    for flag in permission_matrix_flags or []:
        matrix_boost = max(matrix_boost, MATRIX_FLAG_SEVERITY.get(flag, 0.6))
    if matrix_boost > 0:
        # Blend: matrix evidence dominates when present
        return min(1.0, max(base, 0.55 * base + 0.55 * matrix_boost))
    return base


def _technique_severity(ttp: str) -> float:
    """
    Severity for one technique: per-technique override first, then a tactic-derived
    fallback (so EVERY Mobile technique the multi-label model can predict gets a
    principled weight), then DEFAULT.
    """
    if ttp in TTP_SEVERITY_WEIGHTS:
        return TTP_SEVERITY_WEIGHTS[ttp]
    tactic = TECHNIQUE_TACTIC.get(ttp)
    if tactic and tactic in TACTIC_SEVERITY:
        return TACTIC_SEVERITY[tactic]
    return TTP_SEVERITY_WEIGHTS["DEFAULT"]


def ttp_severity_component(predicted_ttps: dict[str, float]) -> float:
    """
    Fed by MITRE technique IDs predicted DIRECTLY by the multi-label TTP classifier
    (cold path) or the FAMILY_TO_TTPS bridge (legacy/hot path). Severity covers the
    full Mobile technique space via _technique_severity, not just 5 hardcoded IDs.

    N9: this used to return the MEAN of the severity-weighted probabilities, which
    made the component fall as the model found more. T1471 at 0.9 alone scored 0.855;
    the same T1471 surrounded by five corroborating Discovery techniques scored 0.510
    — a 5.2-point swing on a 15-point component, in the wrong direction. Over the
    corpus it was worse than non-monotonic: the single highest value belonged to a
    *benign* app (0.941, one severe technique) against a malware maximum of 0.810,
    because averaging eight techniques always lands near the middle of the severity
    scale while averaging one lands on that technique's own severity.

    Severity-weighted probabilities are now summed into an evidence mass and squashed
    (see TTP_SEVERITY_SATURATION_MASS), so the component is monotone in evidence and
    still bounded at 1.0 — the same shape classifier_confidence_component uses.
    """
    if not predicted_ttps:
        return 0.0
    mass = sum(prob * _technique_severity(ttp) for ttp, prob in predicted_ttps.items())
    return 1.0 - math.exp(-mass / TTP_SEVERITY_SATURATION_MASS)


def forensic_anchor_component(matched_anchor_behaviors: set[str]) -> float:
    """
    §9.3 fix: score deterministic forensic-dictionary matches directly.

    Unlike the classifier (probabilistic), these are grounded in proven API
    presence in the binary — the strongest static predictor per GUARD SHAP.
    Scaled by per-behavior severity weights so a confirmed SMS interception
    anchor counts more than a generic crypto usage hit.

    N9: this used to return the mean severity plus a small breadth bonus
    (`0.05 * (n - 1)`, capped at 0.2). The bonus was far too small to offset what
    averaging did. Measured over the corpus the component discriminated *backwards*:
    benign p95 0.800 against malware p50 0.767, separation -0.033. Clean apps match
    a median of one anchor, and the mean of one anchor is that anchor's own severity
    — so a benign app matching DYNAMIC_REFLECTION (0.6) scored 0.600, while malware
    matching CRYPTOGRAPHY_USAGE + DYNAMIC_REFLECTION + C2_BEHAVIOR averaged 0.583.
    The component was charging malware for also doing the ordinary things.

    Summing into a saturating mass fixes the sign (separation +0.046) and is monotone:
    an additional proven behavior can never lower the score.
    """
    if not matched_anchor_behaviors:
        return 0.0
    mass = sum(BEHAVIOR_SEVERITY.get(b, 0.5) for b in matched_anchor_behaviors)
    return 1.0 - math.exp(-mass / ANCHOR_SATURATION_MASS)


def obfuscation_component(
    obfuscation: ObfuscationSignal,
    entropy_threshold: float | None = None,
) -> float:
    """
    §9.5: coverage gaps raise the score, not just the narrative text. An APK that
    evades analysis is *more* suspicious than a fully transparent one, all else equal.

    N7 rewrite. The four old inputs measured, over the 353-APK corpus:

      | input                            | benign          | malware        |
      |----------------------------------|-----------------|----------------|
      | `string_entropy_score` >= 7.2    | never (max 3.47)| never          |
      | `flattening_suspected`           | 30/30 sampled   | 23/28 sampled  |
      | `unresolved_reflection_targets`  | 0 (stub)        | 0 (stub)       |
      | `method_parse_failure_rate` >=.1 | 0/353           | 0/353          |

    Three were dead and the fourth was a near-constant pointing the wrong way, which
    is why the component read exactly 6.00/15 for 216 of 220 clean apps and 108 of
    133 malware — 39.3% of cap for benign against 32.5% for malware, an inverted
    constant occupying 15% of the score.

    * Mean per-string Shannon entropy cannot reach 7.2 bits: that needs ~147 distinct
      characters per string. It is also inverted, because large clean apps carry
      longer, more varied literals than a packed stub does. It stays on
      ObfuscationSignal — it is one of the three frozen OBFUSCATION_FEATURES and the
      coverage note still reports it — but it no longer moves the score.
      `entropy_threshold` is kept in the signature so call sites need not change.
    * Flattening prevalence is measured and reported but not scored: benign p75 0.119
      against malware p75 0.118, and no threshold from 0.05 to 0.50 gives a lift
      outside 0.79-1.07. Paying points for it is paying for noise.
    * Manifest-vs-code is what the component now rests on: a DEX that cannot
      possibly implement the manifest it ships with. Re-measured over 300 clean and
      318 malware samples, 37 malware fail that test — including a sample declaring
      539 activities, 42 services and 49 receivers with 57 methods — and the lowest
      ratio any clean app reaches is 56.85 dex methods per declared component,
      28.4x above the floor. Tripling the corpus and adding 80 apps up to 60 MB did
      not move that minimum at all: it is the same app (net.pgaskin.windy, 1137
      methods / 20 declared) at the same ratio. Those samples used to score 0.0
      here, because an empty CFG set has nothing that can look flattened: the
      component that exists to measure evasion read zero on exactly the samples
      that defeated the analyser.
    * Method parse-failure rate was measured and dropped, not merely left unscored.
      `method_parse_failure_rate` was 0.0 on all 353 samples of the old corpus and
      is still 0.0 on all 616 of this one. A threshold, a multiplier and a cap
      governing a signal with zero observations across two corpora is surface area,
      not calibration, so the branch and its three constants were deleted.

    On this corpus that leaves the component at 0.0 for every clean app and non-zero
    only where the code genuinely could not be reached. A component that is silent
    when it has nothing to say beats one that pays 6.00 to everybody.

    Post-N7 addition: `manifest_parse_failed` (MANIFEST_CORRUPTED_WEIGHT) is scored
    without the corpus measurement every other input here required, because it's a
    different kind of signal — not a prevalence to check for benign confounds, but a
    binary fact with no plausible innocent explanation (no build tool corrupts its
    own manifest). Found in practice, not measured in advance: a MalwareBazaar/
    VirusTotal-confirmed sample (Tanglebot, an mParivahan-spoofing SMS/banking
    trojan) scored 22.47 "low" before this existed, because its corrupted manifest
    starved permission_api_component, ttp_severity_component and
    classifier_confidence_component of the feature vector all three depend on —
    ~60 of 100 possible points structurally unreachable on one deterministically
    malicious sample.
    """
    score = 0.0

    # The recovered code cannot account for the app the manifest describes — packed,
    # encrypted, or staged at runtime. `None` on either field means "not measured",
    # which earns nothing: only a measurement is evidence.
    declared = obfuscation.declared_component_count
    recovered = obfuscation.dex_method_count
    if recovered is not None:
        if recovered == 0 or (
            declared
            and recovered < MIN_METHODS_PER_DECLARED_COMPONENT * declared
        ):
            score += CODE_NOT_RECOVERED_WEIGHT
    # No code examined at all, out of a DEX too small to be a real app. Distinct
    # from the ratio test above, which compares the DEX against its own manifest;
    # this compares it against "is there enough here to be an app". Additive, so
    # "no methods AND no CFGs" saturates the component. See
    # TOTAL_METHOD_PARSE_FAILURE_WEIGHT for the corpus measurement behind it.
    if no_code_analysed(obfuscation):
        score += TOTAL_METHOD_PARSE_FAILURE_WEIGHT

    # Unresolved reflection targets are measured and REPORTED (see the coverage
    # note) but deliberately not scored — see UNRESOLVED_REFLECTION_WEIGHT.

    # A structurally corrupted manifest (ingest.py's fallback path fired) means
    # permission_api_component, ttp_severity_component and
    # classifier_confidence_component all lose most or all of their evidence too
    # — the same missing feature vector starves several components at once, not
    # just this one. Scoring it here is the one place that actually captures
    # "this sample is deliberately hiding its manifest," which the corpus found
    # in practice: a MalwareBazaar/VirusTotal-confirmed sample with a corrupted
    # manifest scored 22.47 ("low") before this weight existed, entirely because
    # ~60 of the 100 possible points were structurally unreachable without it.
    if obfuscation.manifest_parse_failed:
        score += MANIFEST_CORRUPTED_WEIGHT

    return min(1.0, score)


def reputation_component(
    cache_hit: bool,
    cached_score: float | None,
    is_known_malware: bool = False,
) -> float:
    """
    If we got a cache hit, reputation is informed by prior known score.
    If no cache hit (first-seen sample), reputation defaults to neutral —
    it's neither vouched-for nor known-bad on this axis alone.

    §sig: if the sample matches a known-malware signature hash, reputation
    jumps to near-maximum regardless of cache state.
    """
    if is_known_malware:
        return 0.95  # known-bad sample — near-maximum reputation risk
    if cache_hit and cached_score is not None:
        return min(1.0, cached_score / 100.0)
    return 0.3  # neutral-low prior for unknown samples


def ioc_component(
    matched_c2_indicators: int,
    signature_match_count: int = 0,
    yara_match_count: int = 0,
    yara_max_severity: float = 0.0,
    extracted_c2_count: int = 0,
    cert_anomaly_count: int = 0,
    secondary_dex_count: int = 0,
    dropper_signal_count: int = 0,
) -> float:
    """
    IOC score — signature detection, YARA results, extracted C2 indicators,
    certificate anomalies, and dropper payload signals.

    N6 rewrite. The old tiers summed everything into one `min(1.0, ...)`, which let
    ubiquitous evidence saturate the cap on its own. Measured, clean apps drew 93.4%
    of the 5-point cap against malware's 97.6% — a component with no information in
    it. Two causes, in order of size:

      * **YARA.** `severity * 0.3 * min(n, 3)` paid 0.765 to anything matching three
        rules at severity 0.85, and a clean app matches a mean of 10.8 of the 498
        loaded community rules, at exactly that severity (`IP`, `domain`,
        `contains_base64` and friends). Rule-declared severity is metadata written by
        the rule's author, not a measurement of how specific the rule is, so breadth
        across a generic corpus no longer multiplies: YARA contributes
        `IOC_YARA_WEIGHT * max_severity`, once. See T11 for the corpus skew itself.
      * **`self_signed`** on every APK, worth 0.15 — fixed upstream in
        apk_static.analyze_certificate_anomalies.

    Evidence is now split by whether it identifies *this* sample:

      * **Attributable** — a signature hash/cert hit, an exact extracted IoC, a hidden
        DEX payload. Any of these can carry the component to its cap alone, because
        each names something specific about this file.
      * **Circumstantial** — YARA, certificate anomalies, dropper heuristics, forensic
        C2 strings. Jointly capped at IOC_CIRCUMSTANTIAL_CAP, so no pile of generic
        hits can imply a verdict on its own.

    Caveat for anyone reading corpus numbers: `signature_match_count` is 1 for every
    malware sample in `data/ttp_apks/` because those hashes came from MalwareBazaar
    and are in the signature DB. On this corpus it is a tautology, not a measurement.
    """
    attributable = 0.0
    attributable += signature_match_count * IOC_SIGNATURE_WEIGHT
    attributable += min(
        IOC_EXTRACTED_C2_CAP, extracted_c2_count * IOC_EXTRACTED_C2_WEIGHT
    )
    attributable += min(
        IOC_SECONDARY_DEX_CAP, secondary_dex_count * IOC_SECONDARY_DEX_WEIGHT
    )

    circumstantial = 0.0
    if yara_match_count > 0:
        circumstantial += IOC_YARA_WEIGHT * yara_max_severity
    circumstantial += cert_anomaly_count * IOC_CERT_ANOMALY_WEIGHT
    circumstantial += dropper_signal_count * IOC_DROPPER_WEIGHT
    circumstantial += matched_c2_indicators * IOC_FORENSIC_C2_WEIGHT

    return min(1.0, attributable + min(IOC_CIRCUMSTANTIAL_CAP, circumstantial))


def _band_for(total: float) -> str:
    """Verdict band thresholds, shared so a cache hit reports the same band
    a cold-path run would have for the same total_score."""
    if total <= BAND_LOW_CEILING:
        return "low"
    if total <= BAND_MEDIUM_CEILING:
        return "medium"
    if total <= BAND_SUSPICIOUS_CEILING:
        return "suspicious"
    if total <= BAND_HIGH_CEILING:
        return "high"
    return "malicious"


def compute_risk_score(
    predicted_ttps: dict[str, float],
    permissions: list[str],
    obfuscation: ObfuscationSignal,
    # Retained for call-site compatibility and no longer read: string-pool entropy
    # stopped contributing to the score in N7 — see obfuscation_component. It still
    # drives the coverage note in build_obfuscation_signal, which is where the
    # threshold does its remaining work.
    entropy_threshold: float,
    matched_anchor_behaviors: set[str] | None = None,
    cache_hit: bool = False,
    cached_score: float | None = None,
    matched_c2_indicators: int = 0,
    # Signature detection & YARA scanning inputs
    signature_match_count: int = 0,
    yara_match_count: int = 0,
    yara_max_severity: float = 0.0,
    is_known_malware: bool = False,
    # Advanced Android static anchors
    permission_matrix_flags: list[str] | None = None,
    extracted_c2_count: int = 0,
    cert_anomaly_count: int = 0,
    secondary_dex_count: int = 0,
    dropper_signal_count: int = 0,
    # See classifier_confidence_component.
    classifier_evidence_present: bool = True,
    ttp_thresholds: dict[str, float] | None = None,
    # Brand-impersonation findings (app/analysis/impersonation.py) as dicts carrying
    # at least a "kind". Applied as a floor, not a weighted term — see
    # IMPERSONATION_SCORE_FLOOR for why.
    impersonation_findings: list[dict] | None = None,
    # Phase 8's output dict (dynamic_verification.py), or None when that phase
    # didn't run. Applied as a floor — see DYNAMIC_CONFIRMATION_SCORE_FLOOR.
    dynamic_verification: dict | None = None,
) -> RiskScoreBreakdown:
    if matched_anchor_behaviors is None:
        matched_anchor_behaviors = set()

    # Both model-derived components are gated together: if the classifier had no
    # grounds for an opinion, the severity of the techniques it named is just as
    # ungrounded. The deterministic components (permissions, anchors, obfuscation,
    # IOC) are untouched — they are measurements, not predictions.
    c1 = classifier_confidence_component(
        predicted_ttps,
        evidence_present=classifier_evidence_present,
        ttp_thresholds=ttp_thresholds,
    )
    c2 = permission_api_risk_component(
        permissions, permission_matrix_flags=permission_matrix_flags
    )
    c3 = ttp_severity_component(predicted_ttps) if classifier_evidence_present else 0.0
    c4 = forensic_anchor_component(matched_anchor_behaviors)
    c5 = obfuscation_component(obfuscation)
    c6 = reputation_component(cache_hit, cached_score, is_known_malware)
    c7 = ioc_component(
        matched_c2_indicators,
        signature_match_count=signature_match_count,
        yara_match_count=yara_match_count,
        yara_max_severity=yara_max_severity,
        extracted_c2_count=extracted_c2_count,
        cert_anomaly_count=cert_anomaly_count,
        secondary_dex_count=secondary_dex_count,
        dropper_signal_count=dropper_signal_count,
    )

    # Revised weights (§9.3): 0.25 + 0.20 + 0.15 + 0.15 + 0.15 + 0.05 + 0.05 = 1.00
    total = (
        0.25 * c1 + 0.20 * c2 + 0.15 * c3 + 0.15 * c4 + 0.15 * c5 + 0.05 * c6 + 0.05 * c7
    ) * 100

    # Brand impersonation raises a floor under the weighted total. It never lowers a
    # score and never caps one: a clone that is ALSO obvious malware keeps the higher
    # arithmetic verdict. `impersonation_floor_applied` records whether the floor
    # actually moved the number, so the report can distinguish "this scored 82 on its
    # own behaviour" from "this scored 11 and is a signed clone of a bank app".
    weighted_total = total
    impersonation_floor = 0.0
    for finding in impersonation_findings or []:
        impersonation_floor = max(
            impersonation_floor,
            IMPERSONATION_SCORE_FLOOR.get(finding.get("kind", ""), 0.0),
        )

    dynamic_floor = dynamic_confirmation_floor(dynamic_verification)
    opaque_floor = opaque_reputation_floor(is_known_malware, obfuscation)

    total = max(total, impersonation_floor, dynamic_floor, opaque_floor)

    band = _band_for(total)

    # Zero-day / novel-variant signal: the model-free components (deterministic
    # forensic anchors, structural obfuscation/coverage) carry strong evidence while
    # the classifier is unfamiliar (low confidence / empty predictions). This is
    # exactly the first-seen sample the family/TTP model has not learned yet. It does
    # not change the numeric weights — the deterministic components already provide
    # the score floor — it surfaces the situation for the analyst / report.
    zero_day_indicator = (
        (c4 >= ZERO_DAY_ANCHOR_MIN or c5 >= ZERO_DAY_OBF_MIN)
        and c1 < ZERO_DAY_CONF_MAX
        and not cache_hit
    )

    return RiskScoreBreakdown(
        classifier_confidence_component=round(c1 * 25, 2),
        permission_api_component=round(c2 * 20, 2),
        ttp_severity_component=round(c3 * 15, 2),
        forensic_anchor_component=round(c4 * 15, 2),
        obfuscation_component=round(c5 * 15, 2),
        reputation_component=round(c6 * 5, 2),
        ioc_component=round(c7 * 5, 2),
        total_score=round(total, 2),
        verdict_band=band,
        zero_day_indicator=zero_day_indicator,
        impersonation_floor_applied=impersonation_floor > weighted_total,
        dynamic_confirmation_floor_applied=dynamic_floor > weighted_total,
        opaque_reputation_floor_applied=opaque_floor > weighted_total,
        weighted_score=round(weighted_total, 2),
    )
