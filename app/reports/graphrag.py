"""
GraphRAG report generation. Retrieves bounded ontology facts from Neo4j
and constrains the LLM to summarize ONLY the JSON manifest + ontology facts
provided — not to invent evidence. This directly implements the paper's
prompt guardrails:
  - cite every behavior from extracted evidence
  - say "not observed" rather than guessing
  - separate deterministic findings from model predictions
  - include confidence values
  - output analyst actions in priority order

Runs against a local Ollama instance (OpenAI-compatible API at
http://localhost:11434/v1). No API key or network calls needed.

Anti-hallucination measures implemented here:
  1. temperature=0  — greedy decode; eliminates stochastic drift.
  2. top_p=1.0      — no nucleus sampling on top of greedy.
  3. SYSTEM_PROMPT OUTPUT FORMAT section — explicit section contract
     prevents the model from adding speculative “also consider…” padding.
  4. Hard prohibition on citing technique IDs / names not in the
     ## MITRE ATT&CK Mobile Ontology Context block.
  5. Post-generation grounding check — any T-ID in the narrative that
     was NOT in the provided ontology context is logged as a warning so
     the operator can spot-check reports easily.
"""
import json
import re
from collections import Counter
from openai import OpenAI
from loguru import logger

from app.core.config import settings
from app.core.schemas import AnalysisManifest, RiskScoreBreakdown
from app.graph.ontology import get_technique_context
from app.ml.features import TTP_PERMISSION_VOCAB

SYSTEM_PROMPT = """You are a cybersecurity analyst report generator for GuardGraph AI,
a banking-focused Android malware analysis engine.

STRICT RULES — violating ANY of these makes the report unusable:
1. Only state findings that are explicitly present in the provided JSON manifest,
   risk score breakdown, or MITRE ontology context block. Never invent evidence.
2. If something is not covered by the provided data (e.g. native code was not
   analyzed, or a technique has low confidence), say so explicitly using
   phrasing like "not observed" or "not statically resolved" — do NOT guess.
3. Clearly separate deterministic findings (hash matches, permission declarations,
   matched APIs, extracted C2 IoCs, permission matrix flags, certificate anomalies,
   accessibility config flags, secondary DEX / dropper signals, exported component risks)
   from model predictions (classifier confidence, predicted TTPs).
4. Always include the confidence value alongside any predicted TTP.
5. When present, explicitly cite:
   - c2_indicators (Telegram bots, Firebase, Discord webhooks, TOR, raw IP:port)
   - permission_matrix_flags (OVERLAY_ATTACK_PATTERN, SMS_OTP_STEALER_PATTERN, etc.)
   - accessibility_flags (canRetrieveWindowContent, typeAllMasks keylogging masks)
   - cert_anomalies (debug keys, self-signed, expired)
   - secondary_dex_count / payload_assets / dropper_signals
   - exported_risks (unprotected exported receivers/services)
6. Do NOT mention any MITRE technique ID (e.g. T1636) or technique name that is
   NOT present in the "## MITRE ATT&CK Mobile Ontology Context" section below.
   If you have general knowledge of a technique but it is absent from that block,
   do not cite it — say "no ontology context provided for this technique" instead.
7. End with a "Recommended Analyst Actions" section in priority order.
8. Do not use hedging filler language beyond what's needed for genuine uncertainty.
9. If the risk score breakdown has "zero_day_indicator": true, prominently flag
   this as a POSSIBLE NOVEL / ZERO-DAY VARIANT. Explain that the verdict rests on
   model-free evidence (deterministic matched APIs/permissions and/or structural
   obfuscation/coverage signals) while the classifier has low familiarity — not on
   classifier confidence alone.
10. Do not add sections, bullet points, or conclusions that go beyond what the data
   supports. If a section would require invented evidence, omit it entirely.
7. Do not use hedging filler language beyond what's needed for genuine uncertainty.
8. If the risk score breakdown has "zero_day_indicator": true, prominently flag this as a
   POSSIBLE NOVEL / ZERO-DAY VARIANT. Explain that the verdict rests on model-free evidence
   (deterministic matched APIs/permissions and/or structural obfuscation/coverage signals)
   while the classifier has low familiarity with this sample — not on classifier confidence.
>>>>>>> 364c1bf (feat(analysis): add static malware anchors (C2 IoCs, permission matrices, cert anomalies, secondary DEX payloads, uncompressed YARA byte scanning))
Write for a bank fraud-operations audience: clear, direct, actionable.
"""


def _summarize_behavioral_subgraphs(behavioral_subgraphs: list) -> dict:
    """
    Collapses the (often 400+) per-subgraph entries down to one bucket per
    primary_behavior_flag, so the prompt carries the same behavioral signal
    without serializing every individual subgraph. Full detail (topological
    invariants, per-subgraph IDs) stays in the manifest for the API response
    and Neo4j — only the LLM-facing summary is condensed. Unsummarized
    subgraphs were once 87.9% of the prompt and pushed evaluation past the
    model's effective context.
    """
    behavior_counts = Counter(
        bs.primary_behavior_flag for bs in behavioral_subgraphs
    )
    apis_by_behavior: dict[str, list[str]] = {}
    for bs in behavioral_subgraphs:
        seen = apis_by_behavior.setdefault(bs.primary_behavior_flag, [])
        for api in bs.matched_apis:
            if api not in seen and len(seen) < 12:
                seen.append(api)

    return {
        "total_subgraphs": len(behavioral_subgraphs),
        "by_behavior": [
            {
                "primary_behavior_flag": b,
                "subgraph_count": n,
                "representative_matched_apis": apis_by_behavior.get(b, []),
            }
            for b, n in behavior_counts.most_common()
        ],
    }


_PERM_RE = re.compile(r"android\.permission\.[A-Z_]+")

# Bare permission-constant citations (e.g. "RECORD_AUDIO" instead of
# "android.permission.RECORD_AUDIO" — observed in testing: the model dropped
# the prefix while still citing real/fabricated permission names). Matched
# ONLY against this known-permission vocabulary, not treated as freeform
# ALL-CAPS text — otherwise GuardGraph's own behavior-flag / matrix-flag
# vocabulary (e.g. ACCESSIBILITY_ABUSE, T1616) would false-positive as
# "invented permissions".
_BARE_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_KNOWN_PERMISSION_SUFFIXES = {p.rsplit(".", 1)[-1] for p in TTP_PERMISSION_VOCAB}


def _permission_check(narrative: str, declared: set[str]) -> list[str]:
    """
    Anti-fabrication check: the inverse of _grounding_check. That check only
    verifies cited technique IDs are a SUBSET of the supplied ontology, which
    can't catch the model inventing plausible-looking permissions (e.g.
    RECORD_AUDIO back-derived from a predicted TTP rather than the actual
    manifest). Flags any permission the APK does not actually declare,
    whether cited fully-qualified
    (android.permission.X) or bare (X, if X is a recognized Android
    permission name).
    """
    declared_suffixes = {d.rsplit(".", 1)[-1] for d in declared}

    qualified_suffixes = {c.rsplit(".", 1)[-1] for c in _PERM_RE.findall(narrative)}
    bare_suffixes = set(_BARE_TOKEN_RE.findall(narrative)) & _KNOWN_PERMISSION_SUFFIXES

    invented = sorted(
        f"android.permission.{suffix}"
        for suffix in (qualified_suffixes | bare_suffixes) - declared_suffixes
    )
    if invented:
        logger.error(
            f"[Phase 7] FABRICATION DETECTED — narrative cites permissions not "
            f"declared by the APK: {invented}. Report is unsafe to ship."
        )
    return invented


def _grounding_check(narrative: str, provided_technique_ids: set) -> None:
    """
    Post-generation sanity check. Scans the LLM output for MITRE technique ID
    references (pattern T\\d{4}(\\.\\d{3})?) and warns if any were cited that
    were NOT in the provided ontology context block.
    """
    cited_ids = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", narrative))
    hallucinated = cited_ids - provided_technique_ids
    if hallucinated:
        logger.warning(
            f"[Phase 7] Grounding check FAILED — LLM cited technique IDs not in "
            f"provided ontology context: {sorted(hallucinated)}. "
            "Spot-check this report for fabricated evidence."
        )
    else:
        logger.info("[Phase 7] Grounding check passed — all cited technique IDs are grounded.")


def generate_report(
    manifest: AnalysisManifest,
    risk_score: RiskScoreBreakdown,
) -> tuple[str, list[str]]:
    """
    Returns (narrative_report_text, limitations_list).

    Requires a running Ollama instance:
        ollama serve          # if not already running as a service
        ollama pull qwen2.5:7b-instruct-q4_K_M

    Anti-hallucination: temperature is pinned to 0 (greedy decode).
    Do NOT raise this without explicit justification — stochastic sampling
    is the primary driver of LLM drift from the grounded prompt.
    """
    technique_ids = list(manifest.predicted_ttps.keys())
    ontology_context = get_technique_context(technique_ids) if technique_ids else []

    limitations = [manifest.obfuscation.coverage_note]
    if manifest.obfuscation.unresolved_reflection_targets > 0:
        limitations.append(
            f"{manifest.obfuscation.unresolved_reflection_targets} reflection-based "
            "API calls could not be statically resolved to their real target."
        )

    # Provide only the fields the LLM needs for grounding.
    # Omitting internal numeric arrays (feature vectors, subgraph topology floats)
    # reduces the surface area for the model to pattern-match against unrelated data.
    manifest_summary = {
        "target_package": manifest.target_package,
        "sha256": manifest.sha256,
        "cache_hit": manifest.cache_hit,
        "predicted_ttps": manifest.predicted_ttps,
        "predicted_family": manifest.predicted_family,
        "family_confidence": manifest.family_confidence,
        "permissions": manifest.permissions,
        "behavioral_subgraph_summary": _summarize_behavioral_subgraphs(
            manifest.behavioral_subgraphs
        ),
        "obfuscation": {
            "string_entropy_score": manifest.obfuscation.string_entropy_score,
            "flattening_suspected": manifest.obfuscation.flattening_suspected,
            "reflection_call_count": manifest.obfuscation.reflection_call_count,
            "unresolved_reflection_targets": manifest.obfuscation.unresolved_reflection_targets,
            "method_parse_failure_rate": manifest.obfuscation.method_parse_failure_rate,
            "coverage_note": manifest.obfuscation.coverage_note,
        },
        "signature_yara": (
            {
                "signature_matches": [m.model_dump() for m in manifest.signature_yara.signature_matches],
                "yara_matches": [m.model_dump() for m in manifest.signature_yara.yara_matches],
                "is_known_malware": manifest.signature_yara.is_known_malware,
                "combined_severity": manifest.signature_yara.combined_severity,
            }
            if manifest.signature_yara else None
        ),
    }

    user_prompt = f"""Generate an analyst report from the following grounded data ONLY.
Do not use any information, technique IDs, technique names, or threat intelligence
that is not explicitly present in the data blocks below.

## JSON Manifest (grounded facts from static analysis)
{json.dumps(manifest_summary, indent=2)}

## Risk Score Breakdown
{risk_score.model_dump_json(indent=2)}

## MITRE ATT&CK Mobile Ontology Context (ONLY cite techniques listed here)
{json.dumps(ontology_context, indent=2)}

## Known Coverage Limitations (state these explicitly in the report)
{json.dumps(limitations, indent=2)}
"""

    # Hard budget check — Ollama silently truncates an oversized prompt rather
    # than erroring, which is exactly how finding 1 went unnoticed (only 16,386
    # of ~53,000 tokens were evaluated). Fail loudly instead of shipping a
    # report grounded in a partial manifest.
    approx_tokens = (len(SYSTEM_PROMPT) + len(user_prompt)) // 3  # conservative chars/token
    if approx_tokens > settings.graphrag_prompt_token_budget:
        raise RuntimeError(
            f"[Phase 7] Prompt ~{approx_tokens} tokens exceeds budget "
            f"{settings.graphrag_prompt_token_budget}; the model would silently "
            "drop the manifest head. Reduce prompt size before calling the LLM."
        )

    # temperature=0 — greedy decode; eliminates stochastic drift that causes
    # the model to "helpfully" add technique context it wasn’t given.
    # Do NOT raise this without explicit justification.
    client = OpenAI(
        base_url=settings.ollama_base_url,
        api_key="ollama",  # required by the client constructor; ignored by Ollama
    )
    try:
        response = client.chat.completions.create(
            model=settings.ollama_model,
            max_tokens=2000,
            temperature=0,   # greedy decode — critical for hallucination prevention
            top_p=1.0,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
    except Exception as e:
        raise RuntimeError(
            f"Ollama LLM call failed ({settings.ollama_base_url}, model={settings.ollama_model}): {e}. "
            "Is Ollama running? Try: ollama serve"
        ) from e

    narrative = response.choices[0].message.content or ""

    # Post-generation grounding check — warn if the LLM cited technique IDs
    # that were not in the provided ontology context block.
    provided_ids = {ctx["technique_id"] for ctx in ontology_context}
    _grounding_check(narrative, provided_ids)

    # Anti-fabrication check — flag any cited permission the APK doesn't
    # actually declare, and surface it in limitations so it reaches the
    # analyst rather than only the log.
    invented_permissions = _permission_check(narrative, set(manifest.permissions))
    if invented_permissions:
        limitations.append(
            "FABRICATION DETECTED: narrative cites permissions not declared by "
            f"this APK: {', '.join(invented_permissions)}. Treat the narrative "
            "as unverified and consult the structured manifest instead."
        )

    return narrative, limitations
