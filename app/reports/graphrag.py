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
Hallucination-checking is still manual — local 7B models are more prone to
drifting from the system prompt than Claude; spot-check every new report
format against the curated demo set before trusting output.
"""
import json
from openai import OpenAI

from app.core.config import settings
from app.core.schemas import AnalysisManifest, RiskScoreBreakdown
from app.graph.ontology import get_technique_context

SYSTEM_PROMPT = """You are a cybersecurity analyst report generator for GuardGraph AI,
a banking-focused Android malware analysis engine.

STRICT RULES:
1. Only state findings that are explicitly present in the provided JSON manifest,
   risk score breakdown, or MITRE ontology context. Never invent evidence.
2. If something is not covered by the provided data (e.g. native code was not
   analyzed, or a technique has low confidence), say so explicitly using
   phrasing like "not observed" or "not statically resolved" — do not guess.
3. Clearly separate deterministic findings (hash matches, permission declarations,
   matched APIs) from model predictions (classifier confidence, predicted TTPs).
4. Always include the confidence value alongside any predicted TTP.
5. End with a "Recommended Analyst Actions" section in priority order.
6. Do not use hedging filler language beyond what's needed for genuine uncertainty.
7. If the risk score breakdown has "zero_day_indicator": true, prominently flag this as a
   POSSIBLE NOVEL / ZERO-DAY VARIANT. Explain that the verdict rests on model-free evidence
   (deterministic matched APIs/permissions and/or structural obfuscation/coverage signals)
   while the classifier has low familiarity with this sample — not on classifier confidence.
Write for a bank fraud-operations audience: clear, direct, actionable.
"""


def generate_report(
    manifest: AnalysisManifest,
    risk_score: RiskScoreBreakdown,
) -> tuple[str, list[str]]:
    """
    Returns (narrative_report_text, limitations_list).

    Requires a running Ollama instance:
        ollama serve          # if not already running as a service
        ollama pull qwen2.5:7b-instruct-q4_K_M
    """
    technique_ids = list(manifest.predicted_ttps.keys())
    ontology_context = get_technique_context(technique_ids) if technique_ids else []

    limitations = [manifest.obfuscation.coverage_note]
    if manifest.obfuscation.unresolved_reflection_targets > 0:
        limitations.append(
            f"{manifest.obfuscation.unresolved_reflection_targets} reflection-based "
            "API calls could not be statically resolved to their real target."
        )

    user_prompt = f"""
Generate an analyst report from the following grounded data. Do not use any
information beyond what's given here.

## JSON Manifest
{manifest.model_dump_json(indent=2)}

## Risk Score Breakdown
{risk_score.model_dump_json(indent=2)}

## MITRE ATT&CK Mobile Ontology Context (verified facts, safe to cite)
{json.dumps(ontology_context, indent=2)}

## Known Coverage Limitations (state these explicitly in the report)
{json.dumps(limitations, indent=2)}
"""

    # Ollama exposes an OpenAI-compatible API — no real key needed.
    client = OpenAI(
        base_url=settings.ollama_base_url,
        api_key="ollama",  # required by the client constructor; ignored by Ollama
    )
    try:
        response = client.chat.completions.create(
            model=settings.ollama_model,
            max_tokens=2000,
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

    return narrative, limitations
