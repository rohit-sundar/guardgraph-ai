"""
SINGLE SOURCE OF TRUTH for the multi-label MITRE ATT&CK Mobile TTP output space.

This is to the TTP classifier what FEATURE_NAMES (features.py) is to the feature
vector: `TTP_LABELS` defines the *column order* of the model's multi-label output.
A Binary-Relevance model has no concept of label names at inference time — it
returns a probability per output index, and the index→technique mapping lives
here. If this order changes, the TTP model must be retrained.

FREEZE-BEFORE-TRAIN INVARIANT
    `TTP_LABELS` must be identical at training time and inference time. Treat this
    curated set as frozen once a model is trained against it. `scripts/build_ttp_label_space.py`
    can emit a richer/fuller technique list from the live ATT&CK Mobile STIX bundle
    (for ontology descriptions and coverage checks), but it does NOT silently
    rewrite this list — regenerate + review + commit deliberately, then retrain.

Design note (DroidTTP alignment): DroidTTP (arXiv:2503.15866) trained over ~48
Mobile techniques sourced from ATT&CK procedure references. We curate a comparable
banking-fraud-weighted set of real, current Mobile ATT&CK parent techniques. Rare
labels with too few positive samples are simply skipped by the trainer and always
predicted 0.0 by the classifier — so a broad label space is safe.
"""
from __future__ import annotations

import json
import os

from loguru import logger

# Curated MITRE ATT&CK **Mobile** technique set (parent techniques only), keyed by
# technique_id → (display name, primary tactic). Tactics use ATT&CK Mobile display
# names. This is the frozen classifier output contract.
_TECHNIQUE_CATALOG: dict[str, tuple[str, str]] = {
    # ── Initial Access ────────────────────────────────────────────────────
    "T1660": ("Phishing", "Initial Access"),
    "T1474": ("Supply Chain Compromise", "Initial Access"),
    # ── Execution ─────────────────────────────────────────────────────────
    "T1623": ("Command and Scripting Interpreter", "Execution"),
    "T1575": ("Native API", "Execution"),
    # ── Persistence ───────────────────────────────────────────────────────
    "T1624": ("Event Triggered Execution", "Persistence"),
    "T1625": ("Hijack Execution Flow", "Persistence"),
    "T1541": ("Foreground Persistence", "Persistence"),
    "T1398": ("Boot or Logon Initialization Scripts", "Persistence"),
    "T1661": ("Application Versioning", "Persistence"),
    # ── Privilege Escalation ──────────────────────────────────────────────
    "T1626": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    # ── Defense Evasion ───────────────────────────────────────────────────
    "T1406": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1628": ("Hide Artifacts", "Defense Evasion"),
    "T1629": ("Impair Defenses", "Defense Evasion"),
    "T1630": ("Indicator Removal on Host", "Defense Evasion"),
    "T1631": ("Process Injection", "Defense Evasion"),
    "T1632": ("Subvert Trust Controls", "Defense Evasion"),
    "T1633": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1655": ("Masquerading", "Defense Evasion"),
    "T1627": ("Execution Guardrails", "Defense Evasion"),
    # ── Credential Access ─────────────────────────────────────────────────
    "T1634": ("Credentials from Password Store", "Credential Access"),
    "T1635": ("Steal Application Access Token", "Credential Access"),
    "T1417": ("Input Capture", "Credential Access"),
    # ── Discovery ─────────────────────────────────────────────────────────
    "T1418": ("Software Discovery", "Discovery"),
    "T1420": ("File and Directory Discovery", "Discovery"),
    "T1421": ("System Network Connections Discovery", "Discovery"),
    "T1422": ("System Network Configuration Discovery", "Discovery"),
    "T1424": ("Process Discovery", "Discovery"),
    "T1426": ("System Information Discovery", "Discovery"),
    # ── Collection ────────────────────────────────────────────────────────
    "T1636": ("Protected User Data", "Collection"),
    "T1409": ("Stored Application Data", "Collection"),
    "T1429": ("Audio Capture", "Collection"),
    "T1512": ("Video Capture", "Collection"),
    "T1513": ("Screen Capture", "Collection"),
    "T1414": ("Clipboard Data", "Collection"),
    "T1533": ("Data from Local System", "Collection"),
    "T1517": ("Access Notifications", "Collection"),
    "T1430": ("Location Tracking", "Collection"),
    "T1638": ("Adversary-in-the-Middle", "Collection"),
    # ── Command and Control ───────────────────────────────────────────────
    "T1437": ("Application Layer Protocol", "Command and Control"),
    "T1521": ("Encrypted Channel", "Command and Control"),
    "T1509": ("Non-Standard Port", "Command and Control"),
    "T1481": ("Web Service", "Command and Control"),
    "T1604": ("Proxy Through Victim", "Command and Control"),
    "T1637": ("Dynamic Resolution", "Command and Control"),
    "T1644": ("Out of Band Data", "Command and Control"),
    # ── Exfiltration ──────────────────────────────────────────────────────
    "T1646": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1639": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    # ── Impact ────────────────────────────────────────────────────────────
    "T1471": ("Data Encrypted for Impact", "Impact"),
    "T1582": ("SMS Control", "Impact"),
    "T1616": ("Call Control", "Impact"),
    "T1516": ("Input Injection", "Impact"),
    "T1640": ("Account Access Removal", "Impact"),
    "T1641": ("Data Manipulation", "Impact"),
    "T1642": ("Endpoint Denial of Service", "Impact"),
    "T1643": ("Generate Traffic from Victim", "Impact"),
    "T1662": ("Data Destruction", "Impact"),
    "T1472": ("Generate Fraudulent Advertising Revenue", "Impact"),
}

# Frozen output order: sorted technique IDs. Sorting keeps the contract stable and
# reproducible regardless of dict insertion order.
TTP_LABELS: list[str] = sorted(_TECHNIQUE_CATALOG.keys())

# technique_id → tactic (display name). Used by risk scoring's tactic-derived
# severity so every predicted technique has a principled severity, not DEFAULT.
TECHNIQUE_TACTIC: dict[str, str] = {tid: _TECHNIQUE_CATALOG[tid][1] for tid in TTP_LABELS}

# technique_id → human-readable technique name.
TECHNIQUE_NAME: dict[str, str] = {tid: _TECHNIQUE_CATALOG[tid][0] for tid in TTP_LABELS}


def load_full_technique_ontology(
    path: str = "data/ontology/mobile_techniques.json",
) -> list[dict]:
    """
    Loads the richer technique ontology emitted by scripts/build_ttp_label_space.py
    (technique_id, name, tactic, description, is_subtechnique) when present.

    Used by the Neo4j ontology loader for GraphRAG grounding descriptions. This is
    NOT the classifier contract — TTP_LABELS above is. Returns [] if the file has
    not been generated yet (so callers degrade to the baked-in catalog).
    """
    if not os.path.exists(path):
        logger.warning(
            f"[labels] Full technique ontology not found at {path}. "
            "Run scripts/build_ttp_label_space.py to generate it; falling back "
            "to the baked-in catalog."
        )
        return [
            {
                "technique_id": tid,
                "name": TECHNIQUE_NAME[tid],
                "tactic": TECHNIQUE_TACTIC[tid],
                "description": "",
                "is_subtechnique": "." in tid,
            }
            for tid in TTP_LABELS
        ]
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
