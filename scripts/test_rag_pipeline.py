"""
Standalone test harness for the RAG pipeline.
Allows AI Engineers to iterate on the LLM prompt and Ollama integration
without needing to run the full static analysis (Androguard) pipeline.
"""
import sys
import os

# Ensure the app module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.schemas import AnalysisManifest, RiskScoreBreakdown, ObfuscationSignal, BehavioralSubgraph


def _install_ontology_stub():
    """
    Replaces the Neo4j-backed ontology lookup with fixed text so this harness
    runs without a database, then imports graphrag AFTERWARDS — graphrag binds
    the function with `from ... import get_technique_context`, so the stub only
    takes effect if it is in place before that import runs.

    Both the patch and the import live in here, called from main(), rather than
    at module scope. This file's name matches pytest's `test_*.py` discovery
    pattern, so a bare `pytest` from the repo root COLLECTS AND IMPORTS it —
    and a module-level patch of a real module is never undone, silently
    replacing the ontology lookup for every test that runs afterwards in the
    same process. That produced a genuine, confusing failure: a cache-hit test
    unrelated to this file received this dict, iterated it, and got the keys as
    strings. Any import-time mutation of application state is unsafe here for
    the same reason; keep side effects inside functions.
    """
    import app.graph.ontology
    app.graph.ontology.get_technique_context = lambda t: {
        "T1636": "Stealth SMS Interception: Intercepting incoming SMS messages for OTP theft.",
        "T1417": "Input Capture: Capturing user input (e.g. credentials) via overlays or keylogging.",
        "T1624": "Screen Capture: Capturing the screen to steal sensitive data."
    }
    from app.reports.graphrag import generate_report
    return generate_report


def main():
    generate_report = _install_ontology_stub()
    print("🚀 Initializing RAG Test Harness...")

    # 1. Create Mock Obfuscation Signal
    mock_obfuscation = ObfuscationSignal(
        string_entropy_score=7.8,
        flattening_suspected=True,
        flattening_outlier_nodes=["node_452", "node_991"],
        reflection_call_count=12,
        unresolved_reflection_targets=4,
        method_parse_failure_rate=0.15,
        coverage_note="4 reflection call targets not statically resolved; 15.0% of relevant methods failed CFG parsing — analysis coverage reduced; possible heavy obfuscation"
    )

    # 2. Create Mock Behavioral Subgraphs
    mock_subgraphs = [
        BehavioralSubgraph(
            subgraph_id="SUB_Lcom/bank/login;->submit()_1",
            primary_behavior_flag="CREDENTIAL_HARVESTING",
            matched_apis=["Landroid/webkit/WebView;->loadUrl", "Landroid/widget/EditText;->getText"],
            topological_invariants={"degree_centrality_mean": 0.45, "closeness_centrality_mean": 0.6},
            subgraph_size_ratio=0.25
        ),
        BehavioralSubgraph(
            subgraph_id="SUB_Lcom/stealth/sms;->intercept()_2",
            primary_behavior_flag="STEALTH_SMS_INTERCEPTION",
            matched_apis=["Landroid/telephony/SmsManager;->sendTextMessage"],
            topological_invariants={"degree_centrality_mean": 0.8, "closeness_centrality_mean": 0.9},
            subgraph_size_ratio=0.10
        )
    ]

    # 3. Create Mock Manifest
    mock_manifest = AnalysisManifest(
        target_package="com.fake.banking.app",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        cache_hit=False,
        total_nodes_parsed=1450,
        graph_density=0.034,
        behavioral_subgraphs=mock_subgraphs,
        obfuscation=mock_obfuscation,
        predicted_ttps={"T1636": 0.82, "T1417": 0.75, "T1624": 0.90},
        predicted_family="banker",
        family_confidence=0.92
    )

    # 4. Create Mock Risk Score
    mock_risk_score = RiskScoreBreakdown(
        classifier_confidence_component=23.0,
        permission_api_component=18.5,
        ttp_severity_component=13.0,
        forensic_anchor_component=14.5,
        obfuscation_component=15.0,
        reputation_component=1.5,
        ioc_component=2.0,
        total_score=87.5,
        verdict_band="malicious"
    )

    print("\n[Mock Data Prepared] Invoking generate_report()...")
    print("Ensure Ollama is running (`ollama serve`)!\n")

    try:
        narrative, limitations, _grounding = generate_report(manifest=mock_manifest, risk_score=mock_risk_score)
        
        print("================ REPORT GENERATED ================\n")
        print(narrative)
        print("\n================ LIMITATIONS ================\n")
        for lim in limitations:
            print(f"- {lim}")
            
    except Exception as e:
        print(f"\n❌ Error generating report: {e}")

if __name__ == "__main__":
    main()
