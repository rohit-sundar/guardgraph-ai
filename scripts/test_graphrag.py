import sys
import os
import json

# Setup sys.path to root directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.schemas import AnalysisManifest, RiskScoreBreakdown, ObfuscationSignal, BehavioralSubgraph
from app.reports.graphrag import generate_report

def main():
    print("Constructing mock AnalysisManifest and RiskScoreBreakdown...")
    
    # Mock some behavior subgraphs
    subgraphs = [
        BehavioralSubgraph(
            subgraph_id="SUB_Lcom/malware/sms/Receiver;->onReceive_STEALTH_SMS_INTERCEPTION",
            primary_behavior_flag="STEALTH_SMS_INTERCEPTION",
            matched_apis=["android/telephony/SmsMessage;->getMessageBody", "android/content/BroadcastReceiver;->abortBroadcast"],
            topological_invariants={
                "degree_centrality_mean": 0.45,
                "closeness_centrality_mean": 0.52,
                "clustering_coefficient_mean": 0.12
            },
            subgraph_size_ratio=0.35
        )
    ]
    
    obfuscation = ObfuscationSignal(
        string_entropy_score=7.45,  # High entropy
        flattening_suspected=True,
        flattening_outlier_nodes=["Lcom/malware/sms/Receiver;->decrypt"],
        reflection_call_count=12,
        unresolved_reflection_targets=5,
        method_parse_failure_rate=0.08,
        coverage_note="8% of methods failed parsing due to control flow obfuscation. 5 reflection targets unresolved."
    )
    
    manifest = AnalysisManifest(
        target_package="com.secure.banking.helper",
        sha256="bf8b77626a57e3f890cf2ad42c7f66a2e4d9e0344d51199a2245b08df23315a6",
        cache_hit=False,
        total_nodes_parsed=1420,
        graph_density=0.0035,
        behavioral_subgraphs=subgraphs,
        obfuscation=obfuscation,
        predicted_ttps={
            "T1636": 0.89,  # Protected User Data (SMS)
            "T1417": 0.75   # Input Capture
        },
        predicted_family="banker",
        family_confidence=0.89
    )
    
    risk_score = RiskScoreBreakdown(
        classifier_confidence_component=26.7,
        permission_api_component=15.0,
        ttp_severity_component=18.0,
        forensic_anchor_component=15.0,
        obfuscation_component=12.0,
        reputation_component=0.0,
        ioc_component=0.0,
        total_score=86.7,
        verdict_band="Malicious"
    )
    
    print("Calling generate_report using local Ollama model...")
    try:
        narrative, limitations, _grounding = generate_report(manifest, risk_score)
        print("\n=== REPORT GENERATION SUCCESSFUL ===")
        print(f"Limitations: {limitations}")
        print("\n=== NARRATIVE REPORT ===")
        print(narrative)
        print("========================")
    except Exception as e:
        print(f"\nERROR: Failed to generate report: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
