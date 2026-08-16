"""
Unit and integration tests for the modular AnalysisPipeline phases.
Ensures that each of the seven phases can be called with correct arguments
and satisfies the expected schema contracts.
"""
import unittest
import sys
import os
import networkx as nx

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.pipeline import AnalysisPipeline
from app.core.schemas import (
    IngestionResult,
    ObfuscationSignal,
    BehavioralSubgraph,
    RiskScoreBreakdown
)
from app.ml.labels import TTP_LABELS
from app.ml.features import FEATURE_NAMES, TTP_FEATURE_NAMES, build_ttp_feature_vector

class TestAnalysisPipelinePhases(unittest.TestCase):
    def test_pipeline_methods_exist(self):
        """Verify that all phase methods are defined on AnalysisPipeline."""
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase1_ingestion"))
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase1b_signature_yara"))
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase2_graph_construction"))
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase3_forensic_matching"))
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase4_feature_engineering"))
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase5_ml_classification"))
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase6_risk_scoring"))
        self.assertTrue(hasattr(AnalysisPipeline, "run_phase7_reporting"))

    def test_phase4_feature_engineering_contract(self):
        """Verify phase 4 returns the expected types and BOTH feature vector sizes."""
        mock_ingestion = IngestionResult(
            sha256="bf8b77626a57e3f890cf2ad42c7f66a2e4d9e0344d51199a2245b08df23315a6",
            package_name="com.test.app",
            permissions=["android.permission.READ_SMS"]
        )
        mock_cfgs = {
            "Lcom/test/app/MainActivity;->onCreate()V": nx.DiGraph()
        }

        # Phase 4 now returns 5 values: obfuscation, family (35) vec, TTP (181) vec, density, nodes
        obfuscation, vec, ttp_vec, mean_density, total_nodes = AnalysisPipeline.run_phase4_feature_engineering(
            ingestion=mock_ingestion,
            cfgs=mock_cfgs,
            all_matches={},
            behavioral_subgraphs=[],
            all_strings=[],
            parse_failure_rate=0.0
        )

        self.assertIsInstance(obfuscation, ObfuscationSignal)
        self.assertIsInstance(vec, list)
        self.assertEqual(len(vec), len(FEATURE_NAMES))  # legacy family vector
        self.assertIsInstance(ttp_vec, list)
        self.assertEqual(len(ttp_vec), len(TTP_FEATURE_NAMES))  # multi-label TTP vector (181)
        self.assertEqual(mean_density, 0.0)
        self.assertEqual(total_nodes, 0)

    def test_phase5_ttp_classification_contract(self):
        """
        Phase 5 must return (predicted_ttps dict, family, confidence) with every TTP key
        a valid MITRE technique in TTP_LABELS and every prob in [0,1] — robust to whether
        the model is trained (degrades to empty on FileNotFoundError, never raises).
        """
        ttp_vec = build_ttp_feature_vector(
            permissions=["android.permission.READ_SMS"],
            api_calls=["Landroid/telephony/SmsManager;->sendTextMessage(...)"],
            matched_behaviors={"OTP_INTERCEPTION"},
        )
        family_vec = [0.0] * 33

        predicted_ttps, family, conf = AnalysisPipeline.run_phase5_ml_classification(ttp_vec, family_vec)

        self.assertIsInstance(predicted_ttps, dict)
        for tid, prob in predicted_ttps.items():
            self.assertIn(tid, TTP_LABELS)          # only real Mobile technique IDs
            self.assertGreaterEqual(prob, 0.0)
            self.assertLessEqual(prob, 1.0)
        self.assertTrue(family is None or isinstance(family, str))

    def test_phase6_zero_day_indicator(self):
        """Strong deterministic evidence + no model prediction ⇒ zero_day_indicator True;
        a benign sample ⇒ False."""
        obf_low = ObfuscationSignal(
            string_entropy_score=3.0, flattening_suspected=False, coverage_note="ok"
        )
        novel = AnalysisPipeline.run_phase6_risk_scoring(
            predicted_ttps={},  # model unfamiliar / untrained
            permissions=["android.permission.READ_SMS"],
            obfuscation=obf_low,
            all_matches={"STEALTH_SMS_INTERCEPTION": ["n1"], "OTP_INTERCEPTION": ["n2"]},
            cache_hit=False,
        )
        self.assertTrue(novel.zero_day_indicator)

        benign = AnalysisPipeline.run_phase6_risk_scoring(
            predicted_ttps={},
            permissions=["android.permission.INTERNET"],
            obfuscation=obf_low,
            all_matches={},
            cache_hit=False,
        )
        self.assertFalse(benign.zero_day_indicator)


    def test_phase6_risk_scoring_contract(self):
        """Verify phase 6 produces a valid RiskScoreBreakdown."""
        mock_obfuscation = ObfuscationSignal(
            string_entropy_score=5.5,
            flattening_suspected=False,
            coverage_note="No coverage gaps"
        )
        
        risk_score = AnalysisPipeline.run_phase6_risk_scoring(
            predicted_ttps={"T1636": 0.8},
            permissions=["android.permission.READ_SMS"],
            obfuscation=mock_obfuscation,
            all_matches={},
            cache_hit=False
        )
        
        self.assertIsInstance(risk_score, RiskScoreBreakdown)
        self.assertTrue(risk_score.total_score >= 0.0)
        self.assertIn(risk_score.verdict_band, ["low", "suspicious", "high", "malicious"])

if __name__ == "__main__":
    unittest.main()
