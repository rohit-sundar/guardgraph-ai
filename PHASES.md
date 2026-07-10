# GuardGraph AI — Processing Phases

This document describes the 7 sequential static analysis execution phases that construct the processing pipeline in the cold path.

```mermaid
graph TD
    A[Phase 1: Ingestion & Metadata] --> B[Phase 2: Graph Representation]
    B --> C[Phase 3: Forensic Anchor Extraction]
    C --> D[Phase 4: Feature Engineering]
    D --> E[Phase 5: ML Classification]
    E --> F[Phase 6: Risk Scoring]
    F --> G[Phase 7: GraphRAG Reporting]
```

## Phase Descriptions

### Phase 1: Ingestion & Metadata Extraction
- **Module**: `app/analysis/ingest.py`
- **Actions**: Computes SHA-256 hash of the APK file, extracts certificate thumbprints, and parses the Android Manifest file to read permissions, activities, services, and receivers.
- **Trigger**: Called in both hot and cold paths.

### Phase 2: Graph Representation
- **Module**: `app/analysis/cfg.py`
- **Actions**: Builds Control Flow Graphs (CFGs) for each class method using Androguard and represents them in memory as NetworkX directed graphs, enriching nodes with Attributed CFG (ACFG) features.

### Phase 3: Forensic Anchor Extraction
- **Module**: `app/analysis/forensic.py`
- **Actions**: Scans the method CFGs against the forensic dictionary to identify sensitive "anchor" APIs (e.g. BroadcastReceivers, SMS interception calls) and extracts 4-hop subgraphs around these anchor nodes.

### Phase 4: Feature Engineering
- **Module**: `app/analysis/topology.py` and `app/analysis/obfuscation.py`
- **Actions**: Computes topological invariants (degree, closeness, and clustering metrics) for the behavioral subgraphs and extracts obfuscation indicators (Shannon entropy, z-scores for control-flow flattening, and parse failure rates).

### Phase 5: Machine Learning Classification
- **Module**: `app/ml/classifier.py`
- **Actions**: Feeds the compiled feature vector into the XGBoost classifier to predict the threat/malware family (e.g., banker, rat) and maps the classification to MITRE ATT&CK Mobile techniques.

### Phase 6: Risk Scoring
- **Module**: `app/reports/scoring.py`
- **Actions**: Computes the weighted risk score formula (0–100) and maps the sample to its final verdict band (Low, Suspicious, High, Malicious).

### Phase 7: GraphRAG Reporting
- **Module**: `app/reports/graphrag.py`
- **Actions**: Queries Neo4j for predicted TTPs, retrieves ATT&CK/CAPEC details, and formats this grounded data to generate an analyst report via a local Ollama model (Qwen 2.5 7B-Instruct).
