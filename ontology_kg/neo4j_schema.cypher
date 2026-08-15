// ============================================================
// GuardGraph AI — Neo4j Knowledge Graph Schema
// Owner: Sar (Ontology + Signature Dictionary)
// Run this FIRST in Neo4j Browser or via cypher-shell before loading any data.
// ============================================================

// ---- Uniqueness constraints (also creates indexes automatically) ----
CREATE CONSTRAINT sample_hash IF NOT EXISTS FOR (s:Sample) REQUIRE s.sha256 IS UNIQUE;
CREATE CONSTRAINT hash_value IF NOT EXISTS FOR (h:Hash) REQUIRE h.value IS UNIQUE;
CREATE CONSTRAINT cert_thumb IF NOT EXISTS FOR (c:Certificate) REQUIRE c.thumbprint IS UNIQUE;
CREATE CONSTRAINT package_name IF NOT EXISTS FOR (p:Package) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT permission_name IF NOT EXISTS FOR (p:Permission) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT api_signature IF NOT EXISTS FOR (a:API) REQUIRE a.signature IS UNIQUE;
CREATE CONSTRAINT behavior_id IF NOT EXISTS FOR (b:Behavior) REQUIRE b.behavior_id IS UNIQUE;
CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.tactic_id IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE;
CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (c:CAPECPattern) REQUIRE c.capec_id IS UNIQUE;
CREATE CONSTRAINT family_name IF NOT EXISTS FOR (f:MalwareFamily) REQUIRE f.name IS UNIQUE;
CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.mitigation_id IS UNIQUE;

// ============================================================
// Node label reference (for your team — not executable, just documentation)
// ============================================================
// :Sample          {sha256, package_name, first_seen, risk_score}
// :Hash            {value, algo}
// :Certificate     {thumbprint, issuer}
// :Package         {name}
// :Permission      {name, risk_weight}
// :API             {signature, category}          e.g. "Landroid/telephony/SmsManager;->sendTextMessage"
// :StringLiteral   {value, category}              e.g. otp, bank, C2 url
// :Behavior         {behavior_id, label, description}   e.g. STEALTH_SMS_INTERCEPTION
// :Tactic          {tactic_id, name}               e.g. TA0041 Collection
// :Technique       {technique_id, name}            e.g. T1636 Protected User Data
// :CAPECPattern    {capec_id, name}
// :MalwareFamily   {name, malware_type}            e.g. Wacatac / banker
// :Mitigation      {mitigation_id, description}
// :Report          {report_id, generated_at}

// ============================================================
// Relationship reference
// ============================================================
// (:Sample)-[:HAS_HASH]->(:Hash)
// (:Sample)-[:SIGNED_BY]->(:Certificate)
// (:Sample)-[:DECLARES_PERMISSION]->(:Permission)
// (:Sample)-[:CALLS_API]->(:API)
// (:Sample)-[:CONTAINS_STRING]->(:StringLiteral)
// (:API)-[:INDICATES_BEHAVIOR]->(:Behavior)
// (:Permission)-[:APK_REQUESTS_PERMISSION]->(:Behavior)
// (:Behavior)-[:BEHAVIOR_MAPS_TO_TTP]->(:Technique)
// (:Technique)-[:BELONGS_TO_TACTIC]->(:Tactic)
// (:Technique)-[:TTP_HAS_CAPEC_PATTERN]->(:CAPECPattern)
// (:CAPECPattern)-[:CONTROL_MITIGATES_BEHAVIOR]->(:Mitigation)
// (:Sample)-[:CLASSIFIED_AS_FAMILY]->(:MalwareFamily)
// (:MalwareFamily)-[:FAMILY_OBSERVED_IN_CAMPAIGN]->(:Report)
// (:Sample)-[:SAMPLE_SIMILAR_TO]->(:Sample)