"""
Main /analyze endpoint. Orchestrates the full cold/hot path pipeline:

  upload -> hash -> cache lookup (hot path) OR
  ingest -> CFG/ACFG -> anchor detection -> topology -> obfuscation ->
  classify -> score -> GraphRAG report (cold path)

This is intentionally synchronous for the prototype — no Celery/queue.
A cold-path analysis on a real APK will take several seconds; that's
acceptable for a demo. Do not "optimize" this before it's needed.

Changes vs. original skeleton:
- §9.1: hot path now truly short-circuits before build_all_method_cfgs.
- §9.2: predicted_ttps derived from FAMILY_TO_TTPS bridge, not raw family names.
- §9.3: matched_anchor_behaviors passed to compute_risk_score directly.
- §9.4: graph_density now computed as mean per-method density (not global sum).
- §9.5/9.6: method_parse_failure_rate threaded from cfg.py → obfuscation signal.
- §9.7: subgraph_size_ratio recorded per BehavioralSubgraph for tuning data.
- The TTP classifier only votes when the analysis actually observed something —
  it was trained without a benign class and answers confidently regardless.
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import uuid

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from loguru import logger

from app.graph.cache import lookup_signature, store_signature, find_related_samples, get_threat_landscape, list_recent_samples
from app.graph.ontology import get_technique_context
from app.ml.classifier import ttp_classifier
from app.reports.scoring import compute_risk_score, _band_for
from app.core import progress
from app.core.config import settings
from app.core.schemas import AnalysisManifest, AnalysisReport, ObfuscationSignal, RiskScoreBreakdown, SignatureYaraResult

router = APIRouter()


def _ttp_thresholds() -> dict[str, float]:
    """
    The trained bundle's per-label decision thresholds (0.10-0.90, calibrated per
    technique on the validation split — see train_model.py). Read here rather than
    only inside scoring so the MITRE tab can show the SAME boundary the score was
    computed against, instead of rendering every prediction as if it cleared a
    flat 0.5 cut. {} for an untrained bundle; callers fall back to the global
    default per-technique in that case.
    """
    try:
        return ttp_classifier.thresholds()
    except (FileNotFoundError, KeyError, Exception) as e:
        logger.warning(f"Per-label TTP thresholds unavailable for the UI: {e}")
        return {}


def _build_ttp_context(predicted_ttps: dict[str, float]) -> list[dict]:
    """
    Merges predicted_ttps (technique_id -> probability) with MITRE ATT&CK Mobile
    ontology facts (name/tactic/description) via the same get_technique_context()
    GraphRAG grounds its narrative in — so the UI can never show a technique name
    the LLM wasn't also given. Sorted by probability descending.

    Also carries each technique's own decision threshold, so the MITRE tab can
    draw a tick mark on the confidence bar at the boundary that ACTUALLY governed
    whether this row surfaced — prevalence across the 32 trained labels ranges
    0.10-0.90 (train_model.py's THRESHOLD_GRID), so a 0.98 on a 0.10-threshold
    label and a 0.98 on a 0.90-threshold one are not the same margin of evidence,
    even though both currently render as an identical percentage bar.
    """
    if not predicted_ttps:
        return []
    context = get_technique_context(list(predicted_ttps.keys()))
    thresholds = _ttp_thresholds()
    rows = [
        {
            **ctx,
            "probability": predicted_ttps.get(ctx["technique_id"], 0.0),
            "threshold": thresholds.get(ctx["technique_id"], TTP_PREDICT_THRESHOLD),
        }
        for ctx in context
    ]
    rows.sort(key=lambda r: r["probability"], reverse=True)
    return rows

# Score assigned when the APK cannot be parsed at all. Deliberately mid-band
# ("suspicious") rather than 0: a file that defeats Androguard's AXML parser or
# carries a corrupted ZIP central directory is usually doing so on purpose, and
# reporting "low" on an anti-analysis sample is the worse error. It is not scored
# higher either, because nothing was actually observed — no anchors, no
# permissions, no IoCs. The band says "look at this by hand", which is the truth.
# Still true with the `medium` band in between `low` and `suspicious`
# (scoring.BAND_MEDIUM_CEILING = 40.0): 50.0 sits above it, so this constant keeps
# reading "suspicious", not "medium" — pinned by
# test_unparseable_score_still_reads_suspicious.
UNPARSEABLE_RISK_SCORE = 50.0

# Upload ceiling shared by /analyze and /analyze/start. Google Play's own limit
# for a base APK is 100 MB (larger apps ship as split bundles), so 150 MB accepts
# anything this analyzer is meant to see while bounding what a single
# unauthenticated request can make the server hold.
MAX_UPLOAD_BYTES = 150 * 1024 * 1024
_UPLOAD_CHUNK_BYTES = 1024 * 1024


async def _save_upload_bounded(file: UploadFile, tmp_path: str) -> None:
    """
    Streams an upload to disk under MAX_UPLOAD_BYTES rather than `await file.read()`
    — /analyze and /analyze/start are both unauthenticated and their input is
    hostile by definition, so reading a whole attacker-chosen body into memory
    first is a free memory-exhaustion DoS. Writing in chunks also means an
    oversized upload is rejected partway through instead of after it has already
    been buffered in full.
    """
    size = 0
    with open(tmp_path, "wb") as f:
        while chunk := await file.read(_UPLOAD_CHUNK_BYTES):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    413,
                    f"APK exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.",
                )
            f.write(chunk)


@router.get("/graph/landscape")
async def graph_landscape(limit: int = 30):
    """
    Cytoscape-ready snapshot of the whole correlation graph (Sample/
    MalwareFamily/Technique/C2Indicator/Certificate) for the UI's "Threat
    Landscape" tab — not tied to any single analysis run.
    """
    return get_threat_landscape(limit=limit)


_TTP_METRICS_PATH = "data/models/ttp_metrics.json"


@router.get("/model/metrics")
async def model_metrics():
    """
    Serves the TTP classifier's own training-time evaluation, not tied to any
    analysis run — this is what backs the "Model Accuracy" panel on the Risk
    Scoring tab.

    Deliberately surfaces BOTH numbers side by side rather than only the
    flattering one: `stratified` is comparable to what most published
    DroidTTP-style multi-label malware papers report, but on this dataset it is
    measuring family memorisation — every malware row's label comes from its
    family's ATT&CK software entry, so a split stratified on labels puts
    identical label vectors on both sides of the train/test boundary by
    construction. `family_held_out` is a GroupKFold evaluation where every fold
    holds a whole family out, so it can only be measured on families the model
    never trained on — that is the number that means something about a real
    unseen sample, and it is honestly much lower (see train_model.py's
    FAMILY_CV_SPLITS docstring for the full derivation).

    Returns {"trained": false} rather than 404/500 when the bundle hasn't been
    trained yet — this is a status the UI renders a message for, not an error.
    """
    if not os.path.exists(_TTP_METRICS_PATH):
        return {"trained": False}

    try:
        with open(_TTP_METRICS_PATH, encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"ttp_metrics.json unreadable: {e}")
        return {"trained": False}

    family_held_out = m.get("family_held_out") or {}
    return {
        "trained": True,
        "n_samples": m.get("n_samples"),
        "n_labels": m.get("n_labels"),
        "trained_labels": len(m.get("trained_labels") or []),
        "dropped_labels": len(m.get("dropped_labels") or []),
        "stratified": m.get("binary_relevance"),
        "family_held_out": (
            {k: v for k, v in family_held_out.items() if k != "folds"}
            if "error" not in family_held_out else None
        ),
        "family_held_out_error": family_held_out.get("error"),
    }


@router.get("/analyses")
async def list_analyses(limit: int = 30):
    """
    Summary rows for the Analysis History panel — every sample this instance has
    ever produced a verdict for, most-recently-touched first. Backed entirely by
    Neo4j Sample nodes; no APK needs to still exist on disk.
    """
    rows = list_recent_samples(limit=limit)
    return [
        {
            "sha256": r["sha256"],
            "app_name": r.get("app_name") or r.get("package_name") or r["sha256"],
            "family": r.get("family") or None,
            "risk_score": r.get("risk_score"),
            "verdict_band": _band_for(r["risk_score"]) if r.get("risk_score") is not None else None,
            "analyzed_at": r.get("analyzed_at"),
        }
        for r in rows
    ]


@router.get("/analyses/{sha256}", response_model=AnalysisReport)
async def get_analysis(sha256: str):
    """
    Reconstructs a past verdict from Neo4j ALONE — unlike the hot-path cache hit
    inside _run_analysis, there is no uploaded file here to re-ingest, so the
    manifest fields that only ever came from re-parsing the APK (cert_anomalies,
    accessibility_flags, exported_risks, payload_assets, dropper_signals,
    resolved_*, app_label/icon_phash, impersonation) are not recoverable and are
    left empty rather than guessed. The limitations list says so explicitly, the
    same honesty policy the unparseable-APK path already follows: a field reading
    empty here means "not available for a historical record", not "not present
    in the sample".
    """
    cached = lookup_signature(sha256)
    if cached is None:
        raise HTTPException(404, f"No stored analysis for {sha256}.")

    cached_score = cached.get("base_score")
    cached_ttps = cached.get("ttps") or {}
    total_score = cached_score if cached_score is not None else 0.0

    rc = cached.get("risk_components") or {}
    risk_score = RiskScoreBreakdown(
        classifier_confidence_component=rc.get("classifier_confidence_component"),
        permission_api_component=rc.get("permission_api_component"),
        ttp_severity_component=rc.get("ttp_severity_component"),
        forensic_anchor_component=rc.get("forensic_anchor_component"),
        obfuscation_component=rc.get("obfuscation_component"),
        reputation_component=rc.get("reputation_component"),
        ioc_component=rc.get("ioc_component"),
        total_score=total_score,
        verdict_band=_band_for(total_score),
        zero_day_indicator=rc.get("zero_day_indicator", False),
        impersonation_floor_applied=rc.get("impersonation_floor_applied", False),
        weighted_score=rc.get("weighted_score"),
    )

    cached_obf_data = cached.get("obfuscation_data")
    obfuscation = ObfuscationSignal(**cached_obf_data) if cached_obf_data else _empty_obfuscation_signal()

    cached_sig_yara_data = cached.get("signature_yara_data")
    signature_yara = SignatureYaraResult(**cached_sig_yara_data) if cached_sig_yara_data else None

    manifest = AnalysisManifest(
        target_package=cached.get("package_name"),
        sha256=sha256,
        cache_hit=True,
        total_nodes_parsed=0,
        graph_density=0.0,
        behavioral_subgraphs=[],
        obfuscation=obfuscation,
        predicted_ttps=cached_ttps,
        predicted_family=cached.get("family") or None,
        family_confidence=None,
        ttp_context=_build_ttp_context(cached_ttps),
        related_samples=find_related_samples(
            list(cached_ttps.keys()), cached.get("c2_indicators") or [],
            exclude_sha256=sha256,
            cert_thumbprint=cached.get("cert_thumbprint"),
        ),
        signature_yara=signature_yara,
        permissions=cached.get("permissions") or [],
        c2_indicators=cached.get("c2_indicators") or [],
    )

    narrative = cached.get("narrative") or "[No narrative stored for this sample.]"
    limitations = list(cached.get("limitations") or []) + [
        "HISTORICAL RECORD: reconstructed from the stored verdict, not the original "
        "APK — fields that only ever came from re-parsing the file (certificate "
        "anomalies, accessibility flags, exported components, payload assets, "
        "dropper signals, resolved crypto/DCL/WebView/native findings, brand "
        "impersonation, app identity) are not recoverable and read empty here "
        "rather than being guessed. Re-upload the sample for a full current analysis."
    ]

    return AnalysisReport(
        manifest=manifest,
        risk_score=risk_score,
        narrative_report=narrative,
        limitations=limitations,
    )


def _analyze_with_fallback(filepath: str, job_id: str | None = None) -> AnalysisReport:
    """
    Shared body of both analysis entry points: run the pipeline, and if the APK
    defeats it entirely, fall back to the mid-band "look at this by hand" report
    instead of a raw 500. Synchronous — callers are responsible for getting it off
    the event loop (run_in_threadpool for the blocking HTTP path, a plain
    background thread for the SSE job path; see /analyze/start below).
    """
    try:
        return _run_analysis(filepath, job_id=job_id)
    except Exception as exc:
        logger.error(f"Unparseable APK fallback triggered: {exc}")
        return _unparseable_report(filepath, exc)


@router.post("/analyze", response_model=AnalysisReport)
async def analyze(file: UploadFile = File(...)):
    """
    Synchronous: blocks until the full report is ready. This is what curl, the
    README's quickstart, and scripts/test_upload.py use — kept exactly as it was
    for anything that isn't the browser UI. The UI itself uses /analyze/start +
    /analyze/stream below, which is the same pipeline with real progress attached.
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "Only .apk files are supported in this prototype.")

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}.apk")

    try:
        await _save_upload_bounded(file, tmp_path)

        # _analyze_with_fallback is fully synchronous and takes minutes. Called
        # directly inside `async def` it blocks the event loop for its whole
        # duration — the server stops answering everything, /health included, so
        # a second person uploading sees a dead application rather than a queue.
        result = await run_in_threadpool(_analyze_with_fallback, tmp_path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


# ── Streamed progress (SSE) ─────────────────────────────────────────────────
#
# The UI previously showed a progress bar driven by simulatePipelineProgress() —
# fixed setTimeout delays with no connection to the real pipeline, reaching 95%
# and sitting there however long the analysis actually took. These two endpoints
# replace it with the pipeline's own phase boundaries (app/core/progress.py),
# streamed to the browser as they actually happen.
#
# Two endpoints instead of one, because SSE needs the client to already be
# holding a job_id before the long-running work starts, and a single POST
# can't hand back an id AND stream from the same request:
#   1. POST /analyze/start   — saves the upload, starts the analysis on a
#                              background thread, returns {job_id} in
#                              milliseconds.
#   2. GET  /analyze/stream/{job_id} — the browser opens this immediately after
#                              receiving job_id; it relays progress events and,
#                              as its final event, the complete AnalysisReport.
#
# /analyze itself is untouched and stays fully synchronous — see its docstring.

# job_id -> {"status": "running" | "complete" | "error", "result": dict | None,
#            "error": str | None}. Deliberately a plain process-lifetime dict, not
# Neo4j or a real job queue: a hackathon prototype's demo session lives entirely
# in one process, and a restart already discards in-flight uploads regardless.
# Entries are popped by the stream endpoint once delivered, so this only grows
# by jobs whose stream was never opened.
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()


def _run_background_job(tmp_dir: str, tmp_path: str, job_id: str) -> None:
    """
    Runs on a plain threading.Thread (not run_in_threadpool/anyio) because nothing
    here is awaiting the result inside the request that started it — the request
    already returned. Cleans up the temp upload itself, since no `finally` in the
    request handler will run after this point.
    """
    try:
        report = _analyze_with_fallback(tmp_path, job_id=job_id)
        with _JOBS_LOCK:
            _JOBS[job_id] = {"status": "complete", "result": report.model_dump(mode="json")}
        progress.emit_final(job_id, "complete")
    except Exception as exc:  # last-resort guard: a bug here must not hang the stream forever
        logger.error(f"[progress] background analysis {job_id} crashed: {exc}")
        with _JOBS_LOCK:
            _JOBS[job_id] = {"status": "error", "error": str(exc)}
        progress.emit_final(job_id, "error", str(exc))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/analyze/start")
async def analyze_start(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "Only .apk files are supported in this prototype.")

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}.apk")
    try:
        await _save_upload_bounded(file, tmp_path)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    job_id = uuid.uuid4().hex
    progress.broker.create(job_id)
    with _JOBS_LOCK:
        _JOBS[job_id] = {"status": "running", "result": None}

    threading.Thread(
        target=_run_background_job, args=(tmp_dir, tmp_path, job_id),
        name=f"analyze-{job_id[:8]}", daemon=True,
    ).start()

    return {"job_id": job_id}


@router.get("/analyze/stream/{job_id}")
async def analyze_stream(job_id: str):
    if not progress.broker.exists(job_id):
        raise HTTPException(404, "Unknown or expired job_id.")

    async def event_source():
        # Only True once the terminal event has actually completed a `yield` back
        # to the client. A disconnected browser's EventSource retries the SAME
        # GET automatically, and this generator is torn down by an exception
        # (GeneratorExit / CancelledError) at whatever point that disconnect is
        # noticed. Cleanup runs ONLY on the confirmed-delivered path; otherwise
        # both registries are left intact so the reconnect can still receive the
        # completion event instead of "Unknown or expired job_id" on an analysis
        # that is still running, or already finished, server-side.
        #
        # Completion is read from _JOBS rather than from the progress queue's
        # "final" marker, deliberately: broker.try_get() DEQUEUES — if that final
        # marker were consumed here and the yield below then failed to reach a
        # client that disconnected at that exact instant, the marker would be
        # gone and a reconnect would poll forever. A plain dict lookup has no such
        # failure mode, so it is the single source of truth for "is this done";
        # the queue is used only for the (loseable-without-harm) progress ticks.
        delivered_final = False
        try:
            while True:
                event = progress.broker.try_get(job_id)
                if event is not None and not event.get("final"):
                    yield f"event: progress\ndata: {json.dumps(event)}\n\n"
                    continue

                with _JOBS_LOCK:
                    job = _JOBS.get(job_id)
                if job is not None and job.get("status") in ("complete", "error"):
                    payload = {
                        "phase": "final",
                        "name": "Complete" if job["status"] == "complete" else "Failed",
                        "final": True,
                        **job,
                    }
                    yield f"event: complete\ndata: {json.dumps(payload)}\n\n"
                    delivered_final = True
                    return

                await asyncio.sleep(0.15)
        finally:
            if delivered_final:
                progress.broker.discard(job_id)
                with _JOBS_LOCK:
                    _JOBS.pop(job_id, None)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Disables response buffering on nginx-fronted deployments; harmless
            # and inert when served directly by uvicorn, as in this prototype.
            "X-Accel-Buffering": "no",
        },
    )


def _unparseable_report(filepath: str, exc: BaseException) -> AnalysisReport:
    """
    Builds the verdict returned when static analysis cannot complete.

    The SHA-256 is recomputed from the raw bytes — it needs no parsing and is the
    one fact still available, so the analyst can pivot to threat intel on the hash
    even though nothing was extracted from the file. The sample is NOT cached: a
    parse failure is a property of this analyzer, not a verdict worth replaying on
    the hot path after the underlying cause is fixed.
    """
    from app.analysis.ingest import compute_sha256
    from app.analysis.failure_diagnostics import probable_cause

    try:
        sha256 = compute_sha256(filepath)
    except Exception:  # unreadable temp file — nothing left to report on
        sha256 = ""

    label, explanation = probable_cause(exc)
    raw_reason = f"{type(exc).__name__}: {exc}"
    obfuscation = ObfuscationSignal(
        string_entropy_score=0.0,
        flattening_suspected=False,
        flattening_outlier_nodes=[],
        reflection_call_count=0,
        unresolved_reflection_targets=0,
        method_parse_failure_rate=1.0,  # nothing parsed — 100% of the app is a gap
        coverage_note=(
            f"static analysis aborted — probable cause: {label}. {explanation} "
            f"(raw error: {raw_reason})"
        ),
    )
    manifest = AnalysisManifest(
        target_package=None,
        sha256=sha256,
        cache_hit=False,
        total_nodes_parsed=0,
        graph_density=0.0,
        behavioral_subgraphs=[],
        obfuscation=obfuscation,
        predicted_ttps={},
        predicted_family=None,
        family_confidence=None,
        signature_yara=None,
    )
    risk_score = RiskScoreBreakdown(
        # Every component is None, not 0.0 — the same distinction the hot path
        # draws. Nothing was computed; asserting "we looked and found nothing"
        # about a file we could not open would be a lie.
        classifier_confidence_component=None,
        permission_api_component=None,
        ttp_severity_component=None,
        forensic_anchor_component=None,
        obfuscation_component=None,
        reputation_component=None,
        ioc_component=None,
        total_score=UNPARSEABLE_RISK_SCORE,
        verdict_band=_band_for(UNPARSEABLE_RISK_SCORE),
        zero_day_indicator=False,
    )

    # coverage_note (above) already carries the probable-cause explanation and
    # raw error, and generate_report's own limitations list leads with it —
    # these two just add framing that isn't in the coverage note itself.
    limitations = [
        "ANALYSIS INCOMPLETE: the APK could not be parsed, so no permissions, "
        "forensic anchors, IoCs or TTPs were extracted. Every field in this "
        "manifest is empty because nothing was observed, not because nothing "
        "is there.",
        f"Score fixed at {UNPARSEABLE_RISK_SCORE} — not derived from evidence.",
    ]

    # Still run the LLM report instead of a hardcoded placeholder — the
    # grounding prompt's "say not observed, don't invent evidence" rule
    # applies just as well to an empty manifest as a full one, and an
    # analyst gets a written explanation of what's known and why instead of
    # a dead end. run_phase7_reporting already has its own fallback if
    # Ollama itself is unreachable, so this never raises.
    from app.core.pipeline import AnalysisPipeline
    narrative, report_limitations, grounding = AnalysisPipeline.run_phase7_reporting(
        manifest, risk_score
    )
    limitations = limitations + report_limitations

    return AnalysisReport(
        manifest=manifest,
        risk_score=risk_score,
        narrative_report=narrative,
        limitations=limitations,
        grounding=grounding,
    )


from app.core.pipeline import (
    AnalysisPipeline,
    has_deterministic_evidence,
    NO_CLASSIFIER_EVIDENCE_NOTE,
    TTP_PREDICT_THRESHOLD,
)

def _run_analysis(filepath: str, job_id: str | None = None) -> AnalysisReport:
    """
    job_id is optional and purely additive: when given, each phase boundary is
    published via app.core.progress for /analyze/stream/{job_id} to relay over SSE.
    None (the default) makes every progress.emit() call a no-op, so /analyze and
    every test or script calling this directly are byte-for-byte unaffected — see
    progress.py's module docstring for why.
    """
    # --- Phase 1: Ingestion & Metadata (+ Android malware static enrichments) ---
    progress.emit(job_id, 1, "APK Ingestion", "start")
    ingestion, apk_obj, dvm, analysis_obj, yara_targets = (
        AnalysisPipeline.run_phase1_ingestion(filepath)
    )
    progress.emit(job_id, 1, "APK Ingestion", "done")

    # --- Hot path: cache lookup ---
    cached = lookup_signature(ingestion.sha256)
    cache_hit = cached is not None

    if cache_hit:
        # Phases 1.5-7 never run on this path — say so once rather than emitting
        # nine individual "skipped" events for the UI to collapse itself.
        for phase, name in progress.PHASES[1:]:
            progress.emit(job_id, phase, name, "skipped", "known sample — cache hit")
        # A cache hit means "we already reached a verdict on this SHA-256" —
        # return that verdict, not one recomputed from emptied inputs. A prior
        # version called compute_risk_score() with predicted_ttps={}, no
        # anchors and no obfuscation signal, so 81.65 of an 86.14 "malicious"
        # score was discarded and the hot path answered "low" for known-bad
        # malware — while the *cached narrative in the same response* still
        # said 86.14.
        cached_score = cached.get("base_score")
        cached_ttps = cached.get("ttps") or {}
        total_score = cached_score if cached_score is not None else 0.0

        # Reconstruct risk score — use cached component breakdown if available
        rc = cached.get("risk_components") or {}
        risk_score = RiskScoreBreakdown(
            classifier_confidence_component=rc.get("classifier_confidence_component"),
            permission_api_component=rc.get("permission_api_component"),
            ttp_severity_component=rc.get("ttp_severity_component"),
            forensic_anchor_component=rc.get("forensic_anchor_component"),
            obfuscation_component=rc.get("obfuscation_component"),
            reputation_component=rc.get("reputation_component"),
            ioc_component=rc.get("ioc_component"),
            total_score=total_score,
            verdict_band=_band_for(total_score),
            zero_day_indicator=rc.get("zero_day_indicator", False),
            impersonation_floor_applied=rc.get("impersonation_floor_applied", False),
            weighted_score=rc.get("weighted_score"),
        )

        # Reconstruct signature_yara from cache if available
        cached_sig_yara_data = cached.get("signature_yara_data")
        if cached_sig_yara_data:
            cached_sig_yara = SignatureYaraResult(**cached_sig_yara_data)
        else:
            cached_sig_yara = None

        # Reconstruct obfuscation from cache if available
        cached_obf_data = cached.get("obfuscation_data")
        if cached_obf_data:
            obfuscation = ObfuscationSignal(**cached_obf_data)
        else:
            obfuscation = _empty_obfuscation_signal()

        # Use cached permissions, falling back to ingestion
        cached_permissions = cached.get("permissions") or ingestion.permissions

        # Free on a cache hit: both derive from nothing but the Phase 1 ingestion
        # that already re-runs on every request (cert_anomalies/permission_matrix_
        # flags/etc. below are the same pattern). Running this fresh rather than
        # caching it also means an update to the protected-brand reference table
        # takes effect on the very next request for an already-cached sample,
        # instead of waiting for someone to re-upload it.
        impersonation = AnalysisPipeline.run_phase5b_impersonation(ingestion)

        manifest = AnalysisManifest(
            target_package=ingestion.package_name,
            sha256=ingestion.sha256,
            cache_hit=True,
            total_nodes_parsed=0,
            graph_density=0.0,
            behavioral_subgraphs=[],
            obfuscation=obfuscation,
            predicted_ttps=cached_ttps,
            predicted_family=cached.get("family"),
            family_confidence=None,
            ttp_context=_build_ttp_context(cached_ttps),
            related_samples=find_related_samples(
                list(cached_ttps.keys()), ingestion.c2_indicators,
                exclude_sha256=ingestion.sha256,
                cert_thumbprint=ingestion.cert_thumbprint,
            ),
            signature_yara=cached_sig_yara,
            permissions=cached_permissions,
            c2_indicators=ingestion.c2_indicators,
            cert_anomalies=ingestion.cert_anomalies,
            permission_matrix_flags=ingestion.permission_matrix_flags,
            secondary_dex_count=ingestion.secondary_dex_count,
            accessibility_flags=ingestion.accessibility_flags,
            exported_risks=ingestion.exported_risks,
            payload_assets=ingestion.payload_assets,
            dropper_signals=ingestion.dropper_signals,
            # The four resolved_* lists genuinely cannot be cheaply recomputed on
            # a cache hit — they need the full CFG, which is not rebuilt here —
            # so unlike everything above them, these come from the persisted
            # record rather than a fresh ingestion field. Records cached before
            # this fix existed have none of these keys; cached.get(...) then
            # returns None -> `or []` reads as "not recovered", not "checked,
            # found nothing", which is the same honest-gap convention the rest
            # of this file already uses for a hollow cache record.
            resolved_crypto_configs=cached.get("resolved_crypto_configs") or [],
            resolved_dcl_targets=cached.get("resolved_dcl_targets") or [],
            resolved_webview_bridges=cached.get("resolved_webview_bridges") or [],
            resolved_native_bridges=cached.get("resolved_native_bridges") or [],
            app_label=ingestion.app_label,
            icon_phash=ingestion.icon_phash,
            impersonation=impersonation,
        )
        narrative = cached.get("narrative", "")
        limitations = cached.get("limitations", [])
        grounding = cached.get("grounding")

        if cached_score is None:
            limitations = limitations + ["cache hit had no stored score — reporting 0/low"]
        if cached_score is not None and "resolved_crypto_configs" not in cached:
            limitations = limitations + [
                "cache hit predates reverse-engineering persistence — resolved "
                "crypto/DCL/WebView/native findings are not recoverable for this "
                "record without a fresh upload"
            ]
        if cached_score is not None and grounding is None:
            limitations = limitations + [
                "cache hit predates grounding-check persistence — the narrative's "
                "fabrication checks cannot be shown for this record without a "
                "fresh upload"
            ]
        if not narrative:
            narrative = "[Narrative not found in cache. Cached score only.]"
            limitations = limitations + ["analysis skipped — known sample (cache hit)"]

        return AnalysisReport(
            manifest=manifest,
            risk_score=risk_score,
            narrative_report=narrative,
            limitations=limitations,
            grounding=grounding,
        )

    # --- Phase 1.5: Signature Detection & YARA (APK + uncompressed DEX/assets) ---
    progress.emit(job_id, 1.5, "Signature & YARA Scan", "start")
    sig_yara = AnalysisPipeline.run_phase1b_signature_yara(
        filepath, ingestion, yara_targets=yara_targets
    )
    progress.emit(job_id, 1.5, "Signature & YARA Scan", "done")

    # --- Phase 2: Graph Representation ---
    progress.emit(job_id, 2, "CFG / ACFG Construction", "start")
    cfgs, parse_failure_rate = AnalysisPipeline.run_phase2_graph_construction(analysis_obj)
    progress.emit(job_id, 2, "CFG / ACFG Construction", "done")

    # --- Phase 3: Forensic Matching & Subgraph Extraction ---
    progress.emit(job_id, 3, "Forensic Anchor Matching", "start")
    all_matches, behavioral_subgraphs, all_strings = AnalysisPipeline.run_phase3_forensic_matching(cfgs, ingestion)

    # Merge C2 IoCs found in DEX string literals into ingestion
    ingestion = AnalysisPipeline.merge_c2_from_strings(ingestion, all_strings)
    progress.emit(job_id, 3, "Forensic Anchor Matching", "done")

    # --- Phase 3.5: Reverse-Engineering Deep Dive (crypto/DCL/WebView/native) ---
    progress.emit(job_id, 3.5, "Reverse-Engineering Deep Dive", "start")
    resolved_crypto, resolved_dcl, resolved_webview, resolved_native = (
        AnalysisPipeline.run_phase3b_re_deepdive(cfgs, ingestion, apk_obj=apk_obj, analysis_obj=analysis_obj)
    )
    progress.emit(job_id, 3.5, "Reverse-Engineering Deep Dive", "done")

    # --- Phase 4: Feature Engineering (family 35-vec + multi-label TTP 181-vec) ---
    progress.emit(job_id, 4, "Feature Engineering", "start")
    obfuscation, feature_vector, ttp_feature_vector, mean_density, total_nodes = (
        AnalysisPipeline.run_phase4_feature_engineering(
            ingestion, cfgs, all_matches, behavioral_subgraphs, all_strings, parse_failure_rate,
            sig_yara=sig_yara,
        )
    )
    progress.emit(job_id, 4, "Feature Engineering", "done")

    # --- Classifier evidence gate ---
    # The TTP model was trained without a benign class, so it answers confidently
    # even when handed nothing. Decide ONCE here whether the analysis actually
    # observed anything, and apply that decision to Phase 5, Phase 6 and the
    # analyst-facing limitations alike.
    classifier_evidence = has_deterministic_evidence(
        cfg_count=len(cfgs),
        matched_behaviors=set(all_matches),
        ttp_feature_vector=ttp_feature_vector,
    )

    # --- Phase 5: Multi-label TTP Classification (direct) + auxiliary family label ---
    progress.emit(job_id, 5, "MITRE TTP Classification", "start")
    predicted_ttps, predicted_family, family_confidence = AnalysisPipeline.run_phase5_ml_classification(
        ttp_feature_vector, feature_vector, evidence_present=classifier_evidence
    )
    progress.emit(job_id, 5, "MITRE TTP Classification", "done")

    # --- Phase 5.5: Brand impersonation (identity, not payload) ---
    progress.emit(job_id, 5.5, "Brand Impersonation Checks", "start")
    impersonation = AnalysisPipeline.run_phase5b_impersonation(ingestion)
    progress.emit(job_id, 5.5, "Brand Impersonation Checks", "done")

    manifest = AnalysisManifest(
        target_package=ingestion.package_name,
        sha256=ingestion.sha256,
        cache_hit=cache_hit,
        total_nodes_parsed=total_nodes,
        graph_density=round(mean_density, 6),
        behavioral_subgraphs=behavioral_subgraphs,
        obfuscation=obfuscation,
        predicted_ttps=predicted_ttps,
        predicted_family=predicted_family,
        family_confidence=family_confidence,
        ttp_context=_build_ttp_context(predicted_ttps),
        related_samples=find_related_samples(
            list(predicted_ttps.keys()), ingestion.c2_indicators,
            exclude_sha256=ingestion.sha256,
            cert_thumbprint=ingestion.cert_thumbprint,
        ),
        signature_yara=sig_yara,
        permissions=ingestion.permissions,
        c2_indicators=ingestion.c2_indicators,
        cert_anomalies=ingestion.cert_anomalies,
        permission_matrix_flags=ingestion.permission_matrix_flags,
        secondary_dex_count=ingestion.secondary_dex_count,
        accessibility_flags=ingestion.accessibility_flags,
        exported_risks=ingestion.exported_risks,
        payload_assets=ingestion.payload_assets,
        dropper_signals=ingestion.dropper_signals,
        resolved_crypto_configs=resolved_crypto,
        resolved_dcl_targets=resolved_dcl,
        resolved_webview_bridges=resolved_webview,
        resolved_native_bridges=resolved_native,
        app_label=ingestion.app_label,
        icon_phash=ingestion.icon_phash,
        impersonation=impersonation,
    )

    # --- Phase 6: Risk Scoring (includes static malware anchors) ---
    progress.emit(job_id, 6, "Risk Scoring", "start")
    risk_score = AnalysisPipeline.run_phase6_risk_scoring(
        predicted_ttps, ingestion.permissions, obfuscation, all_matches, cache_hit, None,
        sig_yara=sig_yara,
        ingestion=ingestion,
        classifier_evidence_present=classifier_evidence,
        impersonation=impersonation,
    )
    progress.emit(job_id, 6, "Risk Scoring", "done")

    # --- Phase 7: Explainable Reporting ---
    progress.emit(job_id, 7, "GraphRAG Report Generation", "start")
    narrative, limitations, grounding = AnalysisPipeline.run_phase7_reporting(
        manifest, risk_score
    )
    progress.emit(job_id, 7, "GraphRAG Report Generation", "done")

    if not classifier_evidence:
        limitations = list(limitations) + [NO_CLASSIFIER_EVIDENCE_NOTE]

    # Always persist after a cold-path run so the hot path fires on the next
    # request for the same SHA-256. predicted_family may be None when the
    # auxiliary family classifier is untrained — that's fine, store "" and
    # let lookup_signature gate on SHA-256 presence instead of family.
    if not cache_hit:
        store_signature(
            sha256=ingestion.sha256,
            family=predicted_family or "",
            risk_score=risk_score.total_score,
            ttps=predicted_ttps,
            narrative=narrative,
            limitations=limitations,
            signature_yara_data=sig_yara.model_dump() if sig_yara else None,
            permissions=ingestion.permissions,
            risk_components=risk_score.model_dump(),
            obfuscation_data=obfuscation.model_dump(),
            package_name=ingestion.package_name,
            c2_indicators=ingestion.c2_indicators,
            cert_thumbprint=ingestion.cert_thumbprint,
            resolved_crypto_configs=resolved_crypto,
            resolved_dcl_targets=resolved_dcl,
            resolved_webview_bridges=resolved_webview,
            resolved_native_bridges=resolved_native,
            grounding=grounding,
        )

    return AnalysisReport(
        manifest=manifest,
        risk_score=risk_score,
        narrative_report=narrative,
        limitations=limitations,
        grounding=grounding,
    )


def _empty_topological_invariants() -> dict[str, float]:
    from app.analysis.topology import compute_topological_invariants
    import networkx as nx
    return compute_topological_invariants(nx.DiGraph())


def _empty_obfuscation_signal() -> ObfuscationSignal:
    """Returns a no-signal ObfuscationSignal for hot-path cache hits."""
    return ObfuscationSignal(
        string_entropy_score=0.0,
        flattening_suspected=False,
        flattening_outlier_nodes=[],
        reflection_call_count=0,
        unresolved_reflection_targets=0,
        method_parse_failure_rate=0.0,
        coverage_note="analysis skipped — known sample (cache hit)",
    )
