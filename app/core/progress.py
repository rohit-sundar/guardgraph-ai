"""
Real pipeline progress, for streaming to the UI over Server-Sent Events.

The frontend previously showed progress via simulatePipelineProgress() — a fixed
sequence of setTimeout delays with no connection to the actual pipeline, which
reached 95% and sat there however long the real analysis took. Every phase already
logs its own start and duration (see app/core/pipeline.py's logger.info calls); this
module is what lets those same boundaries reach the browser instead of only the
server log.

Deliberately explicit rather than contextvar-based: each background analysis is given
a job_id string up front, and every progress call passes it directly. A raw
threading.Thread (used for the background job, see routes.py) does not inherit the
caller's contextvars — each new OS thread starts a fresh empty Context — so a
contextvar-based "current job" would silently stop working the moment the analysis
moved off the request-handling thread. Passing job_id as a plain argument has no such
failure mode.

emit()/publish() are no-ops when job_id is None or unknown. That is what keeps the
existing synchronous /analyze and /analyze_sample endpoints — used by curl, the
README's quickstart, and scripts/test_upload.py — completely unaffected: they call
the same pipeline code with job_id=None and pay nothing for this module existing.
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

# Phase number and display name, in execution order. Numbers match the phase
# comments already in app/core/pipeline.py and app/api/routes.py, including the
# half-steps (1.5, 3.5, 5.5) that were inserted between the original whole-numbered
# phases rather than renumbering everything around them.
PHASES: list[tuple[float, str]] = [
    (1, "APK Ingestion"),
    (1.5, "Signature & YARA Scan"),
    (2, "CFG / ACFG Construction"),
    (3, "Forensic Anchor Matching"),
    (3.5, "Reverse-Engineering Deep Dive"),
    (4, "Feature Engineering"),
    (5, "MITRE TTP Classification"),
    (5.5, "Brand Impersonation Checks"),
    (6, "Risk Scoring"),
    (7, "GraphRAG Report Generation"),
]
TOTAL_PHASES = len(PHASES)
_PHASE_INDEX = {phase: i for i, (phase, _) in enumerate(PHASES)}


@dataclass
class _Job:
    events: "queue.Queue[dict]" = field(default_factory=lambda: queue.Queue(maxsize=256))
    created_at: float = field(default_factory=time.time)


class ProgressBroker:
    """
    Thread-safe job_id -> event queue registry.

    One producer (the background analysis thread) and one consumer (the SSE
    generator) per job, so a plain queue.Queue is enough — no pub/sub fan-out is
    needed. `publish` is non-blocking: a slow or absent consumer must never stall
    the analysis itself, so a full queue drops the event rather than blocking.
    """

    def __init__(self, max_age_seconds: float = 3600.0):
        self._jobs: dict[str, _Job] = {}
        self._lock = threading.Lock()
        self._max_age = max_age_seconds

    def create(self, job_id: str) -> None:
        with self._lock:
            self._jobs[job_id] = _Job()
            self._evict_stale_locked()

    def exists(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._jobs

    def publish(self, job_id: str, event: dict) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return
        try:
            job.events.put_nowait(event)
        except queue.Full:
            pass  # a consumer that isn't keeping up loses progress ticks, not correctness

    def try_get(self, job_id: str) -> Optional[dict]:
        """Non-blocking read — the SSE generator polls this so it stays async-friendly."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return None
        try:
            return job.events.get_nowait()
        except queue.Empty:
            return None

    def discard(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)

    def _evict_stale_locked(self) -> None:
        """
        Best-effort cleanup for jobs whose stream was never opened or never finished
        (a closed tab, a crashed background thread). Runs opportunistically on each
        create() rather than on a timer — nothing here is precise enough to need one,
        and a lost job_id costs one small queue object until the next create().
        """
        cutoff = time.time() - self._max_age
        stale = [jid for jid, job in self._jobs.items() if job.created_at < cutoff]
        for jid in stale:
            self._jobs.pop(jid, None)


broker = ProgressBroker()


def emit(job_id: Optional[str], phase: float, name: str, status: str, detail: str = "") -> None:
    """
    Records one phase transition. `status` is "start", "done", "skipped" (the cache
    hit path, which never runs phases 1.5 onward), or "error".

    No-op when job_id is None — see module docstring. Also no-op if the job_id is
    unrecognised (stream already discarded, or a stale id) rather than raising: a
    progress event is a courtesy to a UI, never a condition the analysis depends on.
    """
    if not job_id:
        return
    broker.publish(job_id, {
        "phase": phase,
        "phase_index": _PHASE_INDEX.get(phase),
        "total_phases": TOTAL_PHASES,
        "name": name,
        "status": status,
        "detail": detail,
        "ts": time.time(),
    })


def emit_final(job_id: Optional[str], status: str, detail: str = "") -> None:
    """The one event that ends the stream. status is "complete" or "error"."""
    if not job_id:
        return
    broker.publish(job_id, {
        "phase": "final",
        "phase_index": TOTAL_PHASES,
        "total_phases": TOTAL_PHASES,
        "name": "Complete" if status == "complete" else "Failed",
        "status": status,
        "detail": detail,
        "ts": time.time(),
        "final": True,
    })
