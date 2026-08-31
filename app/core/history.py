"""
On-disk record of the analyses THIS instance actually performed.

Deliberately separate from Neo4j. The graph holds a Sample node for everything
the instance knows about, which includes corpus samples bulk-loaded by the
population scripts and never analysed through the app. Listing those as
"Analysis History" told the operator they had analysed hundreds of APKs they had
never uploaded, and restarting the server changed nothing because the graph is
persistent by design.

The distinction is a real one, not cosmetic: the graph is a KNOWLEDGE BASE that
correlation, related-samples and the threat-landscape view all read from, so it
must keep every node it has. This file is a LOG of what was actually run here.
Those are different questions and they now have different stores.

Kept as a flat JSON list rather than a database: it is a bounded, append-mostly
list of small records read in one gulp by a single process, which is the case a
file handles well and a second database dependency would not improve.
"""
import json
import os
import tempfile
import threading
import time
from pathlib import Path

from loguru import logger

# Repo root, not the current working directory — the server is not always
# started from the repo root, and a relative path would silently write a second
# history file wherever it happened to be launched from.
_HISTORY_PATH = Path(__file__).resolve().parents[2] / "data" / "analysis_history.json"

# Bounds the file. History is a convenience list the operator scrolls, not an
# audit log — Neo4j still holds the full record of every verdict, reachable by
# sha256 whether or not it is listed here.
_MAX_ENTRIES = 500

# Every write is read-modify-write, and analyses run on background threads
# (see _run_background_job), so two finishing at once could otherwise lose one.
_LOCK = threading.Lock()


def _read() -> list[dict]:
    """Never raises: a missing or damaged history file must not fail an analysis
    that has otherwise completely succeeded."""
    try:
        with open(_HISTORY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as e:
        logger.warning(f"[history] unreadable history file ({e}) — starting a new one.")
        return []


def _write(entries: list[dict]) -> None:
    """Atomic replace, so an interrupted write cannot leave a truncated file that
    the next read would discard along with every entry in it."""
    _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(_HISTORY_PATH.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=1)
        os.replace(tmp, _HISTORY_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def record_analysis(sha256: str, app_name: str | None, family: str | None,
                    risk_score: float | None) -> None:
    """Upsert by sha256, most-recent-first. Re-analysing a sample moves it back to
    the top rather than adding a duplicate row, which matches what the panel is
    for — 'what have I looked at', not 'how many times did I press upload'.

    Best-effort by contract: a failure to record history must never fail the
    analysis it is recording."""
    if not sha256:
        return
    try:
        with _LOCK:
            entries = [e for e in _read() if e.get("sha256") != sha256]
            entries.insert(0, {
                "sha256": sha256,
                "app_name": app_name or sha256,
                "family": family or None,
                "risk_score": risk_score,
                "analyzed_at": int(time.time() * 1000),
            })
            _write(entries[:_MAX_ENTRIES])
    except Exception as e:
        logger.warning(f"[history] could not record {sha256[:12]}: {e}")


def list_history(limit: int = 30) -> list[dict]:
    """Newest first. Stored in order, so no sort is needed on read."""
    with _LOCK:
        return _read()[:max(0, limit)]


def peek_history_shas() -> list[str]:
    """The sha256s currently in the history, WITHOUT clearing it.

    Exists so the clear endpoint can decide whether the clear is sane before it
    commits to one: `clear_history` empties the file as it reads, so a caller
    that wants to refuse has already destroyed the list it was refusing over.
    """
    with _LOCK:
        return [e.get("sha256") for e in _read() if e.get("sha256")]


def clear_history() -> list[str]:
    """Empties the file and returns the sha256s that were in it, so the caller can
    drop the matching cached verdicts — clearing the list while leaving the cache
    behind would produce an empty panel whose samples still answer from cache and
    still report every static phase as skipped."""
    with _LOCK:
        shas = [e.get("sha256") for e in _read() if e.get("sha256")]
        _write([])
        return shas
