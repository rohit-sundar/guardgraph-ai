"""
Tests for app/core/progress.py — the SSE progress broker behind /analyze/stream.

Three properties matter, in order of how badly getting them wrong would look in a
live demo:

  1. Every call is a no-op when job_id is None. This is what keeps /analyze,
     /analyze_sample, and every existing test or script calling _run_analysis
     directly byte-for-byte unaffected by this module's existence.
  2. publish() never blocks and never raises when the queue is full or the job_id
     is unknown — a progress tick is a courtesy to a UI, never something the
     analysis itself can be made to wait on or fail because of.
  3. A job survives being read from repeatedly. try_get() and the routes.py
     reconnect logic depend on this: a disconnect-and-reconnect must not lose the
     terminal event just because a queue read is (by necessity) destructive.

Fully offline — no FastAPI app, no Neo4j, no Ollama.
"""
import queue
import time
import unittest

from app.core.progress import PHASES, TOTAL_PHASES, ProgressBroker, emit, emit_final


class TestNoOpWithoutJobId(unittest.TestCase):
    """emit()/emit_final() with job_id=None must not touch the broker at all."""

    def test_emit_none_job_id_does_not_raise(self):
        emit(None, 1, "APK Ingestion", "start")  # must not raise

    def test_emit_final_none_job_id_does_not_raise(self):
        emit_final(None, "complete")  # must not raise

    def test_emit_unknown_job_id_is_silently_dropped(self):
        """A job_id that was never create()'d (or was already discarded) is not an
        error — the caller is mid-analysis and cannot usefully react to it."""
        emit("never-created", 1, "APK Ingestion", "start")  # must not raise


class TestBrokerLifecycle(unittest.TestCase):
    def setUp(self):
        self.broker = ProgressBroker()

    def test_create_then_exists(self):
        self.assertFalse(self.broker.exists("j1"))
        self.broker.create("j1")
        self.assertTrue(self.broker.exists("j1"))

    def test_publish_then_try_get_returns_the_event(self):
        self.broker.create("j1")
        self.broker.publish("j1", {"phase": 1, "status": "start"})
        event = self.broker.try_get("j1")
        self.assertEqual(event, {"phase": 1, "status": "start"})

    def test_try_get_on_empty_queue_returns_none_without_blocking(self):
        self.broker.create("j1")
        started = time.monotonic()
        result = self.broker.try_get("j1")
        elapsed = time.monotonic() - started
        self.assertIsNone(result)
        self.assertLess(elapsed, 0.05, "try_get must not block waiting for an event")

    def test_try_get_on_unknown_job_returns_none(self):
        self.assertIsNone(self.broker.try_get("never-created"))

    def test_publish_to_unknown_job_does_not_raise(self):
        self.broker.publish("never-created", {"phase": 1})  # must not raise

    def test_events_are_delivered_in_order(self):
        self.broker.create("j1")
        for i in range(5):
            self.broker.publish("j1", {"i": i})
        received = [self.broker.try_get("j1")["i"] for _ in range(5)]
        self.assertEqual(received, [0, 1, 2, 3, 4])

    def test_discard_removes_the_job(self):
        self.broker.create("j1")
        self.broker.discard("j1")
        self.assertFalse(self.broker.exists("j1"))
        self.assertIsNone(self.broker.try_get("j1"))

    def test_discard_of_unknown_job_does_not_raise(self):
        self.broker.discard("never-created")  # must not raise

    def test_publish_never_blocks_when_queue_is_full(self):
        """
        A progress tick must never be able to stall the analysis thread that is
        producing it. The queue has a bounded size specifically so a consumer
        that stopped reading (a dropped stream nobody reconnected to) can't turn
        publish() into a blocking call.
        """
        self.broker.create("j1")
        # _Job's queue defaults to maxsize=256 — publish comfortably past that.
        started = time.monotonic()
        for i in range(400):
            self.broker.publish("j1", {"i": i})
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0, "publish() must drop rather than block on a full queue")


class TestPhaseTable(unittest.TestCase):
    """PHASES is the contract the frontend's step markup (index.html) mirrors via
    data-phase attributes — these pin the shape that contract depends on."""

    def test_phase_numbers_are_unique_and_ascending(self):
        numbers = [p for p, _ in PHASES]
        self.assertEqual(numbers, sorted(numbers))
        self.assertEqual(len(numbers), len(set(numbers)))

    def test_total_phases_matches_the_table_length(self):
        self.assertEqual(TOTAL_PHASES, len(PHASES))

    def test_every_phase_has_a_nonempty_display_name(self):
        for phase, name in PHASES:
            self.assertTrue(name.strip(), f"phase {phase} has an empty name")


class TestEmitPayloadShape(unittest.TestCase):
    """What routes.py's SSE generator and app.js's applyProgressEvent() both
    depend on being present on every event."""

    def setUp(self):
        self.broker = ProgressBroker()
        self.broker.create("j1")

    def _emit(self, *args, **kwargs):
        # emit() reads the module-level `broker` singleton, not an instance one,
        # so exercise it through that — see the patch in the two tests below.
        import app.core.progress as progress_module
        original = progress_module.broker
        progress_module.broker = self.broker
        try:
            progress_module.emit(*args, **kwargs)
        finally:
            progress_module.broker = original

    def test_emit_includes_phase_index_and_total(self):
        self._emit("j1", 3.5, "Reverse-Engineering Deep Dive", "start")
        event = self.broker.try_get("j1")
        self.assertEqual(event["phase"], 3.5)
        self.assertEqual(event["phase_index"], PHASES.index((3.5, "Reverse-Engineering Deep Dive")))
        self.assertEqual(event["total_phases"], TOTAL_PHASES)
        self.assertEqual(event["status"], "start")
        self.assertNotIn("final", event)

    def test_emit_final_is_flagged_and_terminal(self):
        import app.core.progress as progress_module
        original = progress_module.broker
        progress_module.broker = self.broker
        try:
            progress_module.emit_final("j1", "complete")
        finally:
            progress_module.broker = original

        event = self.broker.try_get("j1")
        self.assertTrue(event["final"])
        self.assertEqual(event["status"], "complete")
        self.assertEqual(event["phase_index"], TOTAL_PHASES)


if __name__ == "__main__":
    unittest.main()
