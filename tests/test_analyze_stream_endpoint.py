"""
Regression test for the /analyze/stream/{job_id} reconnect bug (N14).

Found by hand: killing an active curl mid-stream and reconnecting to the same
job_id returned "Unknown or expired job_id" even though the analysis was still
running fine server-side — because the first implementation discarded both the
progress broker entry AND the job result unconditionally in a `finally`, the
instant ANY client disconnected, whether or not the terminal event had actually
been delivered.

The deeper bug under that: broker.try_get() DEQUEUES. Using the queue's own
"final" marker as the completion signal meant that if a slow/dying client
dequeued that marker and then failed to receive it, the marker was gone forever
and a reconnect would poll an empty queue indefinitely. The fix makes _JOBS — a
plain dict, non-destructive to read — the single source of truth for "is this
job done", and only tears down state after a `yield` back to a client has
actually completed.

Calls the route function directly (bypassing ASGI/TestClient) so the exact race
can be constructed deterministically: publish a "final" marker, drain it from the
queue exactly as a dead connection would have, THEN mark the job complete in
_JOBS, and confirm a fresh call to the endpoint still recovers the result.

Fully offline — no real analysis, no Neo4j, no Ollama.
"""
import json
import unittest
import uuid

from fastapi import HTTPException

from app.api import routes as routes_module
from app.core import progress


class _StreamTestBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.job_id = f"test-{uuid.uuid4().hex}"
        progress.broker.create(self.job_id)
        with routes_module._JOBS_LOCK:
            routes_module._JOBS[self.job_id] = {"status": "running", "result": None}

    async def asyncTearDown(self):
        progress.broker.discard(self.job_id)
        with routes_module._JOBS_LOCK:
            routes_module._JOBS.pop(self.job_id, None)

    async def _drain_naturally(self, response) -> list[str]:
        """
        Consumes the stream to exhaustion via a plain `async for` — exactly what
        Starlette's own StreamingResponse driving loop does: after each chunk is
        successfully sent, it calls the generator ONE MORE TIME before looping,
        which is what actually resumes execution past the final `return` and
        triggers cleanup. Use this whenever a test needs to observe a stream that
        was genuinely delivered in full, cleanup included.
        """
        return [chunk async for chunk in response.body_iterator]

    async def _collect_then_disconnect(self, response, limit: int) -> list[str]:
        """
        Reads exactly `limit` chunks, then forces the generator closed via
        aclose() WITHOUT letting it resume naturally afterward.

        This is what a real client disconnect looks like to the generator: torn
        down by GeneratorExit at the `yield` it's suspended on, never reaching
        the `return`/cleanup one line below it — the same shape whether the
        client vanished before receiving those bytes or right after. Use this to
        simulate "the client is gone as of this point," which is the scenario
        the reconnect fix exists for.
        """
        chunks = []
        try:
            async for chunk in response.body_iterator:
                chunks.append(chunk)
                if len(chunks) >= limit:
                    break
        finally:
            await response.body_iterator.aclose()
        return chunks


class TestFinalEventSurvivesADestructiveQueueRead(_StreamTestBase):
    """The exact race that caused the bug."""

    async def test_completion_is_still_recoverable_after_the_queue_marker_is_gone(self):
        # A "final" marker is published, then drained — as if a now-dead
        # connection had already dequeued it but never managed to deliver it.
        progress.broker.publish(self.job_id, {"phase": "final", "final": True, "status": "complete"})
        drained = progress.broker.try_get(self.job_id)
        self.assertIsNotNone(drained, "setup invariant: the marker must really be gone")
        self.assertIsNone(progress.broker.try_get(self.job_id), "queue must now be empty")

        # Only now does the job actually finish — the realistic ordering is that
        # a slow/dead consumer could race ahead of _JOBS being written.
        with routes_module._JOBS_LOCK:
            routes_module._JOBS[self.job_id] = {
                "status": "complete",
                "result": {"risk_score": {"total_score": 42.0}},
            }

        response = await routes_module.analyze_stream(self.job_id)
        chunks = await self._drain_naturally(response)

        self.assertEqual(len(chunks), 1)
        self.assertIn("event: complete", chunks[0])
        payload = json.loads(chunks[0].split("data: ", 1)[1])
        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["result"]["risk_score"]["total_score"], 42.0)

    async def test_error_status_is_relayed_the_same_way(self):
        with routes_module._JOBS_LOCK:
            routes_module._JOBS[self.job_id] = {
                "status": "error", "error": "boom: androguard choked on the manifest",
            }
        response = await routes_module.analyze_stream(self.job_id)
        chunks = await self._drain_naturally(response)

        payload = json.loads(chunks[0].split("data: ", 1)[1])
        self.assertEqual(payload["status"], "error")
        self.assertIn("boom", payload["error"])


class TestReconnectDoesNotDiscardAnUnfinishedJob(_StreamTestBase):
    """
    The user-facing bug: a stream that ends WITHOUT delivering a final event
    (simulating a disconnect) must leave the job intact for a follow-up call —
    a browser EventSource reconnects to the exact same URL automatically.
    """

    async def test_reading_only_progress_events_leaves_the_job_recoverable(self):
        progress.broker.publish(self.job_id, {"phase": 1, "status": "start", "name": "APK Ingestion"})

        first = await routes_module.analyze_stream(self.job_id)
        first_chunks = await self._collect_then_disconnect(first, limit=1)
        self.assertIn("event: progress", first_chunks[0])

        # The "disconnect": no final event was ever seen, so nothing should have
        # been torn down. A second, independent call is exactly what a browser's
        # automatic EventSource retry does.
        self.assertTrue(progress.broker.exists(self.job_id))
        with routes_module._JOBS_LOCK:
            self.assertIn(self.job_id, routes_module._JOBS)

        with routes_module._JOBS_LOCK:
            routes_module._JOBS[self.job_id] = {
                "status": "complete", "result": {"risk_score": {"total_score": 7.5}},
            }
        second = await routes_module.analyze_stream(self.job_id)
        second_chunks = await self._drain_naturally(second)
        payload = json.loads(second_chunks[0].split("data: ", 1)[1])
        self.assertEqual(payload["result"]["risk_score"]["total_score"], 7.5)

    async def test_delivered_completion_does_tear_down_the_job(self):
        """The other half of the invariant: cleanup DOES happen once delivery is
        confirmed, so a completed job doesn't leak forever."""
        with routes_module._JOBS_LOCK:
            routes_module._JOBS[self.job_id] = {
                "status": "complete", "result": {"risk_score": {"total_score": 1.0}},
            }
        response = await routes_module.analyze_stream(self.job_id)
        await self._drain_naturally(response)  # full, natural delivery — cleanup should follow

        self.assertFalse(progress.broker.exists(self.job_id))
        with routes_module._JOBS_LOCK:
            self.assertNotIn(self.job_id, routes_module._JOBS)


class TestUnknownJobId(unittest.IsolatedAsyncioTestCase):
    async def test_returns_404(self):
        with self.assertRaises(HTTPException) as ctx:
            await routes_module.analyze_stream(f"never-created-{uuid.uuid4().hex}")
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
