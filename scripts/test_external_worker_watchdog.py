import unittest
from datetime import datetime, timedelta, timezone

from external_worker_watchdog import (
    DISPATCH_COOLDOWN,
    STALE_AFTER,
    has_active_run,
    has_recent_dispatch,
    is_stale,
    parse_timestamp,
)


class WatchdogDecisionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 7, 5, 0, tzinfo=timezone.utc)

    def test_recent_schedule_is_healthy(self):
        self.assertFalse(is_stale(self.now - timedelta(minutes=29), self.now))

    def test_schedule_older_than_threshold_is_stale(self):
        self.assertTrue(is_stale(self.now - timedelta(minutes=31), self.now))

    def test_missing_schedule_is_stale(self):
        self.assertTrue(is_stale(None, self.now))

    def test_active_run_suppresses_dispatch(self):
        self.assertTrue(has_active_run([{"status": "in_progress"}]))
        self.assertTrue(has_active_run([{"status": "queued"}]))
        self.assertFalse(has_active_run([{"status": "completed"}]))

    def test_recent_dispatch_is_in_cooldown(self):
        runs = [{
            "event": "workflow_dispatch",
            "created_at": (self.now - timedelta(minutes=10)).isoformat(),
        }]
        self.assertTrue(has_recent_dispatch(runs, self.now))

    def test_old_dispatch_is_not_in_cooldown(self):
        runs = [{
            "event": "workflow_dispatch",
            "created_at": (self.now - DISPATCH_COOLDOWN - timedelta(minutes=1)).isoformat(),
        }]
        self.assertFalse(has_recent_dispatch(runs, self.now))

    def test_schedule_event_does_not_count_as_manual_dispatch(self):
        runs = [{
            "event": "schedule",
            "created_at": (self.now - timedelta(minutes=1)).isoformat(),
        }]
        self.assertFalse(has_recent_dispatch(runs, self.now))

    def test_github_timestamp_parses_to_utc(self):
        self.assertEqual(
            parse_timestamp("2026-11-07T04:30:00Z"),
            datetime(2026, 11, 7, 4, 30, tzinfo=timezone.utc),
        )


if __name__ == "__main__":
    unittest.main()
