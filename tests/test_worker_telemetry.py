import unittest

from scripts.worker_telemetry import summarize_snapshots


def sample(ts, cpu, current, peak):
    return {
        "timestamp_utc": ts,
        "host": {"cpu_count": 2, "memory_total_bytes": 1000,
                 "memory_available_bytes": 500, "load_average_1_5_15": [0.1, 0.2, 0.3]},
        "cgroup": {"source": "cgroup_v2_root", "scope": "test",
                   "cpu_usage_usec": cpu, "memory_current_bytes": current,
                   "memory_peak_bytes": peak},
        "workspace_disk": {"total_bytes": 1000, "used_bytes": 100, "free_bytes": 900},
    }


class TelemetryTests(unittest.TestCase):
    def test_cpu_delta_and_duration(self):
        result = summarize_snapshots(
            sample("2026-11-07T00:00:00+00:00", 1_000_000, 100, 150),
            sample("2026-11-07T00:00:10+00:00", 4_500_000, 120, 200),
        )
        self.assertEqual(result["cgroup_cpu_seconds_delta"], 3.5)
        self.assertEqual(result["snapshot_elapsed_seconds"], 10.0)
        self.assertEqual(result["sample_count"], 2)

    def test_missing_snapshot_is_not_reported_as_zero(self):
        result = summarize_snapshots(None, None)
        self.assertEqual(result["status"], "PARTIAL_OR_UNAVAILABLE")
        self.assertNotIn("cgroup_cpu_seconds_delta", result)

    def test_counter_reset_is_clamped_and_not_negative(self):
        result = summarize_snapshots(
            sample("2026-11-07T00:00:00+00:00", 9_000_000, 100, 150),
            sample("2026-11-07T00:00:01+00:00", 2_000_000, 120, 200),
        )
        self.assertEqual(result["cgroup_cpu_seconds_delta"], 0.0)

    def test_source_mismatch_disables_cpu_delta(self):
        a = sample("2026-11-07T00:00:00+00:00", 1_000_000, 100, 150)
        b = sample("2026-11-07T00:00:01+00:00", 2_000_000, 120, 200)
        b["cgroup"]["source"] = "unavailable"
        result = summarize_snapshots(a, b)
        self.assertIsNone(result["cgroup_cpu_seconds_delta"])


if __name__ == "__main__":
    unittest.main()
