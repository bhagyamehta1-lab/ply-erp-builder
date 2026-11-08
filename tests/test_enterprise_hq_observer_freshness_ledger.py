from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.enterprise_hq_observer_freshness import evaluate_observer_freshness
from scripts.enterprise_hq_observer_freshness_ledger import (
    MAX_OBSERVER_FRESHNESS_RECEIPTS,
    ObserverFreshnessLedger,
    ObserverFreshnessLedgerCorruptionError,
    ObserverFreshnessLedgerError,
)


class ObserverFreshnessLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "observer-freshness.sqlite3"
        self.ledger = ObserverFreshnessLedger(str(self.database))
        self.base_at = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        if getattr(self, "ledger", None) is not None:
            self.ledger.close()
        self.temp.cleanup()

    def receipt(self, age_seconds=900):
        last = self.base_at - timedelta(seconds=age_seconds)
        return evaluate_observer_freshness(
            last.isoformat().replace("+00:00", "Z"),
            self.base_at.isoformat().replace("+00:00", "Z"),
        )

    @staticmethod
    def key(index):
        return hashlib.sha256(f"observer-test-key-{index}".encode()).hexdigest()

    def append(self, index=1, age_seconds=900, recorded_at=None):
        return self.ledger.append(
            self.receipt(age_seconds),
            idempotency_key=self.key(index),
            recorded_at=recorded_at or "2026-11-08T12:00:00Z",
        )

    def test_append_records_verified_receipt(self):
        result = self.append()
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_RECEIPT_RECORDED")
        self.assertEqual(result["sequence"], 1)
        self.assertTrue(result["created"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])

    def test_empty_ledger_verifies(self):
        result = self.ledger.verify()
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_LEDGER_VALID")
        self.assertEqual(result["receipt_count"], 0)
        self.assertIsNone(result["chain_head_digest"])

    def test_summary_counts_statuses_without_receipt_payloads(self):
        self.append(1, 900)
        self.ledger.append(
            self.receipt(2000), idempotency_key=self.key(2),
            recorded_at="2026-11-08T12:01:00Z",
        )
        result = self.ledger.verify()
        self.assertEqual(result["receipt_count"], 2)
        self.assertEqual(result["status_counts"], {"FRESH": 1, "GRACE_PERIOD": 1})
        self.assertNotIn("receipt", result)

    def test_exact_replay_is_idempotent(self):
        first = self.append()
        replay = self.append()
        self.assertEqual(first["record_hash"], replay["record_hash"])
        self.assertTrue(replay["already_present"])
        self.assertFalse(replay["created"])
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)

    def test_idempotency_key_conflict_is_rejected(self):
        self.append()
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "IDEMPOTENCY_CONFLICT"
        ):
            self.append(1, 2000)

    def test_malformed_idempotency_key_is_rejected(self):
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "IDEMPOTENCY_KEY_INVALID"
        ):
            self.ledger.append(
                self.receipt(), idempotency_key="not-a-digest",
                recorded_at="2026-11-08T12:00:00Z",
            )

    def test_uppercase_idempotency_key_is_rejected(self):
        with self.assertRaises(ObserverFreshnessLedgerError):
            self.ledger.append(
                self.receipt(), idempotency_key=self.key(1).upper(),
                recorded_at="2026-11-08T12:00:00Z",
            )

    def test_tampered_decision_digest_is_rejected(self):
        receipt = self.receipt()
        receipt["decision_digest"] = "0" * 64
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "RECEIPT_INVALID"
        ):
            self.ledger.append(
                receipt, idempotency_key=self.key(1),
                recorded_at="2026-11-08T12:00:00Z",
            )

    def test_extra_receipt_fields_are_rejected(self):
        receipt = self.receipt()
        receipt["run_id"] = "must-not-be-stored"
        with self.assertRaises(ObserverFreshnessLedgerError):
            self.ledger.append(
                receipt, idempotency_key=self.key(1),
                recorded_at="2026-11-08T12:00:00Z",
            )

    def test_authority_escalation_is_rejected(self):
        receipt = self.receipt()
        receipt["automatic_retry"] = True
        with self.assertRaises(ObserverFreshnessLedgerError):
            self.ledger.append(
                receipt, idempotency_key=self.key(1),
                recorded_at="2026-11-08T12:00:00Z",
            )

    def test_hash_chain_links_successive_receipts(self):
        first = self.append(1)
        second = self.append(2, 2000, "2026-11-08T12:01:00Z")
        row = self.ledger._connection.execute(
            "SELECT sequence, previous_hash FROM observer_freshness_receipts "
            "WHERE sequence = 2"
        ).fetchone()
        self.assertEqual(row["sequence"], 2)
        self.assertEqual(row["previous_hash"], first["record_hash"])
        self.assertNotEqual(second["record_hash"], first["record_hash"])
        self.assertEqual(self.ledger.verify()["receipt_count"], 2)

    def test_record_hash_tampering_is_detected(self):
        self.append()
        self.ledger._connection.execute(
            "DROP TRIGGER observer_freshness_receipts_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE observer_freshness_receipts SET record_hash = ? WHERE sequence = 1",
            ("f" * 64,),
        )
        with self.assertRaises(ObserverFreshnessLedgerCorruptionError):
            self.ledger.verify()

    def test_receipt_payload_tampering_is_detected(self):
        self.append()
        self.ledger._connection.execute(
            "DROP TRIGGER observer_freshness_receipts_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE observer_freshness_receipts SET receipt_json = ? WHERE sequence = 1",
            ('{"tampered":true}',),
        )
        with self.assertRaises(ObserverFreshnessLedgerCorruptionError):
            self.ledger.verify()

    def test_database_rejects_updates(self):
        self.append()
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "UPDATE observer_freshness_receipts SET sequence = 2 WHERE sequence = 1"
            )

    def test_database_rejects_deletes(self):
        self.append()
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "DELETE FROM observer_freshness_receipts WHERE sequence = 1"
            )

    def test_symlink_database_path_is_rejected(self):
        link = self.root / "linked.sqlite3"
        os.symlink(self.database, link)
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "SYMLINK_FORBIDDEN"
        ):
            ObserverFreshnessLedger(str(link))

    def test_directory_database_path_is_rejected(self):
        with self.assertRaises(ObserverFreshnessLedgerError):
            ObserverFreshnessLedger(str(self.root))

    def test_memory_database_is_rejected(self):
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "PERSISTENT_PATH_REQUIRED"
        ):
            ObserverFreshnessLedger(":memory:")

    def test_naive_recorded_at_is_rejected(self):
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "TIMEZONE_REQUIRED"
        ):
            self.append(recorded_at="2026-11-08T12:00:00")

    def test_malformed_recorded_at_is_rejected(self):
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "RECORDED_AT_INVALID"
        ):
            self.append(recorded_at="not-a-time")

    def test_equivalent_timezone_replay_is_idempotent(self):
        first = self.append(recorded_at="2026-11-08T12:00:00Z")
        replay = self.append(recorded_at="2026-11-08T12:00:00+00:00")
        self.assertEqual(first["record_hash"], replay["record_hash"])
        self.assertTrue(replay["already_present"])

    def test_recorded_at_regression_is_rejected(self):
        self.append(1, 900, "2026-11-08T12:01:00Z")
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "RECORDED_AT_REGRESSION"
        ):
            self.append(2, 900, "2026-11-08T12:00:59Z")

    def test_verification_summary_excludes_timestamps_and_keys(self):
        key = self.key(1)
        self.ledger.append(
            self.receipt(), idempotency_key=key,
            recorded_at="2026-11-08T12:00:00Z",
        )
        summary = self.ledger.verify()
        rendered = str(summary)
        self.assertNotIn(key, rendered)
        self.assertNotIn("recorded_at", rendered)
        self.assertNotIn("2026-11-08", rendered)
        self.assertNotIn("repository", rendered)
        self.assertNotIn("workflow", rendered)

    def test_capacity_is_bounded_and_never_auto_purges(self):
        for index in range(MAX_OBSERVER_FRESHNESS_RECEIPTS):
            self.append(index + 1)
        self.assertEqual(
            self.ledger.verify()["receipt_count"],
            MAX_OBSERVER_FRESHNESS_RECEIPTS,
        )
        with self.assertRaisesRegex(
            ObserverFreshnessLedgerError, "CAPACITY_REACHED"
        ):
            self.append(MAX_OBSERVER_FRESHNESS_RECEIPTS + 1)
        self.assertEqual(
            self.ledger.verify()["receipt_count"],
            MAX_OBSERVER_FRESHNESS_RECEIPTS,
        )

    def test_concurrent_appends_preserve_unique_sequences(self):
        def worker(index):
            with ObserverFreshnessLedger(str(self.database)) as ledger:
                return ledger.append(
                    self.receipt(), idempotency_key=self.key(index),
                    recorded_at="2026-11-08T12:00:00Z",
                )["sequence"]

        with ThreadPoolExecutor(max_workers=8) as pool:
            sequences = list(pool.map(worker, range(1, 9)))
        self.assertEqual(sorted(sequences), list(range(1, 9)))
        self.assertEqual(self.ledger.verify()["receipt_count"], 8)

    def test_database_permissions_are_owner_only(self):
        self.append()
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)

    def test_raw_idempotency_key_is_not_persisted(self):
        key = self.key(1)
        self.ledger.append(
            self.receipt(), idempotency_key=key,
            recorded_at="2026-11-08T12:00:00Z",
        )
        self.ledger.close()
        raw = self.database.read_bytes()
        self.assertNotIn(key.encode("ascii"), raw)
        self.ledger = ObserverFreshnessLedger(str(self.database))

    def test_duplicate_decision_digest_can_have_distinct_receipts(self):
        receipt = self.receipt()
        first = self.ledger.append(
            receipt, idempotency_key=self.key(1),
            recorded_at="2026-11-08T12:00:00Z",
        )
        second = self.ledger.append(
            receipt, idempotency_key=self.key(2),
            recorded_at="2026-11-08T12:01:00Z",
        )
        self.assertEqual(first["decision_digest"], second["decision_digest"])
        self.assertNotEqual(first["receipt_id"], second["receipt_id"])
        self.assertEqual(self.ledger.verify()["receipt_count"], 2)

    def test_sequence_gap_is_detected(self):
        self.append()
        self.ledger._connection.execute(
            "DROP TRIGGER observer_freshness_receipts_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE observer_freshness_receipts SET sequence = 2 WHERE sequence = 1"
        )
        with self.assertRaises(ObserverFreshnessLedgerCorruptionError):
            self.ledger.verify()

    def test_append_refuses_to_extend_a_corrupted_chain(self):
        self.append()
        self.ledger._connection.execute(
            "DROP TRIGGER observer_freshness_receipts_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE observer_freshness_receipts SET record_hash = ? WHERE sequence = 1",
            ("e" * 64,),
        )
        with self.assertRaises(ObserverFreshnessLedgerCorruptionError):
            self.append(2, 2000, "2026-11-08T12:01:00Z")
        self.assertEqual(
            self.ledger._connection.execute(
                "SELECT COUNT(*) FROM observer_freshness_receipts"
            ).fetchone()[0],
            1,
        )

    def test_module_has_no_network_or_process_execution_imports(self):
        import ast
        source = (
            Path(__file__).resolve().parents[1]
            / "scripts" / "enterprise_hq_observer_freshness_ledger.py"
        )
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        self.assertFalse(any(
            name.startswith(("urllib", "http", "socket", "subprocess"))
            for name in imported
        ))


if __name__ == "__main__":
    unittest.main()
