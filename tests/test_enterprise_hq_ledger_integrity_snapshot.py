"""Tests for deterministic metadata-only unified ledger integrity checkpoints."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    LedgerIntegritySnapshotError,
    build_ledger_integrity_snapshot,
    verify_ledger_integrity_snapshot,
)
from scripts.enterprise_hq_task_ledger import LedgerCorruptionError


TASK = {
    "task_id": "HQ-INTEGRITY-01",
    "workstream_id": "WS-07",
    "task_kind": "INTERNAL_CODE",
    "attempt": 0,
    "status": "PROPOSED",
    "external_effects": False,
    "requires_human_approval": True,
}


class LedgerIntegritySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "integrity.sqlite3")
        self.ledger = EvidenceVerificationLedger(self.database)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def snapshot(self):
        return build_ledger_integrity_snapshot(self.ledger)

    def test_empty_unified_ledger_produces_valid_checkpoint(self):
        snapshot = self.snapshot()
        checked = verify_ledger_integrity_snapshot(snapshot)
        self.assertEqual(checked["status"], "CHECKPOINT_INTEGRITY_VALID")
        self.assertFalse(checked["execution_authorized"])
        self.assertGreaterEqual(checked["audit_chain_count"], 1)
        self.assertTrue(all(chain["event_count"] == 0 for chain in snapshot["audit_chains"]))

    def test_checkpoint_is_deterministic_for_unchanged_database(self):
        first = self.snapshot()
        second = self.snapshot()
        self.assertEqual(first, second)

    def test_task_append_changes_checkpoint_digest(self):
        before = self.snapshot()
        self.ledger.propose_many([TASK])
        after = self.snapshot()
        self.assertNotEqual(before["snapshot_digest"], after["snapshot_digest"])
        self.assertEqual(
            verify_ledger_integrity_snapshot(after)["status"],
            "CHECKPOINT_INTEGRITY_VALID",
        )

    def test_restart_preserves_checkpoint_digest(self):
        before = self.snapshot()
        self.ledger.close()
        self.ledger = EvidenceVerificationLedger(self.database)
        after = self.snapshot()
        self.assertEqual(before["snapshot_digest"], after["snapshot_digest"])

    def test_checkpoint_contains_metadata_only_not_task_or_payload_content(self):
        self.ledger.propose_many([TASK])
        rendered = json.dumps(self.snapshot(), sort_keys=True)
        self.assertNotIn(TASK["task_id"], rendered)
        self.assertNotIn("sanitized internal company evidence", rendered)
        self.assertNotIn("docs/enterprise-hq-runtime.md", rendered)
        self.assertNotIn("payloads", rendered)

    def test_audit_chain_corruption_prevents_checkpoint_creation(self):
        self.ledger.propose_many([TASK])
        row = self.ledger._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND (name='audit_events' OR name LIKE '%_audit_events') "
            "ORDER BY name LIMIT 1"
        ).fetchone()
        table = row["name"]
        self.ledger._connection.execute(
            f'UPDATE "{table}" SET record_hash = ? WHERE sequence = 1',
            ("0" * 64,),
        )
        with self.assertRaises(LedgerCorruptionError):
            self.snapshot()

    def test_malformed_audit_table_is_rejected(self):
        self.ledger._connection.execute(
            "CREATE TABLE injected_audit_events (sequence INTEGER)"
        )
        with self.assertRaisesRegex(
            LedgerIntegritySnapshotError, "LEDGER_AUDIT_TABLE_SCHEMA_INVALID"
        ):
            self.snapshot()

    def test_recovery_that_claims_execution_resume_is_rejected(self):
        with patch.object(
            self.ledger,
            "recover_after_restart",
            return_value={
                "recovery_status": "PASS",
                "execution_resumed": True,
                "automatic_retry": False,
            },
        ):
            with self.assertRaisesRegex(
                LedgerIntegritySnapshotError,
                "LEDGER_RECOVERY_AUTHORITY_INVARIANT_FAILED",
            ):
                self.snapshot()

    def test_checkpoint_digest_tampering_is_detected(self):
        snapshot = self.snapshot()
        changed = dict(snapshot)
        changed["ledger_type"] = "TamperedLedger"
        with self.assertRaisesRegex(
            LedgerIntegritySnapshotError, "LEDGER_SNAPSHOT_DIGEST_MISMATCH"
        ):
            verify_ledger_integrity_snapshot(changed)

    def test_authorization_claim_is_rejected_even_with_recomputed_digest(self):
        snapshot = self.snapshot()
        changed = dict(snapshot)
        changed["execution_authorized"] = True
        body = {key: value for key, value in changed.items() if key != "snapshot_digest"}
        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
        changed["snapshot_digest"] = hashlib.sha256(encoded).hexdigest()
        with self.assertRaisesRegex(
            LedgerIntegritySnapshotError,
            "LEDGER_SNAPSHOT_AUTHORITY_INVARIANT_FAILED",
        ):
            verify_ledger_integrity_snapshot(changed)

    def test_unknown_snapshot_fields_are_rejected(self):
        snapshot = self.snapshot()
        changed = dict(snapshot)
        changed["raw_payload"] = "must-not-be-accepted"
        with self.assertRaisesRegex(
            LedgerIntegritySnapshotError, "LEDGER_SNAPSHOT_SCHEMA_INVALID"
        ):
            verify_ledger_integrity_snapshot(changed)

    def test_audit_chain_inventory_is_sorted_and_contains_only_heads(self):
        snapshot = self.snapshot()
        names = [chain["table"] for chain in snapshot["audit_chains"]]
        self.assertEqual(names, sorted(names))
        for chain in snapshot["audit_chains"]:
            self.assertEqual(set(chain), {"table", "event_count", "last_sequence", "head_hash"})
            self.assertNotIn("events", chain)
            self.assertNotIn("payload", chain)

    def test_non_ledger_object_fails_closed(self):
        with self.assertRaisesRegex(
            LedgerIntegritySnapshotError, "LEDGER_INTERFACE_UNAVAILABLE"
        ):
            build_ledger_integrity_snapshot(object())


if __name__ == "__main__":
    unittest.main()
