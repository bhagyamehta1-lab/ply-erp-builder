"""Tests for metadata-only ledger backup/restore equivalence verification."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    build_ledger_integrity_snapshot,
    verify_ledger_integrity_snapshot,
)
from scripts.enterprise_hq_ledger_restore_verifier import (
    LedgerRestoreEquivalenceError,
    verify_ledger_restore_equivalence,
)


TASK = {
    "task_id": "HQ-RESTORE-01",
    "workstream_id": "WS-08",
    "task_kind": "INTERNAL_CODE",
    "attempt": 0,
    "status": "PROPOSED",
    "external_effects": False,
    "requires_human_approval": True,
}


class LedgerRestoreEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = str(self.root / "source.sqlite3")
        self.ledger = EvidenceVerificationLedger(self.database)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    @staticmethod
    def _redigest(snapshot):
        body = {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
        encoded = json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        snapshot["snapshot_digest"] = hashlib.sha256(encoded).hexdigest()
        return snapshot

    def _sqlite_backup_snapshot(self):
        backup_path = self.root / "restored.sqlite3"
        target = sqlite3.connect(str(backup_path))
        try:
            self.ledger._connection.backup(target)
        finally:
            target.close()
        restored = EvidenceVerificationLedger(str(backup_path))
        try:
            return build_ledger_integrity_snapshot(restored)
        finally:
            restored.close()

    def test_identical_valid_snapshots_are_equivalent(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        restored = dict(source)
        result = verify_ledger_restore_equivalence(source, restored)
        self.assertEqual(result["status"], "RESTORE_EQUIVALENCE_VERIFIED")
        self.assertEqual(result["source_snapshot_digest"], result["restored_snapshot_digest"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["execution_resumed"])
        self.assertFalse(result["automatic_retry"])

    def test_sqlite_backup_and_restore_preserve_checkpoint(self):
        self.ledger.propose_many([TASK])
        source = build_ledger_integrity_snapshot(self.ledger)
        restored = self._sqlite_backup_snapshot()
        result = verify_ledger_restore_equivalence(source, restored)
        self.assertEqual(result["status"], "RESTORE_EQUIVALENCE_VERIFIED")
        self.assertEqual(source["snapshot_digest"], restored["snapshot_digest"])

    def test_restore_with_additional_task_event_is_rejected(self):
        self.ledger.propose_many([TASK])
        source = build_ledger_integrity_snapshot(self.ledger)
        backup_path = self.root / "changed.sqlite3"
        target = sqlite3.connect(str(backup_path))
        try:
            self.ledger._connection.backup(target)
        finally:
            target.close()
        restored = EvidenceVerificationLedger(str(backup_path))
        try:
            second = dict(TASK, task_id="HQ-RESTORE-02")
            restored.propose_many([second])
            changed = build_ledger_integrity_snapshot(restored)
        finally:
            restored.close()
        with self.assertRaisesRegex(
            LedgerRestoreEquivalenceError, "LEDGER_RESTORE_SNAPSHOT_MISMATCH"
        ):
            verify_ledger_restore_equivalence(source, changed)

    def test_ledger_type_mismatch_is_rejected_after_valid_digest_check(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        changed = dict(source)
        changed["ledger_type"] = "OtherLedger"
        self._redigest(changed)
        verify_ledger_integrity_snapshot(changed)
        with self.assertRaisesRegex(
            LedgerRestoreEquivalenceError, "LEDGER_RESTORE_LEDGER_TYPE_MISMATCH"
        ):
            verify_ledger_restore_equivalence(source, changed)

    def test_audit_chain_count_mismatch_is_rejected(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        changed = dict(source)
        changed["audit_chains"] = list(source["audit_chains"]) + [{
            "table": "z_audit_events",
            "event_count": 0,
            "last_sequence": None,
            "head_hash": None,
        }]
        self._redigest(changed)
        verify_ledger_integrity_snapshot(changed)
        with self.assertRaisesRegex(
            LedgerRestoreEquivalenceError, "LEDGER_RESTORE_CHAIN_COUNT_MISMATCH"
        ):
            verify_ledger_restore_equivalence(source, changed)

    def test_tampered_source_checkpoint_is_rejected(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        changed = dict(source)
        changed["snapshot_status"] = "TAMPERED"
        with self.assertRaises(ValueError):
            verify_ledger_restore_equivalence(changed, source)

    def test_tampered_restored_checkpoint_is_rejected(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        changed = dict(source)
        changed["recovery_summary"] = dict(source["recovery_summary"])
        changed["recovery_summary"]["tasks_recovered"] = 999
        with self.assertRaises(ValueError):
            verify_ledger_restore_equivalence(source, changed)

    def test_authorization_claim_cannot_be_made_valid_by_rehashing(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        changed = dict(source)
        changed["execution_authorized"] = True
        self._redigest(changed)
        with self.assertRaises(ValueError):
            verify_ledger_restore_equivalence(source, changed)

    def test_result_contains_only_digests_counts_and_false_authority(self):
        self.ledger.propose_many([TASK])
        source = build_ledger_integrity_snapshot(self.ledger)
        result = verify_ledger_restore_equivalence(source, dict(source))
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(TASK["task_id"], rendered)
        self.assertNotIn("evidence", rendered.lower())
        self.assertEqual(set(result), {
            "status",
            "source_snapshot_digest",
            "restored_snapshot_digest",
            "audit_chain_count",
            "execution_authorized",
            "execution_resumed",
            "automatic_retry",
        })

    def test_inputs_are_not_mutated(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        restored = dict(source)
        before_source = json.dumps(source, sort_keys=True)
        before_restored = json.dumps(restored, sort_keys=True)
        verify_ledger_restore_equivalence(source, restored)
        self.assertEqual(json.dumps(source, sort_keys=True), before_source)
        self.assertEqual(json.dumps(restored, sort_keys=True), before_restored)

    def test_different_valid_task_states_never_compare_equal(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        self.ledger.propose_many([TASK])
        restored = build_ledger_integrity_snapshot(self.ledger)
        with self.assertRaisesRegex(
            LedgerRestoreEquivalenceError, "LEDGER_RESTORE_SNAPSHOT_MISMATCH"
        ):
            verify_ledger_restore_equivalence(source, restored)

    def test_invalid_non_mapping_input_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_ledger_restore_equivalence(None, {})

    def test_restore_equivalence_does_not_claim_payload_or_semantic_restoration(self):
        source = build_ledger_integrity_snapshot(self.ledger)
        result = verify_ledger_restore_equivalence(source, dict(source))
        self.assertNotIn("payloads_restored", result)
        self.assertNotIn("semantic_verification", result)
        self.assertNotIn("identity_authenticated", result)


if __name__ == "__main__":
    unittest.main()
