"""Regression tests for read-only backup predecessor availability verification."""
from __future__ import annotations

import hashlib
import unittest

from scripts.enterprise_hq_backup_generation_continuity import (
    reconcile_backup_generation_continuity,
)
from scripts.enterprise_hq_backup_predecessor_availability import (
    BackupPredecessorAvailabilityError,
    verify_backup_predecessor_availability_snapshot,
)

AVAILABILITY_STATUS = {
    "AVAILABLE": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED",
    "MISSING": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISSING",
    "UNAVAILABLE": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNAVAILABLE",
    "INVALID": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_INVALID",
    "MISMATCH": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISMATCH",
    "UNKNOWN": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
}


def make_receipt(sequence, predecessor=None):
    file_digest = hashlib.sha256(f"backup-{sequence}".encode()).hexdigest()
    count = 1
    return {
        "backup_count": sequence,
        "backup_id": "hqfb_" + file_digest[:24],
        "file_sha256": file_digest,
        "source_receipt_count": count,
        "source_status_counts": {"FRESH": count},
        "last_source_sequence": count,
        "source_chain_head_digest": hashlib.sha256(
            f"source-{sequence}".encode()
        ).hexdigest(),
        "predecessor_backup_id": predecessor,
        "record_hash": hashlib.sha256(f"receipt-{sequence}".encode()).hexdigest(),
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def make_observation(receipt, sequence, state="AVAILABLE", **overrides):
    row = {
        "status": AVAILABILITY_STATUS[state],
        "availability": state,
        "backup_id": receipt["backup_id"],
        "lineage_sequence": None if state == "UNKNOWN" else receipt["backup_count"],
        "lineage_record_hash": None if state == "UNKNOWN" else receipt["record_hash"],
        "observation_id": "hqba_" + hashlib.sha256(
            f"observation-{sequence}".encode()
        ).hexdigest()[:24],
        "sequence": sequence,
        "record_hash": hashlib.sha256(f"observation-record-{sequence}".encode()).hexdigest(),
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }
    if state == "AVAILABLE":
        row.update({
            "file_sha256": receipt["file_sha256"],
            "source_receipt_count": receipt["source_receipt_count"],
            "source_status_counts": dict(receipt["source_status_counts"]),
            "last_source_sequence": receipt["last_source_sequence"],
            "source_chain_head_digest": receipt["source_chain_head_digest"],
        })
    row.update(overrides)
    return row


class FakeSource:
    def __init__(self, summary, *, rows=None, snapshot=None, mutate=False):
        self.summary = dict(summary)
        self.rows = [] if rows is None else rows
        self.snapshot = snapshot
        self.calls = 0
        self.mutate = mutate

    def verify(self):
        self.calls += 1
        result = dict(self.summary)
        if self.mutate and self.calls >= 2:
            result["chain_head"] = "f" * 64
        return result

    def list_backup_metadata(self):
        return self.rows

    def list_backup_receipts(self):
        return self.rows

    def export_verification_snapshot(self):
        return self.snapshot

    def list_latest_observations(self):
        return self.rows


class BackupPredecessorAvailabilityTests(unittest.TestCase):
    def verify(self, receipts=None, observations=None):
        return verify_backup_predecessor_availability_snapshot(
            [] if receipts is None else receipts,
            [] if observations is None else observations,
        )

    def reject(self, receipts=None, observations=None, code=""):
        with self.assertRaisesRegex(BackupPredecessorAvailabilityError, code):
            self.verify(receipts, observations)

    def chain(self):
        first = make_receipt(1)
        second = make_receipt(2, first["backup_id"])
        return first, second

    def test_empty_histories_report_no_backups(self):
        result = self.verify()
        self.assertEqual(result["recovery_chain_status"], "NO_BACKUPS")
        self.assertEqual(result["predecessor_availability_status"], "NOT_APPLICABLE")

    def test_genesis_backup_available_is_complete(self):
        first = make_receipt(1)
        result = self.verify([first], [make_observation(first, 1)])
        self.assertEqual(result["recovery_chain_status"], "COMPLETE")
        self.assertEqual(result["matched_available_backup_count"], 1)
        self.assertEqual(result["predecessor_link_count"], 0)

    def test_complete_two_generation_chain_requires_available_predecessor(self):
        first, second = self.chain()
        result = self.verify(
            [first, second],
            [make_observation(first, 1), make_observation(second, 2)],
        )
        self.assertEqual(result["recovery_chain_status"], "COMPLETE")
        self.assertEqual(result["predecessor_availability_status"], "VERIFIED")
        self.assertEqual(result["predecessor_available_count"], 1)

    def test_available_latest_backup_is_blocked_when_predecessor_is_missing(self):
        first, second = self.chain()
        result = self.verify([first, second], [make_observation(second, 2)])
        self.assertEqual(
            result["recovery_chain_status"], "BLOCKED_PREDECESSOR_UNAVAILABLE"
        )
        self.assertEqual(result["predecessor_missing_observation_count"], 1)

    def test_missing_predecessor_state_blocks_recovery(self):
        first, second = self.chain()
        result = self.verify(
            [first, second],
            [make_observation(first, 1, "MISSING"), make_observation(second, 2)],
        )
        self.assertEqual(result["recovery_chain_status"], "BLOCKED_PREDECESSOR_UNAVAILABLE")
        self.assertEqual(result["predecessor_nonavailable_count"], 1)

    def test_unavailable_predecessor_state_blocks_recovery(self):
        first, second = self.chain()
        result = self.verify(
            [first, second],
            [make_observation(first, 1, "UNAVAILABLE"), make_observation(second, 2)],
        )
        self.assertEqual(result["predecessor_nonavailable_count"], 1)
        self.assertEqual(result["predecessor_availability_status"], "BLOCKED")

    def test_unknown_predecessor_state_blocks_recovery(self):
        first, second = self.chain()
        result = self.verify(
            [first, second],
            [make_observation(first, 1, "UNKNOWN"), make_observation(second, 2)],
        )
        self.assertEqual(result["predecessor_unknown_observation_count"], 1)
        self.assertEqual(result["recovery_chain_status"], "BLOCKED_PREDECESSOR_UNAVAILABLE")

    def test_current_backup_missing_state_is_incomplete(self):
        first = make_receipt(1)
        result = self.verify([first], [make_observation(first, 1, "MISSING")])
        self.assertEqual(result["availability_reconciliation_status"], "RECONCILED")
        self.assertEqual(result["recovery_chain_status"], "INCOMPLETE")

    def test_current_backup_without_observation_is_incomplete(self):
        first = make_receipt(1)
        result = self.verify([first], [])
        self.assertEqual(result["missing_availability_observation_count"], 1)
        self.assertEqual(result["recovery_chain_status"], "INCOMPLETE")

    def test_unknown_observation_is_not_treated_as_available(self):
        first = make_receipt(1)
        result = self.verify([first], [make_observation(first, 1, "UNKNOWN")])
        self.assertEqual(result["unknown_availability_observation_count"], 1)
        self.assertEqual(result["recovery_chain_status"], "INCOMPLETE")

    def test_lineage_mismatch_is_counted_and_fails_readiness(self):
        first = make_receipt(1)
        observation = make_observation(first, 1, lineage_record_hash="0" * 64)
        result = self.verify([first], [observation])
        self.assertEqual(result["availability_lineage_mismatch_count"], 1)
        self.assertEqual(result["recovery_chain_status"], "INCOMPLETE")

    def test_available_evidence_mismatch_is_counted(self):
        first = make_receipt(1)
        observation = make_observation(first, 1, file_sha256="0" * 64)
        result = self.verify([first], [observation])
        self.assertEqual(result["availability_evidence_mismatch_count"], 1)
        self.assertEqual(result["matched_available_backup_count"], 0)

    def test_nonavailable_observation_with_matching_lineage_reconciles(self):
        first = make_receipt(1)
        result = self.verify([first], [make_observation(first, 1, "INVALID")])
        self.assertEqual(result["availability_reconciliation_status"], "RECONCILED")
        self.assertEqual(result["matched_nonavailable_backup_count"], 1)

    def test_orphan_nonunknown_observation_is_counted(self):
        first = make_receipt(1)
        orphan = make_receipt(2)
        result = self.verify([first], [make_observation(orphan, 1)])
        self.assertEqual(result["orphan_availability_observation_count"], 1)
        self.assertEqual(result["availability_reconciliation_status"], "INCOMPLETE")

    def test_unknown_observation_without_receipt_is_counted_as_unknown(self):
        unknown = make_receipt(1)
        result = self.verify([], [make_observation(unknown, 1, "UNKNOWN")])
        self.assertEqual(result["unknown_availability_observation_count"], 1)
        self.assertEqual(result["orphan_availability_observation_count"], 0)

    def test_rejects_receipt_sequence_gap(self):
        first, second = self.chain()
        second["backup_count"] = 3
        self.reject([first, second], [], "RECEIPT_SEQUENCE_INVALID")

    def test_rejects_duplicate_receipt_identity(self):
        first = make_receipt(1)
        duplicate = make_receipt(2, first["backup_id"])
        duplicate["file_sha256"] = first["file_sha256"]
        duplicate["backup_id"] = first["backup_id"]
        self.reject([first, duplicate], [], "RECEIPT_DUPLICATE_ID")

    def test_rejects_receipt_predecessor_mismatch(self):
        first = make_receipt(1)
        second = make_receipt(2, "hqfb_" + "f" * 24)
        self.reject([first, second], [], "RECEIPT_LINEAGE_INVALID")

    def test_rejects_receipt_identifier_not_derived_from_file_digest(self):
        first = make_receipt(1)
        first["backup_id"] = "hqfb_" + "f" * 24
        self.reject([first], [], "RECEIPT_ID_INVALID")

    def test_rejects_receipt_authorization_escalation(self):
        first = make_receipt(1)
        first["automatic_dispatch"] = True
        self.reject([first], [], "AUTHORIZATION_INVALID")

    def test_rejects_observation_with_extra_field(self):
        first = make_receipt(1)
        observation = make_observation(first, 1)
        observation["filesystem_path"] = "/tmp/private"
        self.reject([first], [observation], "OBSERVATION_SCHEMA_INVALID")

    def test_rejects_invalid_observation_state(self):
        first = make_receipt(1)
        observation = make_observation(first, 1)
        observation["availability"] = "READY"
        self.reject([first], [observation], "STATE_INVALID")

    def test_rejects_observation_status_mismatch(self):
        first = make_receipt(1)
        observation = make_observation(first, 1)
        observation["status"] = "WRONG"
        self.reject([first], [observation], "STATUS_MISMATCH")

    def test_rejects_duplicate_observation_for_backup(self):
        first = make_receipt(1)
        self.reject(
            [first],
            [make_observation(first, 1), make_observation(first, 2)],
            "DUPLICATE_OBSERVATION",
        )

    def test_rejects_duplicate_observation_sequence(self):
        first, second = self.chain()
        one = make_observation(first, 1)
        two = make_observation(second, 1)
        self.reject([first, second], [one, two], "DUPLICATE_SEQUENCE")

    def test_rejects_invalid_observation_identifier(self):
        first = make_receipt(1)
        observation = make_observation(first, 1, observation_id="bad")
        self.reject([first], [observation], "OBSERVATION_IDENTITY_INVALID")

    def test_rejects_unknown_observation_with_lineage(self):
        first = make_receipt(1)
        observation = make_observation(first, 1, "UNKNOWN", lineage_sequence=1)
        self.reject([first], [observation], "UNKNOWN_LINEAGE_INVALID")

    def test_rejects_available_evidence_count_mismatch(self):
        first = make_receipt(1)
        observation = make_observation(first, 1, source_receipt_count=2)
        self.reject([first], [observation], "EVIDENCE_INVALID")

    def test_result_contains_aggregate_counts_only_and_no_authority(self):
        first, second = self.chain()
        result = self.verify(
            [first, second],
            [make_observation(first, 1), make_observation(second, 2)],
        )
        rendered = str(result)
        self.assertNotIn(first["backup_id"], rendered)
        self.assertNotIn(second["backup_id"], rendered)
        self.assertNotIn(first["file_sha256"], rendered)
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_orchestrator_integrates_fourth_availability_ledger(self):
        first, second = self.chain()
        inventory = FakeSource({"status": "INVENTORY_VALID"}, rows=[])
        observer = FakeSource({"status": "OBSERVER_VALID"}, rows=[first, second])
        binding_snapshot = {
            "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_EXPORTED",
            "schema_version": "1.1.0",
            "receipt_count": 0,
            "records": [],
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }
        binding = FakeSource({"status": "BINDING_VALID"}, snapshot=binding_snapshot)
        availability = FakeSource(
            {"status": "AVAILABILITY_VALID", "chain_head": "a" * 64},
            rows=[make_observation(first, 1), make_observation(second, 2)],
        )
        result = reconcile_backup_generation_continuity(
            inventory, observer, binding, availability
        )
        self.assertEqual(result["source_ledger_verification_count"], 4)
        self.assertEqual(result["predecessor_availability_status"], "VERIFIED")
        self.assertEqual(result["recovery_chain_status"], "COMPLETE")
        self.assertGreaterEqual(availability.calls, 2)

    def test_orchestrator_fails_closed_when_availability_ledger_changes(self):
        first = make_receipt(1)
        inventory = FakeSource({"status": "INVENTORY_VALID"}, rows=[])
        observer = FakeSource({"status": "OBSERVER_VALID"}, rows=[first])
        binding_snapshot = {
            "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_EXPORTED",
            "schema_version": "1.1.0",
            "receipt_count": 0,
            "records": [],
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }
        binding = FakeSource({"status": "BINDING_VALID"}, snapshot=binding_snapshot)
        availability = FakeSource(
            {"status": "AVAILABILITY_VALID", "chain_head": "a" * 64},
            rows=[make_observation(first, 1)],
            mutate=True,
        )
        with self.assertRaisesRegex(ValueError, "SOURCE_SNAPSHOT_CHANGED"):
            reconcile_backup_generation_continuity(
                inventory, observer, binding, availability
            )


if __name__ == "__main__":
    unittest.main()
