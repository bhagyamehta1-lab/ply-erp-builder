from __future__ import annotations

import copy
import hashlib
import json
import unittest

from scripts.enterprise_hq_backup_recovery_readiness_snapshot import (
    BackupRecoveryReadinessSnapshotError,
    verify_backup_recovery_readiness_snapshot,
)


def ready_report():
    return {
        "status": "BACKUP_RECOVERY_READINESS_REPORTED",
        "metadata_readiness": "READY",
        "readiness_scope": "METADATA_ONLY",
        "blocker_codes": [],
        "inventory_record_count": 1,
        "observer_backup_count": 1,
        "binding_receipt_count": 1,
        "availability_observation_count": 1,
        "predecessor_link_count": 0,
        "predecessor_available_count": 0,
        "association_coverage": "COMPLETE",
        "availability_reconciliation_status": "RECONCILED",
        "predecessor_availability_status": "NOT_APPLICABLE",
        "recovery_chain_status": "COMPLETE",
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 4,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def not_ready_report():
    value = ready_report()
    value.update({
        "metadata_readiness": "NOT_READY",
        "blocker_codes": [
            "AVAILABILITY_RECONCILIATION_INCOMPLETE",
            "RECOVERY_CHAIN_INCOMPLETE",
        ],
        "availability_observation_count": 0,
        "availability_reconciliation_status": "INCOMPLETE",
        "recovery_chain_status": "INCOMPLETE",
    })
    return value


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def make_record(sequence, report, evaluated_at, previous_hash=None):
    report_digest = digest(report)
    evaluation_id = "hqrr_" + digest({
        "schema_version": "1.0.0",
        "evaluated_at": evaluated_at,
        "report_digest": report_digest,
    })[:24]
    body = {
        "schema_version": "1.0.0",
        "sequence": sequence,
        "evaluation_id": evaluation_id,
        "evaluated_at": evaluated_at,
        "report_digest": report_digest,
        "metadata_readiness": report["metadata_readiness"],
        "blocker_count": len(report["blocker_codes"]),
        "report": report,
        "previous_hash": previous_hash,
    }
    return {**body, "record_hash": digest(body)}


def make_snapshot(records=None):
    records = [] if records is None else records
    return {
        "schema_version": "1.0.0",
        "record_count": len(records),
        "records": records,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


class BackupRecoveryReadinessSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.first = "2026-11-09T08:00:00.000000Z"
        self.second = "2026-11-09T08:01:00.000000Z"
        self.record1 = make_record(1, ready_report(), self.first)
        self.record2 = make_record(
            2, not_ready_report(), self.second, self.record1["record_hash"]
        )

    def reject(self, snapshot):
        with self.assertRaises(BackupRecoveryReadinessSnapshotError):
            verify_backup_recovery_readiness_snapshot(snapshot)

    def test_accepts_empty_history(self):
        result = verify_backup_recovery_readiness_snapshot(make_snapshot())
        self.assertEqual(result["record_count"], 0)
        self.assertIsNone(result["chain_head_hash"])

    def test_accepts_one_ready_record(self):
        result = verify_backup_recovery_readiness_snapshot(make_snapshot([self.record1]))
        self.assertEqual(result["ready_count"], 1)
        self.assertEqual(result["not_ready_count"], 0)

    def test_accepts_mixed_readiness_history(self):
        result = verify_backup_recovery_readiness_snapshot(
            make_snapshot([self.record1, self.record2])
        )
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["ready_count"], 1)
        self.assertEqual(result["not_ready_count"], 1)
        self.assertEqual(result["blocker_count_total"], 2)

    def test_returns_aggregate_fields_only(self):
        result = verify_backup_recovery_readiness_snapshot(make_snapshot([self.record1]))
        self.assertNotIn("records", result)
        self.assertNotIn("report", result)
        self.assertNotIn("backup_id", str(result))
        self.assertFalse(result["execution_authorized"])

    def test_rejects_extra_snapshot_field(self):
        value = make_snapshot([self.record1])
        value["private_payload"] = "forbidden"
        self.reject(value)

    def test_rejects_record_count_mismatch(self):
        value = make_snapshot([self.record1])
        value["record_count"] = 0
        self.reject(value)

    def test_rejects_oversized_history(self):
        value = make_snapshot()
        value["record_count"] = 513
        self.reject(value)

    def test_rejects_artifact_byte_claim(self):
        value = make_snapshot([self.record1])
        value["artifact_bytes_verified"] = True
        self.reject(value)

    def test_rejects_execution_authorization(self):
        value = make_snapshot([self.record1])
        value["execution_authorized"] = True
        self.reject(value)

    def test_rejects_extra_record_field(self):
        value = make_snapshot([self.record1])
        value["records"][0]["source_backup_id"] = "raw-id"
        self.reject(value)

    def test_rejects_extra_report_field(self):
        value = make_snapshot([self.record1])
        value["records"][0]["report"]["filesystem_path"] = "/private"
        self.reject(value)

    def test_rejects_report_digest_tampering(self):
        value = make_snapshot([self.record1])
        value["records"][0]["report_digest"] = "0" * 64
        self.reject(value)

    def test_rejects_record_hash_tampering(self):
        value = make_snapshot([self.record1])
        value["records"][0]["record_hash"] = "0" * 64
        self.reject(value)

    def test_rejects_sequence_gap(self):
        value = make_snapshot([self.record1, self.record2])
        value["records"][1]["sequence"] = 3
        self.reject(value)

    def test_rejects_broken_previous_hash(self):
        value = make_snapshot([self.record1, self.record2])
        value["records"][1]["previous_hash"] = "0" * 64
        self.reject(value)

    def test_rejects_duplicate_evaluation_id(self):
        duplicate = copy.deepcopy(self.record1)
        duplicate["sequence"] = 2
        duplicate["previous_hash"] = self.record1["record_hash"]
        body = {key: duplicate[key] for key in (
            "schema_version", "sequence", "evaluation_id", "evaluated_at",
            "report_digest", "metadata_readiness", "blocker_count", "report",
            "previous_hash",
        )}
        duplicate["record_hash"] = digest(body)
        self.reject(make_snapshot([self.record1, duplicate]))

    def test_rejects_noncanonical_timestamp(self):
        value = make_snapshot([self.record1])
        value["records"][0]["evaluated_at"] = "2026-11-09T08:00:00Z"
        self.reject(value)

    def test_rejects_timestamp_regression(self):
        first = make_record(1, ready_report(), self.second)
        second = make_record(2, not_ready_report(), self.first, first["record_hash"])
        self.reject(make_snapshot([first, second]))

    def test_rejects_invalid_evaluation_id(self):
        value = make_snapshot([self.record1])
        value["records"][0]["evaluation_id"] = "invalid"
        self.reject(value)

    def test_rejects_readiness_classification_mismatch(self):
        value = make_snapshot([self.record1])
        value["records"][0]["metadata_readiness"] = "NOT_READY"
        self.reject(value)

    def test_rejects_blocker_count_mismatch(self):
        value = make_snapshot([self.record2])
        value["records"][0]["blocker_count"] = 1
        self.reject(value)

    def test_rejects_ready_report_with_blockers(self):
        report = ready_report()
        report["blocker_codes"] = ["RECOVERY_CHAIN_INCOMPLETE"]
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_not_ready_report_without_blockers(self):
        report = not_ready_report()
        report["blocker_codes"] = []
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_report_execution_escalation(self):
        report = ready_report()
        report["execution_authorized"] = True
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_wrong_source_ledger_count(self):
        report = ready_report()
        report["source_ledger_verification_count"] = 3
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_inconsistent_complete_association(self):
        report = ready_report()
        report["inventory_record_count"] = 2
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_predecessor_count_overflow(self):
        report = ready_report()
        report["predecessor_available_count"] = 1
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_unknown_blocker(self):
        report = not_ready_report()
        report["blocker_codes"] = ["UNRECOGNIZED"]
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_wrong_blocker_order(self):
        report = not_ready_report()
        report["blocker_codes"].reverse()
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)

    def test_rejects_unknown_recovery_state(self):
        report = not_ready_report()
        report["recovery_chain_status"] = "MAYBE"
        value = make_snapshot([make_record(1, report, self.first)])
        self.reject(value)


if __name__ == "__main__":
    unittest.main()
