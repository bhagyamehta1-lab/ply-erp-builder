from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import scripts.enterprise_hq_observer_freshness_backup_availability_ledger as availability_module
import scripts.enterprise_hq_observer_freshness_backup_receipts as receipt_module
from scripts.enterprise_hq_backup_artifact_binding import (
    BackupArtifactBindingError,
    verify_backup_artifact_binding,
)
from scripts.enterprise_hq_backup_inventory import (
    BackupInventoryCorruptionError,
    LedgerBackupInventory,
)
from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import build_ledger_integrity_snapshot
from scripts.enterprise_hq_observer_freshness_backup_availability_ledger import (
    ObserverFreshnessBackupAvailabilityLedger,
    ObserverFreshnessBackupAvailabilityLedgerCorruptionError,
)
from scripts.enterprise_hq_observer_freshness_backup_receipts import (
    ObserverFreshnessBackupReceiptLedger,
    ObserverFreshnessBackupReceiptCorruptionError,
)


class BackupArtifactBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 11, 9, 0, 0, tzinfo=timezone.utc)
        self.source = EvidenceVerificationLedger(str(self.root / "source.sqlite3"))
        self.restore_path = self.root / "restored.sqlite3"
        self.source_snapshot, self.restored_snapshot = self._make_equal_snapshots()
        self.inventory = LedgerBackupInventory(str(self.root / "inventory.sqlite3"))
        self.inventory_id = "hqbk_0123456789abcdef01234567"
        entry = {
            "backup_id": self.inventory_id,
            "ledger_type": self.source_snapshot["ledger_type"],
            "declared_size_bytes": 4096,
            "created_at": self._at(0),
            "retain_until": self._at(0, days=30),
            "generation": 1,
            "predecessor_backup_id": None,
            "storage_scope": "LOCAL_ONLY",
        }
        self.inventory.record_backup(
            entry, self.source_snapshot, self.restored_snapshot, now=self.now
        )
        self.inventory_record = self.inventory.get_backup_metadata(self.inventory_id)

        self.receipts = ObserverFreshnessBackupReceiptLedger(
            str(self.root / "receipts.sqlite3")
        )
        self.file_digest = hashlib.sha256(b"verified-observer-backup").hexdigest()
        self.receipt = self.receipts.append_backup(
            {
                "status": "OBSERVER_FRESHNESS_BACKUP_VERIFIED",
                "file_sha256": self.file_digest,
                "receipt_count": 2,
                "status_counts": {"FRESH": 2},
                "last_sequence": 2,
                "chain_head_digest": hashlib.sha256(b"source-chain-head").hexdigest(),
                "equivalence_verified": True,
                "execution_authorized": False,
                "automatic_dispatch": False,
                "automatic_retry": False,
            },
            recorded_at=self._at(1),
        )
        self.receipt_record = self.receipts.get_backup_receipt(self.receipt["backup_id"])
        self.availability = ObserverFreshnessBackupAvailabilityLedger(
            str(self.root / "availability.sqlite3")
        )
        self.observation_seconds = 2

    def tearDown(self):
        self.availability.close()
        self.receipts.close()
        self.inventory.close()
        self.source.close()
        self.temp.cleanup()

    def _at(self, seconds, days=0):
        return (self.now + timedelta(seconds=seconds, days=days)).isoformat().replace("+00:00", "Z")

    def _make_equal_snapshots(self):
        source_snapshot = build_ledger_integrity_snapshot(self.source)
        target = sqlite3.connect(str(self.restore_path))
        try:
            self.source._connection.backup(target)
        finally:
            target.close()
        self.restore_path.chmod(0o600)
        restored = EvidenceVerificationLedger(str(self.restore_path))
        try:
            restored_snapshot = build_ledger_integrity_snapshot(restored)
        finally:
            restored.close()
        return source_snapshot, restored_snapshot

    def add_available(self, **overrides):
        details = self.receipts.get_backup_receipt(self.receipt["backup_id"])
        result = {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED",
            "availability": "AVAILABLE",
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": details["backup_id"],
            "lineage_sequence": details["backup_count"],
            "lineage_record_hash": details["record_hash"],
            "file_sha256": details["file_sha256"],
            "source_receipt_count": details["source_receipt_count"],
            "source_status_counts": details["source_status_counts"],
            "last_source_sequence": details["last_source_sequence"],
            "source_chain_head_digest": details["source_chain_head_digest"],
            "backup_integrity_verified": True,
            "lineage_match_verified": True,
        }
        result.update(overrides)
        saved = self.availability.append_observation(
            result, recorded_at=self._at(self.observation_seconds)
        )
        self.observation_seconds += 1
        return saved

    def add_nonavailable(self, state="MISSING"):
        details = self.receipts.get_backup_receipt(self.receipt["backup_id"])
        saved = self.availability.append_observation(
            {
                "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_" + state,
                "availability": state,
                "execution_authorized": False,
                "automatic_dispatch": False,
                "automatic_retry": False,
                "backup_id": details["backup_id"],
                "lineage_sequence": details["backup_count"],
                "lineage_record_hash": details["record_hash"],
            },
            recorded_at=self._at(self.observation_seconds),
        )
        self.observation_seconds += 1
        return saved

    def binding(self, **overrides):
        value = {
            "inventory_backup_id": self.inventory_id,
            "inventory_entry_digest": self.inventory_record["entry_digest"],
            "observer_backup_id": self.receipt["backup_id"],
            "observer_file_sha256": self.file_digest,
        }
        value.update(overrides)
        return value

    def verify(self, binding=None):
        return verify_backup_artifact_binding(
            self.inventory, self.receipts, self.availability,
            self.binding() if binding is None else binding,
        )

    def test_verified_explicit_association_returns_deterministic_metadata_binding(self):
        self.add_available()
        result = self.verify()
        self.assertEqual(result["status"], "BACKUP_ARTIFACT_BINDING_VERIFIED")
        self.assertEqual(result["binding_status"], "METADATA_ASSOCIATION_VERIFIED")
        self.assertEqual(result["binding_basis"], "EXPLICIT_CALLER_ASSOCIATION")
        self.assertEqual(len(result["binding_digest"]), 64)
        self.assertEqual(result["availability"], "AVAILABLE")

    def test_repeated_verification_produces_same_binding_digest(self):
        self.add_available()
        first = self.verify()
        second = self.verify()
        self.assertEqual(first["binding_digest"], second["binding_digest"])

    def test_inventory_metadata_lookup_returns_only_bounded_metadata(self):
        result = self.inventory.get_backup_metadata(self.inventory_id)
        self.assertEqual(result["status"], "BACKUP_METADATA_FOUND")
        self.assertEqual(result["artifact_presence"], "NOT_INSPECTED")
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertTrue({"path", "database", "payload", "created_at", "retain_until"}.isdisjoint(result))

    def test_missing_inventory_entry_is_rejected(self):
        self.add_available()
        with self.assertRaisesRegex(BackupArtifactBindingError, "INVENTORY_RECORD_NOT_FOUND"):
            self.verify(self.binding(
                inventory_backup_id="hqbk_" + "a" * 24,
                inventory_entry_digest="a" * 64,
            ))

    def test_missing_observer_receipt_is_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingError, "RECEIPT_NOT_FOUND"):
            self.verify(self.binding(
                observer_backup_id="hqfb_" + "a" * 24,
                observer_file_sha256=hashlib.sha256(b"other").hexdigest(),
            ))

    def test_missing_availability_observation_is_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingError, "AVAILABILITY_OBSERVATION_NOT_FOUND"):
            self.verify()

    def test_nonavailable_observation_is_rejected(self):
        self.add_nonavailable("MISSING")
        with self.assertRaisesRegex(BackupArtifactBindingError, "ARTIFACT_NOT_AVAILABLE"):
            self.verify()

    def test_unknown_observation_is_not_accepted(self):
        self.availability.append_observation(
            {
                "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
                "availability": "UNKNOWN",
                "execution_authorized": False,
                "automatic_dispatch": False,
                "automatic_retry": False,
                "backup_id": self.receipt["backup_id"],
                "lineage_sequence": None,
                "lineage_record_hash": None,
            },
            recorded_at=self._at(self.observation_seconds),
        )
        with self.assertRaisesRegex(BackupArtifactBindingError, "ARTIFACT_NOT_AVAILABLE"):
            self.verify()

    def test_inventory_entry_digest_mismatch_is_rejected(self):
        self.add_available()
        with self.assertRaisesRegex(BackupArtifactBindingError, "INVENTORY_EVIDENCE_MISMATCH"):
            self.verify(self.binding(inventory_entry_digest="a" * 64))

    def test_observer_file_digest_mismatch_is_rejected(self):
        self.add_available()
        with self.assertRaisesRegex(BackupArtifactBindingError, "RECEIPT_EVIDENCE_MISMATCH"):
            self.verify(self.binding(observer_file_sha256="b" * 64))

    def test_availability_file_digest_mismatch_is_rejected(self):
        self.add_available(file_sha256="c" * 64)
        with self.assertRaisesRegex(BackupArtifactBindingError, "AVAILABILITY_EVIDENCE_MISMATCH"):
            self.verify()

    def test_availability_lineage_sequence_mismatch_is_rejected(self):
        self.add_available(lineage_sequence=2)
        with self.assertRaisesRegex(BackupArtifactBindingError, "AVAILABILITY_EVIDENCE_MISMATCH"):
            self.verify()

    def test_availability_lineage_hash_mismatch_is_rejected(self):
        self.add_available(lineage_record_hash="d" * 64)
        with self.assertRaisesRegex(BackupArtifactBindingError, "AVAILABILITY_EVIDENCE_MISMATCH"):
            self.verify()

    def test_availability_source_summary_mismatch_is_rejected(self):
        self.add_available(
            source_receipt_count=3,
            source_status_counts={"FRESH": 3},
            last_source_sequence=3,
        )
        with self.assertRaisesRegex(BackupArtifactBindingError, "AVAILABILITY_EVIDENCE_MISMATCH"):
            self.verify()

    def test_corrupt_inventory_fails_closed(self):
        self.add_available()
        self.inventory._connection.execute(
            "UPDATE ledger_backup_inventory SET entry_digest = ? WHERE backup_id = ?",
            ("0" * 64, self.inventory_id),
        )
        with self.assertRaises(BackupInventoryCorruptionError):
            self.verify()

    def test_corrupt_receipt_ledger_fails_closed(self):
        self.add_available()
        self.receipts._connection.execute(
            "DROP TRIGGER observer_freshness_backup_receipts_no_update"
        )
        self.receipts._connection.execute(
            f"UPDATE {receipt_module._TABLE} SET record_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        self.receipts._connection.commit()
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            self.verify()

    def test_corrupt_availability_ledger_fails_closed(self):
        self.add_available()
        self.availability._connection.execute(
            f"DROP TRIGGER {availability_module._UPDATE_TRIGGER}"
        )
        self.availability._connection.execute(
            f"UPDATE {availability_module._TABLE} SET record_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        self.availability._connection.commit()
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerCorruptionError):
            self.verify()

    def test_wrong_ledger_types_are_rejected(self):
        self.add_available()
        with self.assertRaises(BackupArtifactBindingError):
            verify_backup_artifact_binding(object(), self.receipts, self.availability, self.binding())
        with self.assertRaises(BackupArtifactBindingError):
            verify_backup_artifact_binding(self.inventory, object(), self.availability, self.binding())
        with self.assertRaises(BackupArtifactBindingError):
            verify_backup_artifact_binding(self.inventory, self.receipts, object(), self.binding())

    def test_extra_binding_fields_are_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingError, "SCHEMA_INVALID"):
            self.verify(self.binding(path="/tmp/not-allowed"))

    def test_invalid_identifiers_and_digests_are_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingError, "INVENTORY_ID_INVALID"):
            self.verify(self.binding(inventory_backup_id="../private.sqlite3"))
        with self.assertRaisesRegex(BackupArtifactBindingError, "FILE_DIGEST_INVALID"):
            self.verify(self.binding(observer_file_sha256="../private.sqlite3"))

    def test_source_ledgers_remain_unchanged(self):
        self.add_available()
        before = (
            self.inventory.verify(),
            self.receipts.verify(),
            self.availability.verify(),
        )
        self.verify()
        after = (
            self.inventory.verify(),
            self.receipts.verify(),
            self.availability.verify(),
        )
        self.assertEqual(before, after)

    def test_concurrent_source_append_invalidates_snapshot(self):
        self.add_available()
        original = self.availability.list_latest_observations

        def append_during_read():
            rows = original()
            self.add_nonavailable("MISSING")
            return rows

        with patch.object(
            self.availability, "list_latest_observations", side_effect=append_during_read
        ):
            with self.assertRaisesRegex(
                BackupArtifactBindingError, "SOURCE_SNAPSHOT_CHANGED"
            ):
                self.verify()

    def test_result_contains_no_identifiers_paths_or_payloads(self):
        self.add_available()
        result = self.verify()
        forbidden = {
            "inventory_backup_id", "observer_backup_id", "observation_id",
            "file_sha256", "entry_digest", "record_hash", "path", "database",
            "payload", "created_at",
        }
        self.assertTrue(forbidden.isdisjoint(result))

    def test_execution_and_artifact_byte_claims_remain_false(self):
        self.add_available()
        result = self.verify()
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])
        self.assertFalse(result["artifact_bytes_verified"])

    def test_inventory_artifact_presence_remains_not_inspected(self):
        self.add_available()
        result = self.verify()
        self.assertEqual(result["inventory_artifact_presence"], "NOT_INSPECTED")
        self.assertFalse(result["artifact_bytes_verified"])


    def test_association_commitments_are_domain_separated_and_stable(self):
        self.add_available()
        result = self.verify()
        expected_inventory = hashlib.sha256(
            ("enterprise-hq-backup-association:v1:inventory:" + self.inventory_id).encode("ascii")
        ).hexdigest()
        expected_observer = hashlib.sha256(
            ("enterprise-hq-backup-association:v1:observer:" + self.receipt["backup_id"]).encode("ascii")
        ).hexdigest()
        self.assertEqual(result["inventory_association_digest"], expected_inventory)
        self.assertEqual(result["observer_association_digest"], expected_observer)
        self.assertNotEqual(expected_inventory, expected_observer)
        self.assertNotIn(self.inventory_id, repr(result))
        self.assertNotIn(self.receipt["backup_id"], repr(result))

if __name__ == "__main__":
    unittest.main()
