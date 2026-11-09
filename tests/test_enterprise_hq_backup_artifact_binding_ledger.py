from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import scripts.enterprise_hq_backup_artifact_binding_ledger as ledger_module
from scripts.enterprise_hq_backup_artifact_binding_ledger import (
    BackupArtifactBindingLedger,
    BackupArtifactBindingLedgerCorruptionError,
    BackupArtifactBindingLedgerError,
)


class BackupArtifactBindingLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "binding-receipts.sqlite3"
        self.now = datetime(2026, 11, 9, 2, 0, tzinfo=timezone.utc)
        self.ledger = BackupArtifactBindingLedger(str(self.path))

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def at(self, seconds=0):
        return (self.now + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    def result(self, digest=None, **overrides):
        value = {
            "status": "BACKUP_ARTIFACT_BINDING_VERIFIED",
            "binding_status": "METADATA_ASSOCIATION_VERIFIED",
            "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
            "binding_digest": digest or hashlib.sha256(b"binding-one").hexdigest(),
            "inventory_record_count": 3,
            "inventory_generation": 2,
            "observer_backup_sequence": 4,
            "availability_observation_sequence": 7,
            "availability": "AVAILABLE",
            "inventory_artifact_presence": "NOT_INSPECTED",
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }
        value.update(overrides)
        return value

    def append(self, result=None, seconds=0):
        return self.ledger.append_verified_binding(
            self.result() if result is None else result, recorded_at=self.at(seconds)
        )

    def test_empty_ledger_verifies(self):
        result = self.ledger.verify()
        self.assertEqual(result["receipt_count"], 0)
        self.assertIsNone(result["chain_head_hash"])

    def test_valid_binding_is_recorded(self):
        receipt = self.append()
        self.assertEqual(receipt["status"], "BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED")
        self.assertTrue(receipt["receipt_id"].startswith("hqbr_"))
        self.assertEqual(len(receipt["record_hash"]), 64)

    def test_receipt_identifier_is_deterministic(self):
        first = self.append()
        other = BackupArtifactBindingLedger(":memory:")
        try:
            second = other.append_verified_binding(self.result(), recorded_at=self.at())
        finally:
            other.close()
        self.assertEqual(first["receipt_id"], second["receipt_id"])

    def test_exact_replay_is_idempotent_even_with_later_time(self):
        first = self.append()
        replay = self.append(seconds=60)
        self.assertEqual(replay["status"], "BACKUP_ARTIFACT_BINDING_RECEIPT_REPLAYED")
        self.assertEqual(replay["receipt_id"], first["receipt_id"])
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)

    def test_changed_metadata_for_same_digest_is_rejected(self):
        self.append()
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "RECEIPT_CONFLICT"):
            self.append(self.result(inventory_generation=3), seconds=1)

    def test_new_binding_appends_successor(self):
        first = self.append()
        second = self.append(self.result(hashlib.sha256(b"binding-two").hexdigest()), seconds=1)
        self.assertEqual(second["sequence"], 2)
        self.assertNotEqual(first["record_hash"], second["record_hash"])
        self.assertEqual(self.ledger.verify()["receipt_count"], 2)

    def test_invalid_result_schema_is_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "SCHEMA_INVALID"):
            self.ledger.append_verified_binding({"binding_digest": "a" * 64})

    def test_extra_path_or_payload_field_is_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "SCHEMA_INVALID"):
            self.append(self.result(path="/tmp/private.sqlite3"))

    def test_nonverified_binding_status_is_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "STATUS_INVALID"):
            self.append(self.result(binding_status="UNVERIFIED"))

    def test_nonexplicit_binding_basis_is_rejected(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "STATUS_INVALID"):
            self.append(self.result(binding_basis="INFERRED"))

    def test_digest_format_is_validated(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "DIGEST_INVALID"):
            self.append(self.result("not-a-digest"))

    def test_counts_must_be_bounded_integers(self):
        for field, value in (
            ("inventory_record_count", True),
            ("inventory_generation", 0),
            ("observer_backup_sequence", 257),
            ("availability_observation_sequence", 513),
        ):
            with self.subTest(field=field):
                with self.assertRaises(BackupArtifactBindingLedgerError):
                    self.append(self.result(**{field: value}))

    def test_artifact_bytes_must_remain_unverified(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "AUTHORIZATION_INVALID"):
            self.append(self.result(artifact_bytes_verified=True))

    def test_execution_and_dispatch_flags_must_remain_false(self):
        for field in ("execution_authorized", "automatic_dispatch", "automatic_retry"):
            with self.subTest(field=field):
                with self.assertRaises(BackupArtifactBindingLedgerError):
                    self.append(self.result(**{field: True}))

    def test_availability_must_be_available(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "STATUS_INVALID"):
            self.append(self.result(availability="MISSING"))

    def test_inventory_artifact_presence_must_remain_not_inspected(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "STATUS_INVALID"):
            self.append(self.result(inventory_artifact_presence="PRESENT"))

    def test_recorded_at_requires_utc(self):
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "RECORDED_AT_INVALID"):
            self.ledger.append_verified_binding(self.result(), recorded_at="2026-11-09T02:00:00")

    def test_timestamp_regression_is_rejected(self):
        self.append(seconds=10)
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "TIME_REGRESSION"):
            self.append(self.result(hashlib.sha256(b"binding-two").hexdigest()), seconds=9)

    def test_lookup_returns_receipt_without_source_identifiers(self):
        receipt = self.append()
        found = self.ledger.get_receipt(self.result()["binding_digest"])
        self.assertEqual(found["receipt_id"], receipt["receipt_id"])
        self.assertTrue({
            "inventory_backup_id", "observer_backup_id", "file_sha256",
            "path", "database", "payload",
        }.isdisjoint(found))

    def test_missing_lookup_is_aggregate_only(self):
        found = self.ledger.get_receipt("a" * 64)
        self.assertEqual(found["status"], "BACKUP_ARTIFACT_BINDING_RECEIPT_NOT_FOUND")
        self.assertFalse(found["execution_authorized"])

    def test_list_receipts_is_bounded_and_ordered(self):
        self.append()
        self.append(self.result(hashlib.sha256(b"binding-two").hexdigest()), seconds=1)
        rows = self.ledger.list_receipts()
        self.assertEqual([row["sequence"] for row in rows], [1, 2])

    def test_restart_recovery_verifies_history(self):
        self.append()
        self.ledger.close()
        self.ledger = BackupArtifactBindingLedger(str(self.path))
        recovered = self.ledger.recover_after_restart()
        self.assertEqual(recovered["status"], "BACKUP_ARTIFACT_BINDING_RECEIPT_RECOVERY_VERIFIED")
        self.assertEqual(recovered["receipt_count"], 1)

    def test_update_trigger_rejects_mutation(self):
        self.append()
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                f"UPDATE {ledger_module._TABLE} SET inventory_generation = 9 WHERE sequence = 1"
            )

    def test_delete_trigger_rejects_mutation(self):
        self.append()
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                f"DELETE FROM {ledger_module._TABLE} WHERE sequence = 1"
            )

    def test_missing_append_only_trigger_is_rejected(self):
        self.ledger._connection.execute(f"DROP TRIGGER {ledger_module._UPDATE_TRIGGER}")
        with self.assertRaisesRegex(BackupArtifactBindingLedgerCorruptionError, "TRIGGER_SET_INVALID"):
            self.ledger.verify()

    def test_unexpected_table_is_rejected(self):
        self.ledger._connection.execute("CREATE TABLE unexpected_private_payload(value TEXT)")
        with self.assertRaisesRegex(BackupArtifactBindingLedgerCorruptionError, "TABLE_SET_INVALID"):
            self.ledger.verify()

    def test_record_hash_tampering_is_detected(self):
        self.append()
        self.ledger._connection.execute(
            f"DROP TRIGGER {ledger_module._UPDATE_TRIGGER}"
        )
        self.ledger._connection.execute(
            f"UPDATE {ledger_module._TABLE} SET record_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        with self.assertRaises(BackupArtifactBindingLedgerCorruptionError):
            self.ledger.verify()

    def test_previous_hash_tampering_is_detected(self):
        self.append()
        self.append(self.result(hashlib.sha256(b"binding-two").hexdigest()), seconds=1)
        self.ledger._connection.execute(
            f"DROP TRIGGER {ledger_module._UPDATE_TRIGGER}"
        )
        self.ledger._connection.execute(
            f"UPDATE {ledger_module._TABLE} SET previous_hash = ? WHERE sequence = 2",
            ("f" * 64,),
        )
        with self.assertRaises(BackupArtifactBindingLedgerCorruptionError):
            self.ledger.verify()

    def test_receipt_id_tampering_is_detected(self):
        self.append()
        self.ledger._connection.execute(
            f"DROP TRIGGER {ledger_module._UPDATE_TRIGGER}"
        )
        self.ledger._connection.execute(
            f"UPDATE {ledger_module._TABLE} SET receipt_id = ? WHERE sequence = 1",
            ("hqbr_" + "f" * 24,),
        )
        with self.assertRaises(BackupArtifactBindingLedgerCorruptionError):
            self.ledger.verify()

    def test_noncanonical_timestamp_is_detected(self):
        self.append()
        self.ledger._connection.execute(
            f"DROP TRIGGER {ledger_module._UPDATE_TRIGGER}"
        )
        self.ledger._connection.execute(
            f"UPDATE {ledger_module._TABLE} SET recorded_at = ? WHERE sequence = 1",
            ("2026-11-09T02:00:00Z",),
        )
        with self.assertRaises(BackupArtifactBindingLedgerCorruptionError):
            self.ledger.verify()

    def test_database_permissions_are_owner_only(self):
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)

    def test_symlink_database_is_rejected(self):
        target = self.root / "target.sqlite3"
        target.write_bytes(b"")
        link = self.root / "link.sqlite3"
        link.symlink_to(target)
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "PATH_SYMLINK"):
            BackupArtifactBindingLedger(str(link))

    def test_oversized_database_is_rejected(self):
        self.ledger.close()
        self.path.write_bytes(b"x" * (ledger_module.MAX_DATABASE_BYTES + 1))
        with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "DATABASE_TOO_LARGE"):
            BackupArtifactBindingLedger(str(self.path))

    def test_capacity_is_fail_closed(self):
        self.append()
        with patch.object(ledger_module, "MAX_BINDING_RECEIPTS", 1):
            with self.assertRaisesRegex(BackupArtifactBindingLedgerError, "CAPACITY_REACHED"):
                self.append(self.result(hashlib.sha256(b"binding-two").hexdigest()), seconds=1)

    def test_nonzero_authorization_storage_is_detected(self):
        row = {
            "binding_digest": "a" * 64,
            "binding_status": "METADATA_ASSOCIATION_VERIFIED",
            "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
            "inventory_record_count": 1,
            "inventory_generation": 1,
            "observer_backup_sequence": 1,
            "availability_observation_sequence": 1,
            "availability": "AVAILABLE",
            "inventory_artifact_presence": "NOT_INSPECTED",
            "artifact_bytes_verified": 0,
            "execution_authorized": 1,
            "automatic_dispatch": 0,
            "automatic_retry": 0,
        }
        with self.assertRaisesRegex(
            BackupArtifactBindingLedgerCorruptionError, "AUTHORIZATION_INVALID"
        ):
            BackupArtifactBindingLedger._metadata_from_row(row)

    def test_source_binding_result_is_not_mutated(self):
        value = self.result()
        original = dict(value)
        self.ledger.append_verified_binding(value, recorded_at=self.at())
        self.assertEqual(value, original)

    def test_response_keeps_execution_disabled(self):
        receipt = self.append()
        self.assertFalse(receipt["execution_authorized"])
        self.assertFalse(receipt["automatic_dispatch"])
        self.assertFalse(receipt["automatic_retry"])


if __name__ == "__main__":
    unittest.main()
