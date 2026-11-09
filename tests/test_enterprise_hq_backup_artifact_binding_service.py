from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_artifact_binding import BackupArtifactBindingError
from scripts.enterprise_hq_backup_artifact_binding_ledger import (
    BackupArtifactBindingLedger,
)
import scripts.enterprise_hq_backup_artifact_binding_service as service_module
from scripts.enterprise_hq_backup_artifact_binding_service import (
    BackupArtifactBindingServiceError,
    verify_and_record_backup_artifact_binding,
)


class BackupArtifactBindingServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "binding-receipts.sqlite3"
        self.ledger = BackupArtifactBindingLedger(str(self.path))
        self.inventory = object()
        self.receipts = object()
        self.availability = object()
        self.binding = {
            "inventory_backup_id": "hqbk_" + "a" * 24,
            "inventory_entry_digest": "b" * 64,
            "observer_backup_id": "hqfb_" + "c" * 24,
            "observer_file_sha256": "d" * 64,
        }
        self.now = datetime(2026, 11, 9, 3, 0, tzinfo=timezone.utc)
        self.result = self.verified_result()

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def at(self, seconds=0):
        from datetime import timedelta
        return (self.now + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    @staticmethod
    def verified_result(**overrides):
        result = {
            "status": "BACKUP_ARTIFACT_BINDING_VERIFIED",
            "binding_status": "METADATA_ASSOCIATION_VERIFIED",
            "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
            "binding_digest": hashlib.sha256(b"verified-binding").hexdigest(),
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
        result.update(overrides)
        return result

    def run_service(self, *, side_effect=None, recorded_at=None):
        with patch.object(
            service_module,
            "verify_backup_artifact_binding",
            side_effect=side_effect if side_effect is not None else [self.result],
        ) as verifier:
            result = verify_and_record_backup_artifact_binding(
                self.inventory,
                self.receipts,
                self.availability,
                self.binding,
                self.ledger,
                recorded_at=recorded_at,
            )
        return result, verifier

    def test_verified_binding_is_appended_and_read_back(self):
        result, verifier = self.run_service(recorded_at=self.at())
        self.assertEqual(result["status"], "BACKUP_ARTIFACT_BINDING_AUDIT_RECORDED")
        self.assertEqual(result["receipt_status"], "RECORDED")
        self.assertEqual(result["receipt_sequence"], 1)
        self.assertEqual(result["receipt_count"], 1)
        self.assertEqual(verifier.call_count, 1)
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)

    def test_exact_replay_is_idempotent_without_duplicate_receipt(self):
        first, _ = self.run_service(recorded_at=self.at())
        second, _ = self.run_service(recorded_at=self.at(60))
        self.assertEqual(first["receipt_sequence"], second["receipt_sequence"])
        self.assertEqual(second["status"], "BACKUP_ARTIFACT_BINDING_AUDIT_REPLAYED")
        self.assertEqual(second["receipt_status"], "REPLAYED")
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)

    def test_source_verification_failure_does_not_append(self):
        with patch.object(
            service_module,
            "verify_backup_artifact_binding",
            side_effect=BackupArtifactBindingError("SOURCE_INVALID"),
        ):
            with self.assertRaises(BackupArtifactBindingError):
                verify_and_record_backup_artifact_binding(
                    self.inventory, self.receipts, self.availability,
                    self.binding, self.ledger,
                )
        self.assertEqual(self.ledger.verify()["receipt_count"], 0)

    def test_invalid_verifier_result_is_rejected_without_receipt(self):
        invalid = self.verified_result(artifact_bytes_verified=True)
        with patch.object(
            service_module, "verify_backup_artifact_binding", return_value=invalid
        ):
            with self.assertRaisesRegex(
                BackupArtifactBindingServiceError, "APPEND_REJECTED"
            ):
                verify_and_record_backup_artifact_binding(
                    self.inventory, self.receipts, self.availability,
                    self.binding, self.ledger,
                )
        self.assertEqual(self.ledger.verify()["receipt_count"], 0)

    def test_wrong_binding_ledger_type_is_rejected_before_verification(self):
        with patch.object(service_module, "verify_backup_artifact_binding") as verifier:
            with self.assertRaisesRegex(
                BackupArtifactBindingServiceError, "LEDGER_REQUIRED"
            ):
                verify_and_record_backup_artifact_binding(
                    self.inventory, self.receipts, self.availability,
                    self.binding, object(),
                )
        verifier.assert_not_called()

    def test_closed_binding_ledger_is_rejected_before_verification(self):
        self.ledger.close()
        with patch.object(service_module, "verify_backup_artifact_binding") as verifier:
            with self.assertRaisesRegex(
                BackupArtifactBindingServiceError, "LEDGER_NOT_OPEN"
            ):
                verify_and_record_backup_artifact_binding(
                    self.inventory, self.receipts, self.availability,
                    self.binding, self.ledger,
                )
        verifier.assert_not_called()

    def test_invalid_initial_receipt_history_fails_closed(self):
        with patch.object(
            self.ledger, "verify",
            return_value={"status": "CORRUPT", "receipt_count": 0},
        ):
            with patch.object(service_module, "verify_backup_artifact_binding") as verifier:
                with self.assertRaisesRegex(
                    BackupArtifactBindingServiceError, "INITIAL_HISTORY_INVALID"
                ):
                    verify_and_record_backup_artifact_binding(
                        self.inventory, self.receipts, self.availability,
                        self.binding, self.ledger,
                    )
        verifier.assert_not_called()

    def test_append_response_with_wrong_digest_is_rejected(self):
        wrong = self.verified_result(binding_digest="e" * 64)
        with patch.object(
            service_module, "verify_backup_artifact_binding", return_value=self.result
        ):
            with patch.object(
                self.ledger, "append_verified_binding",
                return_value={
                    "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED",
                    "binding_digest": wrong["binding_digest"],
                    "receipt_id": "hqbr_" + "1" * 24,
                    "sequence": 1,
                    "record_hash": "2" * 64,
                },
            ):
                with self.assertRaisesRegex(
                    BackupArtifactBindingServiceError, "APPEND_RESPONSE_INVALID"
                ):
                    verify_and_record_backup_artifact_binding(
                        self.inventory, self.receipts, self.availability,
                        self.binding, self.ledger,
                    )

    def test_unrecognized_append_status_is_rejected(self):
        with patch.object(
            service_module, "verify_backup_artifact_binding", return_value=self.result
        ):
            with patch.object(
                self.ledger, "append_verified_binding",
                return_value={
                    "status": "UNKNOWN",
                    "binding_digest": self.result["binding_digest"],
                    "receipt_id": "hqbr_" + "1" * 24,
                    "sequence": 1,
                    "record_hash": "2" * 64,
                },
            ):
                with self.assertRaisesRegex(
                    BackupArtifactBindingServiceError, "APPEND_RESPONSE_INVALID"
                ):
                    verify_and_record_backup_artifact_binding(
                        self.inventory, self.receipts, self.availability,
                        self.binding, self.ledger,
                    )

    def test_missing_receipt_readback_fails_closed(self):
        with patch.object(
            service_module, "verify_backup_artifact_binding", return_value=self.result
        ):
            with patch.object(
                self.ledger, "get_receipt",
                return_value={"status": "BACKUP_ARTIFACT_BINDING_RECEIPT_NOT_FOUND"},
            ):
                with self.assertRaisesRegex(
                    BackupArtifactBindingServiceError, "READBACK_MISMATCH"
                ):
                    verify_and_record_backup_artifact_binding(
                        self.inventory, self.receipts, self.availability,
                        self.binding, self.ledger,
                    )

    def test_mismatched_receipt_readback_fails_closed(self):
        with patch.object(
            service_module, "verify_backup_artifact_binding", return_value=self.result
        ):
            with patch.object(self.ledger, "get_receipt", side_effect=lambda digest: {
                "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_FOUND",
                "receipt_id": "hqbr_" + "9" * 24,
                "sequence": 1,
                "binding_digest": digest,
                "record_hash": "f" * 64,
            }):
                with self.assertRaisesRegex(
                    BackupArtifactBindingServiceError, "READBACK_MISMATCH"
                ):
                    verify_and_record_backup_artifact_binding(
                        self.inventory, self.receipts, self.availability,
                        self.binding, self.ledger,
                    )

    def test_receipt_sequence_must_exist_in_verified_history(self):
        with patch.object(
            service_module, "verify_backup_artifact_binding", return_value=self.result
        ):
            with patch.object(
                self.ledger, "append_verified_binding",
                return_value={
                    "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED",
                    "binding_digest": self.result["binding_digest"],
                    "receipt_id": "hqbr_" + "1" * 24,
                    "sequence": 1,
                    "record_hash": "2" * 64,
                },
            ):
                with self.assertRaisesRegex(
                    BackupArtifactBindingServiceError, "READBACK_MISMATCH"
                ):
                    verify_and_record_backup_artifact_binding(
                        self.inventory, self.receipts, self.availability,
                        self.binding, self.ledger,
                    )

    def test_single_receipt_chain_head_matches_readback(self):
        result, _ = self.run_service(recorded_at=self.at())
        self.assertTrue(result["receipt_history_verified"])
        self.assertEqual(self.ledger.verify()["chain_head_hash"],
                         self.ledger.get_receipt(self.result["binding_digest"])["record_hash"])

    def test_recorded_timestamp_is_forwarded_to_ledger(self):
        with patch.object(
            self.ledger, "append_verified_binding",
            wraps=self.ledger.append_verified_binding,
        ) as append:
            self.run_service(recorded_at=self.at())
        self.assertEqual(append.call_args.kwargs["recorded_at"], self.at())

    def test_verifier_receives_explicit_source_ledgers_and_binding(self):
        _, verifier = self.run_service()
        verifier.assert_called_once_with(
            self.inventory, self.receipts, self.availability, self.binding
        )

    def test_result_contains_only_aggregate_receipt_metadata(self):
        result, _ = self.run_service()
        forbidden = {
            "receipt_id", "binding_digest", "record_hash", "inventory_backup_id",
            "observer_backup_id", "file_sha256", "path", "database", "payload",
            "recorded_at",
        }
        self.assertTrue(forbidden.isdisjoint(result))

    def test_all_nonexecution_and_byte_verification_flags_remain_false(self):
        result, _ = self.run_service()
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])
        self.assertTrue(result["source_binding_verified"])
        self.assertTrue(result["receipt_readback_verified"])

    def test_post_append_history_corruption_is_reported(self):
        original = self.ledger.verify
        with patch.object(
            self.ledger, "verify",
            side_effect=[
                original(),
                original(),
                RuntimeError("simulated post-append verification failure"),
            ],
        ):
            with patch.object(
                service_module, "verify_backup_artifact_binding",
                return_value=self.result,
            ):
                with self.assertRaisesRegex(
                    BackupArtifactBindingServiceError, "POST_APPEND_HISTORY_INVALID"
                ):
                    verify_and_record_backup_artifact_binding(
                        self.inventory, self.receipts, self.availability,
                        self.binding, self.ledger,
                    )
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)


if __name__ == "__main__":
    unittest.main()
