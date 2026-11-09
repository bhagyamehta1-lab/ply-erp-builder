from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.enterprise_hq_backup_artifact_binding_ledger import (
    BackupArtifactBindingLedger,
)
from scripts.enterprise_hq_backup_artifact_binding_snapshot import (
    BackupArtifactBindingSnapshotError,
    verify_backup_artifact_binding_receipt_snapshot,
)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    )


def receipt_id(binding_digest):
    return "hqbr_" + hashlib.sha256(
        ("enterprise-hq-binding-receipt:v1:" + binding_digest).encode("ascii")
    ).hexdigest()[:24]


def make_record(sequence=1, binding_digest=None, previous_hash=None, recorded_at=None):
    digest = binding_digest or hashlib.sha256(f"binding-{sequence}".encode()).hexdigest()
    body = {
        "schema_version": "1.0.0",
        "sequence": sequence,
        "receipt_id": receipt_id(digest),
        "binding_digest": digest,
        "binding_status": "METADATA_ASSOCIATION_VERIFIED",
        "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
        "inventory_record_count": 3,
        "inventory_generation": 2,
        "observer_backup_sequence": sequence + 2,
        "availability_observation_sequence": sequence + 5,
        "availability": "AVAILABLE",
        "inventory_artifact_presence": "NOT_INSPECTED",
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
        "recorded_at": recorded_at or f"2026-11-09T04:00:{sequence:02d}.000000Z",
        "previous_hash": previous_hash,
    }
    return {**body, "record_hash": hashlib.sha256(canonical(body).encode("ascii")).hexdigest()}


def make_snapshot(records=None):
    rows = list(records or [])
    return {
        "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_EXPORTED",
        "schema_version": "1.0.0",
        "receipt_count": len(rows),
        "records": rows,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


class BackupArtifactBindingSnapshotTests(unittest.TestCase):
    def verify(self, snapshot):
        return verify_backup_artifact_binding_receipt_snapshot(snapshot)

    def reject(self, snapshot, code):
        with self.assertRaisesRegex(BackupArtifactBindingSnapshotError, code):
            self.verify(snapshot)

    def test_accepts_empty_history(self):
        result = self.verify(make_snapshot())
        self.assertEqual(result["status"], "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_VERIFIED")
        self.assertEqual(result["receipt_count"], 0)
        self.assertIsNone(result["chain_head_hash"])

    def test_accepts_single_receipt(self):
        record = make_record()
        result = self.verify(make_snapshot([record]))
        self.assertEqual(result["receipt_count"], 1)
        self.assertEqual(result["chain_head_hash"], record["record_hash"])

    def test_accepts_multi_receipt_hash_chain(self):
        first = make_record(1)
        second = make_record(2, previous_hash=first["record_hash"], recorded_at="2026-11-09T04:00:03.000000Z")
        result = self.verify(make_snapshot([first, second]))
        self.assertEqual(result["receipt_count"], 2)
        self.assertEqual(result["last_sequence"], 2)
        self.assertEqual(result["chain_head_hash"], second["record_hash"])

    def test_returns_only_aggregate_metadata(self):
        result = self.verify(make_snapshot([make_record()]))
        self.assertEqual(set(result), {
            "status", "receipt_count", "last_sequence", "chain_head_hash",
            "independent_hash_verification", "execution_authorized",
            "automatic_dispatch", "automatic_retry",
        })

    def test_rejects_extra_snapshot_field(self):
        snapshot = make_snapshot()
        snapshot["private_payload"] = "must-not-be-accepted"
        self.reject(snapshot, "SNAPSHOT_SCHEMA_INVALID")

    def test_rejects_missing_snapshot_field(self):
        snapshot = make_snapshot()
        del snapshot["records"]
        self.reject(snapshot, "SNAPSHOT_SCHEMA_INVALID")

    def test_rejects_wrong_snapshot_status(self):
        snapshot = make_snapshot()
        snapshot["status"] = "UNVERIFIED"
        self.reject(snapshot, "SNAPSHOT_STATUS_INVALID")

    def test_rejects_wrong_schema_version(self):
        snapshot = make_snapshot()
        snapshot["schema_version"] = "2.0.0"
        self.reject(snapshot, "SNAPSHOT_STATUS_INVALID")

    def test_rejects_boolean_receipt_count(self):
        snapshot = make_snapshot()
        snapshot["receipt_count"] = True
        self.reject(snapshot, "SNAPSHOT_COUNT_INVALID")

    def test_rejects_receipt_count_mismatch(self):
        snapshot = make_snapshot([make_record()])
        snapshot["receipt_count"] = 0
        self.reject(snapshot, "SNAPSHOT_COUNT_INVALID")

    def test_rejects_more_than_maximum_receipts(self):
        records = [make_record(i, recorded_at=f"2026-11-09T04:{i // 60:02d}:{i % 60:02d}.000000Z") for i in range(1, 514)]
        self.reject(make_snapshot(records), "SNAPSHOT_COUNT_INVALID")

    def test_rejects_extra_record_field(self):
        record = make_record()
        record["source_backup_id"] = "forbidden"
        self.reject(make_snapshot([record]), "RECORD_SCHEMA_INVALID")

    def test_rejects_missing_record_field(self):
        record = make_record()
        del record["previous_hash"]
        self.reject(make_snapshot([record]), "RECORD_SCHEMA_INVALID")

    def test_rejects_sequence_gap(self):
        first = make_record(1)
        second = make_record(3, previous_hash=first["record_hash"], recorded_at="2026-11-09T04:00:03.000000Z")
        self.reject(make_snapshot([first, second]), "SEQUENCE_INVALID")

    def test_rejects_duplicate_binding_digest(self):
        first = make_record(1)
        second = make_record(2, binding_digest=first["binding_digest"], previous_hash=first["record_hash"], recorded_at="2026-11-09T04:00:03.000000Z")
        self.reject(make_snapshot([first, second]), "DUPLICATE_RECEIPT")

    def test_rejects_wrong_deterministic_receipt_id(self):
        record = make_record()
        record["receipt_id"] = "hqbr_" + "f" * 24
        self.reject(make_snapshot([record]), "RECEIPT_ID_INVALID")

    def test_rejects_malformed_binding_digest(self):
        record = make_record()
        record["binding_digest"] = "not-a-digest"
        self.reject(make_snapshot([record]), "DIGEST_INVALID")

    def test_rejects_malformed_record_hash(self):
        record = make_record()
        record["record_hash"] = "invalid"
        self.reject(make_snapshot([record]), "RECORD_HASH_INVALID")

    def test_rejects_changed_record_hash(self):
        record = make_record()
        record["record_hash"] = "f" * 64
        self.reject(make_snapshot([record]), "RECORD_HASH_MISMATCH")

    def test_rejects_changed_hashed_metadata(self):
        record = make_record()
        record["inventory_generation"] = 99
        self.reject(make_snapshot([record]), "RECORD_HASH_MISMATCH")

    def test_rejects_broken_previous_hash_link(self):
        first = make_record(1)
        second = make_record(2, previous_hash="f" * 64, recorded_at="2026-11-09T04:00:03.000000Z")
        self.reject(make_snapshot([first, second]), "CHAIN_LINK_INVALID")

    def test_rejects_timestamp_regression(self):
        first = make_record(1, recorded_at="2026-11-09T04:00:05.000000Z")
        second = make_record(2, previous_hash=first["record_hash"], recorded_at="2026-11-09T04:00:03.000000Z")
        self.reject(make_snapshot([first, second]), "TIMESTAMP_REGRESSION")

    def test_rejects_timezone_naive_timestamp(self):
        record = make_record(recorded_at="2026-11-09T04:00:01.000000")
        self.reject(make_snapshot([record]), "TIMESTAMP_INVALID")

    def test_rejects_noncanonical_timestamp(self):
        record = make_record(recorded_at="2026-11-09T04:00:01+00:00")
        self.reject(make_snapshot([record]), "TIMESTAMP_NONCANONICAL")

    def test_rejects_non_utc_timestamp(self):
        record = make_record(recorded_at="2026-11-09T09:30:01.000000+05:30")
        self.reject(make_snapshot([record]), "TIMESTAMP_INVALID")

    def test_rejects_wrong_binding_status(self):
        record = make_record()
        record["binding_status"] = "UNVERIFIED"
        self.reject(make_snapshot([record]), "BINDING_STATUS_INVALID")

    def test_rejects_wrong_binding_basis(self):
        record = make_record()
        record["binding_basis"] = "INFERRED"
        self.reject(make_snapshot([record]), "BINDING_STATUS_INVALID")

    def test_rejects_nonavailable_state(self):
        record = make_record()
        record["availability"] = "MISSING"
        self.reject(make_snapshot([record]), "BINDING_STATUS_INVALID")

    def test_rejects_inspected_inventory_claim(self):
        record = make_record()
        record["inventory_artifact_presence"] = "PRESENT"
        self.reject(make_snapshot([record]), "BINDING_STATUS_INVALID")

    def test_rejects_artifact_byte_verification_claim(self):
        record = make_record()
        record["artifact_bytes_verified"] = True
        self.reject(make_snapshot([record]), "AUTHORIZATION_INVALID")

    def test_rejects_execution_authorization(self):
        record = make_record()
        record["execution_authorized"] = True
        self.reject(make_snapshot([record]), "AUTHORIZATION_INVALID")

    def test_rejects_automatic_dispatch(self):
        record = make_record()
        record["automatic_dispatch"] = True
        self.reject(make_snapshot([record]), "AUTHORIZATION_INVALID")

    def test_rejects_automatic_retry(self):
        record = make_record()
        record["automatic_retry"] = True
        self.reject(make_snapshot([record]), "AUTHORIZATION_INVALID")

    def test_rejects_boolean_integer_metadata(self):
        record = make_record()
        record["inventory_record_count"] = True
        self.reject(make_snapshot([record]), "COUNT_FIELD_INVALID")

    def test_rejects_snapshot_execution_authorization(self):
        snapshot = make_snapshot()
        snapshot["execution_authorized"] = True
        self.reject(snapshot, "SNAPSHOT_AUTHORIZATION_INVALID")

    def test_ledger_export_passes_independent_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = BackupArtifactBindingLedger(str(Path(directory) / "receipts.sqlite3"))
            try:
                digest = hashlib.sha256(b"verified binding").hexdigest()
                ledger.append_verified_binding({
                    "status": "BACKUP_ARTIFACT_BINDING_VERIFIED",
                    "binding_status": "METADATA_ASSOCIATION_VERIFIED",
                    "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
                    "binding_digest": digest,
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
                }, recorded_at="2026-11-09T04:00:00Z")
                snapshot = ledger.export_verification_snapshot()
                verified = self.verify(snapshot)
                self.assertEqual(verified["receipt_count"], 1)
                self.assertEqual(verified["chain_head_hash"], ledger.verify()["chain_head_hash"])
            finally:
                ledger.close()

    def test_ledger_export_omits_source_identifiers_and_artifact_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = BackupArtifactBindingLedger(str(Path(directory) / "receipts.sqlite3"))
            try:
                digest = hashlib.sha256(b"verified binding").hexdigest()
                ledger.append_verified_binding({
                    "status": "BACKUP_ARTIFACT_BINDING_VERIFIED",
                    "binding_status": "METADATA_ASSOCIATION_VERIFIED",
                    "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
                    "binding_digest": digest,
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
                }, recorded_at="2026-11-09T04:00:00Z")
                snapshot = ledger.export_verification_snapshot()
                encoded = json.dumps(snapshot)
                for forbidden in (
                    "inventory_backup_id", "observer_backup_id", "file_sha256",
                    "source_backup_id", "filesystem_path", "private_payload",
                ):
                    self.assertNotIn(forbidden, encoded)
                self.assertEqual(snapshot["records"][0]["inventory_artifact_presence"], "NOT_INSPECTED")
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
