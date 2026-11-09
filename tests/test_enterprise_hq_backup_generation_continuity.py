from __future__ import annotations

import hashlib
import json
import unittest

from scripts.enterprise_hq_backup_generation_continuity import (
    BackupGenerationContinuityError,
    reconcile_backup_generation_continuity,
    verify_backup_generation_continuity_snapshot,
)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def association_digest(kind, identifier):
    return hashlib.sha256(
        f"enterprise-hq-backup-association:v1:{kind}:{identifier}".encode("ascii")
    ).hexdigest()


def make_inventory_record(
    index=1, *, ledger_type="evidence", generation=1,
    predecessor_backup_id=None, created_at=None,
):
    backup_id = f"hqbk_{index:024x}"
    created = created_at or f"2026-11-08T05:{generation:02d}:00Z"
    from datetime import datetime, timedelta, timezone
    parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
    retain = (parsed + timedelta(days=30)).isoformat().replace("+00:00", "Z")
    body = {
        "backup_id": backup_id,
        "ledger_type": ledger_type,
        "source_snapshot_digest": hashlib.sha256(f"source-{index}".encode()).hexdigest(),
        "restored_snapshot_digest": hashlib.sha256(f"source-{index}".encode()).hexdigest(),
        "audit_chain_count": 1,
        "declared_size_bytes": 4096,
        "created_at": created,
        "retain_until": retain,
        "generation": generation,
        "predecessor_backup_id": predecessor_backup_id,
        "storage_scope": "LOCAL_ONLY",
        "restore_status": "RESTORE_EQUIVALENCE_VERIFIED",
        "artifact_presence": "NOT_INSPECTED",
    }
    return {
        "status": "BACKUP_METADATA_FOUND",
        **body,
        "entry_digest": digest(body),
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def make_inventory_snapshot(records=None):
    rows = list(records or [])
    return {
        "status": "BACKUP_INVENTORY_METADATA_SNAPSHOT_EXPORTED",
        "record_count": len(rows),
        "records": rows,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def make_observer_record(index=1, *, predecessor_backup_id=None):
    file_digest = hashlib.sha256(f"observer-file-{index}".encode()).hexdigest()
    return {
        "backup_count": index,
        "backup_id": "hqfb_" + file_digest[:24],
        "file_sha256": file_digest,
        "source_receipt_count": 1,
        "source_status_counts": {"FRESH": 1},
        "last_source_sequence": 1,
        "source_chain_head_digest": hashlib.sha256(f"source-head-{index}".encode()).hexdigest(),
        "predecessor_backup_id": predecessor_backup_id,
        "record_hash": hashlib.sha256(f"observer-record-{index}".encode()).hexdigest(),
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def make_observer_snapshot(records=None):
    rows = list(records or [])
    return {
        "status": "OBSERVER_FRESHNESS_BACKUP_RECEIPT_SNAPSHOT_EXPORTED",
        "backup_count": len(rows),
        "records": rows,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def make_binding_record(
    sequence, inventory_id, observer_id, *, inventory_generation=1,
    observer_sequence=1, inventory_record_count=1, previous_hash=None,
):
    binding_digest = hashlib.sha256(f"binding-{sequence}".encode()).hexdigest()
    body = {
        "schema_version": "1.1.0",
        "sequence": sequence,
        "receipt_id": "hqbr_" + hashlib.sha256(
            ("enterprise-hq-binding-receipt:v1:" + binding_digest).encode("ascii")
        ).hexdigest()[:24],
        "binding_digest": binding_digest,
        "inventory_association_digest": association_digest("inventory", inventory_id),
        "observer_association_digest": association_digest("observer", observer_id),
        "binding_status": "METADATA_ASSOCIATION_VERIFIED",
        "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
        "inventory_record_count": inventory_record_count,
        "inventory_generation": inventory_generation,
        "observer_backup_sequence": observer_sequence,
        "availability_observation_sequence": sequence + 5,
        "availability": "AVAILABLE",
        "inventory_artifact_presence": "NOT_INSPECTED",
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
        "recorded_at": f"2026-11-09T04:00:{sequence:02d}.000000Z",
        "previous_hash": previous_hash,
    }
    return {**body, "record_hash": digest(body)}


def make_binding_snapshot(records=None):
    rows = list(records or [])
    return {
        "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_EXPORTED",
        "schema_version": "1.1.0",
        "receipt_count": len(rows),
        "records": rows,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


class FakeLedger:
    def __init__(self, summary, rows=None, snapshot=None, mutate_on_second=False):
        self.summary = dict(summary)
        self.rows = rows if rows is not None else []
        self.snapshot = snapshot
        self.calls = 0
        self.mutate_on_second = mutate_on_second

    def verify(self):
        self.calls += 1
        result = dict(self.summary)
        if self.mutate_on_second and self.calls >= 2:
            result["chain_head"] = "changed"
        return result

    def list_backup_metadata(self):
        return self.rows

    def list_backup_receipts(self):
        return self.rows

    def export_verification_snapshot(self):
        return self.snapshot


class BackupGenerationContinuityTests(unittest.TestCase):
    def verify(self, inventory=None, observer=None, binding=None):
        return verify_backup_generation_continuity_snapshot(
            make_inventory_snapshot([]) if inventory is None else inventory,
            make_observer_snapshot([]) if observer is None else observer,
            make_binding_snapshot([]) if binding is None else binding,
        )

    def reject(self, inventory=None, observer=None, binding=None, code=""):
        with self.assertRaisesRegex(BackupGenerationContinuityError, code):
            self.verify(inventory, observer, binding)

    def test_accepts_empty_histories(self):
        result = self.verify()
        self.assertEqual(result["status"], "BACKUP_GENERATION_CONTINUITY_VERIFIED")
        self.assertEqual(result["inventory_record_count"], 0)
        self.assertEqual(result["observer_backup_count"], 0)
        self.assertEqual(result["binding_receipt_count"], 0)
        self.assertEqual(result["association_coverage"], "NONE")

    def test_verifies_single_inventory_observer_binding(self):
        inventory = make_inventory_record()
        observer = make_observer_record()
        binding = make_binding_record(1, inventory["backup_id"], observer["backup_id"])
        result = self.verify(
            make_inventory_snapshot([inventory]),
            make_observer_snapshot([observer]),
            make_binding_snapshot([binding]),
        )
        self.assertEqual(result["association_coverage"], "COMPLETE")
        self.assertEqual(result["bound_inventory_count"], 1)
        self.assertEqual(result["bound_observer_backup_count"], 1)
        self.assertEqual(result["inventory_entry_digest_verification"], True)
        self.assertEqual(result["binding_receipt_hash_verification"], True)

    def test_verifies_multiple_inventory_generations_and_observer_predecessors(self):
        first_inventory = make_inventory_record(1, generation=1)
        second_inventory = make_inventory_record(
            2, generation=2, predecessor_backup_id=first_inventory["backup_id"]
        )
        first_observer = make_observer_record(1)
        second_observer = make_observer_record(
            2, predecessor_backup_id=first_observer["backup_id"]
        )
        first_binding = make_binding_record(
            1, first_inventory["backup_id"], first_observer["backup_id"]
        )
        second_binding = make_binding_record(
            2, second_inventory["backup_id"], second_observer["backup_id"],
            inventory_generation=2, observer_sequence=2, inventory_record_count=2,
            previous_hash=first_binding["record_hash"],
        )
        result = self.verify(
            make_inventory_snapshot([first_inventory, second_inventory]),
            make_observer_snapshot([first_observer, second_observer]),
            make_binding_snapshot([first_binding, second_binding]),
        )
        self.assertEqual(result["inventory_record_count"], 2)
        self.assertEqual(result["inventory_ledger_type_count"], 1)
        self.assertEqual(result["inventory_predecessor_link_count"], 1)
        self.assertEqual(result["observer_predecessor_link_count"], 1)
        self.assertEqual(result["binding_association_pair_count"], 2)
        self.assertEqual(result["association_coverage"], "COMPLETE")

    def test_allows_reverification_of_the_same_association(self):
        inventory = make_inventory_record()
        observer = make_observer_record()
        first = make_binding_record(1, inventory["backup_id"], observer["backup_id"])
        second = make_binding_record(
            2, inventory["backup_id"], observer["backup_id"], previous_hash=first["record_hash"]
        )
        result = self.verify(
            make_inventory_snapshot([inventory]),
            make_observer_snapshot([observer]),
            make_binding_snapshot([first, second]),
        )
        self.assertEqual(result["binding_receipt_count"], 2)
        self.assertEqual(result["binding_association_pair_count"], 1)
        self.assertEqual(result["association_coverage"], "COMPLETE")

    def test_reports_partial_association_coverage(self):
        inventory_one = make_inventory_record(1)
        inventory_two = make_inventory_record(
            2, ledger_type="audit", generation=1
        )
        observer_one = make_observer_record(1)
        observer_two = make_observer_record(
            2, predecessor_backup_id=observer_one["backup_id"]
        )
        binding = make_binding_record(1, inventory_one["backup_id"], observer_one["backup_id"])
        result = self.verify(
            make_inventory_snapshot([inventory_one, inventory_two]),
            make_observer_snapshot([observer_one, observer_two]),
            make_binding_snapshot([binding]),
        )
        self.assertEqual(result["association_coverage"], "PARTIAL")
        self.assertEqual(result["unbound_inventory_count"], 1)
        self.assertEqual(result["unbound_observer_backup_count"], 1)

    def test_returns_aggregate_metadata_without_identifiers_or_digests(self):
        inventory = make_inventory_record()
        observer = make_observer_record()
        binding = make_binding_record(1, inventory["backup_id"], observer["backup_id"])
        result = self.verify(
            make_inventory_snapshot([inventory]),
            make_observer_snapshot([observer]),
            make_binding_snapshot([binding]),
        )
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(inventory["backup_id"], rendered)
        self.assertNotIn(observer["backup_id"], rendered)
        self.assertNotIn(inventory["entry_digest"], rendered)
        self.assertNotIn(observer["file_sha256"], rendered)
        self.assertNotIn(binding["binding_digest"], rendered)
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_rejects_extra_inventory_snapshot_field(self):
        snapshot = make_inventory_snapshot()
        snapshot["private_payload"] = "not-allowed"
        self.reject(inventory=snapshot, code="INVENTORY_SNAPSHOT_SCHEMA_INVALID")

    def test_rejects_missing_inventory_snapshot_field(self):
        snapshot = make_inventory_snapshot()
        del snapshot["records"]
        self.reject(inventory=snapshot, code="INVENTORY_SNAPSHOT_SCHEMA_INVALID")

    def test_rejects_wrong_inventory_snapshot_status(self):
        snapshot = make_inventory_snapshot()
        snapshot["status"] = "UNVERIFIED"
        self.reject(inventory=snapshot, code="INVENTORY_SNAPSHOT_STATUS_INVALID")

    def test_rejects_inventory_count_mismatch(self):
        snapshot = make_inventory_snapshot([make_inventory_record()])
        snapshot["record_count"] = 0
        self.reject(inventory=snapshot, code="INVENTORY_COUNT_INVALID")

    def test_rejects_inventory_capacity_exceeded(self):
        snapshot = make_inventory_snapshot()
        snapshot["record_count"] = 257
        snapshot["records"] = [{}] * 257
        self.reject(inventory=snapshot, code="INVENTORY_COUNT_INVALID")

    def test_rejects_inventory_record_extra_field(self):
        row = make_inventory_record()
        row["filesystem_path"] = "/tmp/backup"
        self.reject(
            inventory=make_inventory_snapshot([row]),
            code="INVENTORY_RECORD_SCHEMA_INVALID",
        )

    def test_rejects_invalid_inventory_identifier(self):
        row = make_inventory_record()
        row["backup_id"] = "../backup"
        self.reject(
            inventory=make_inventory_snapshot([row]),
            code="INVENTORY_ID_INVALID",
        )

    def test_rejects_duplicate_inventory_identifier(self):
        first = make_inventory_record(1)
        second = make_inventory_record(1, generation=2, predecessor_backup_id=first["backup_id"])
        self.reject(
            inventory=make_inventory_snapshot([first, second]),
            code="INVENTORY_DUPLICATE_ID",
        )

    def test_rejects_duplicate_inventory_generation(self):
        first = make_inventory_record(1, ledger_type="audit")
        second = make_inventory_record(2, ledger_type="audit")
        self.reject(
            inventory=make_inventory_snapshot([first, second]),
            code="INVENTORY_DUPLICATE_GENERATION",
        )

    def test_rejects_inventory_generation_gap(self):
        first = make_inventory_record(1, generation=1)
        third = make_inventory_record(3, generation=3, predecessor_backup_id=first["backup_id"])
        self.reject(
            inventory=make_inventory_snapshot([first, third]),
            code="INVENTORY_LINEAGE_INVALID",
        )

    def test_rejects_inventory_predecessor_mismatch(self):
        first = make_inventory_record(1)
        second = make_inventory_record(
            2, generation=2, predecessor_backup_id="hqbk_" + "f" * 24
        )
        self.reject(
            inventory=make_inventory_snapshot([first, second]),
            code="INVENTORY_LINEAGE_INVALID",
        )

    def test_rejects_inventory_entry_digest_tampering(self):
        row = make_inventory_record()
        row["entry_digest"] = "0" * 64
        self.reject(
            inventory=make_inventory_snapshot([row]),
            code="INVENTORY_ENTRY_DIGEST_MISMATCH",
        )

    def test_rejects_inventory_restore_digest_mismatch(self):
        row = make_inventory_record()
        row["restored_snapshot_digest"] = "0" * 64
        self.reject(
            inventory=make_inventory_snapshot([row]),
            code="INVENTORY_DIGEST_INVALID",
        )

    def test_rejects_inventory_artifact_byte_claim(self):
        row = make_inventory_record()
        row["artifact_bytes_verified"] = True
        self.reject(
            inventory=make_inventory_snapshot([row]),
            code="INVENTORY_POLICY_INVALID",
        )

    def test_rejects_nonlocal_inventory_scope(self):
        row = make_inventory_record()
        row["storage_scope"] = "REMOTE"
        self.reject(
            inventory=make_inventory_snapshot([row]),
            code="INVENTORY_POLICY_INVALID",
        )

    def test_rejects_invalid_inventory_timestamp(self):
        row = make_inventory_record()
        row["created_at"] = "not-a-timestamp"
        self.reject(
            inventory=make_inventory_snapshot([row]),
            code="INVENTORY_TIMESTAMP_INVALID",
        )

    def test_rejects_observer_count_mismatch(self):
        snapshot = make_observer_snapshot([make_observer_record()])
        snapshot["backup_count"] = 0
        self.reject(observer=snapshot, code="OBSERVER_COUNT_INVALID")

    def test_rejects_observer_sequence_gap(self):
        first = make_observer_record(1)
        second = make_observer_record(2, predecessor_backup_id=first["backup_id"])
        second["backup_count"] = 3
        self.reject(
            observer=make_observer_snapshot([first, second]),
            code="OBSERVER_SEQUENCE_INVALID",
        )

    def test_rejects_observer_predecessor_mismatch(self):
        row = make_observer_record(1, predecessor_backup_id="hqfb_" + "f" * 24)
        self.reject(
            observer=make_observer_snapshot([row]),
            code="OBSERVER_PREDECESSOR_INVALID",
        )

    def test_rejects_observer_identifier_not_derived_from_file_digest(self):
        row = make_observer_record()
        row["backup_id"] = "hqfb_" + "f" * 24
        self.reject(
            observer=make_observer_snapshot([row]),
            code="OBSERVER_ID_INVALID",
        )

    def test_rejects_observer_source_status_count_mismatch(self):
        row = make_observer_record()
        row["source_status_counts"] = {"FRESH": 2}
        self.reject(
            observer=make_observer_snapshot([row]),
            code="OBSERVER_SOURCE_COUNTS_INVALID",
        )

    def test_rejects_observer_record_hash_format(self):
        row = make_observer_record()
        row["record_hash"] = "bad"
        self.reject(
            observer=make_observer_snapshot([row]),
            code="OBSERVER_RECORD_HASH_INVALID",
        )

    def test_rejects_binding_snapshot_corruption(self):
        row = make_inventory_record()
        observer = make_observer_record()
        binding = make_binding_record(1, row["backup_id"], observer["backup_id"])
        binding["record_hash"] = "0" * 64
        self.reject(
            inventory=make_inventory_snapshot([row]),
            observer=make_observer_snapshot([observer]),
            binding=make_binding_snapshot([binding]),
            code="BINDING_SNAPSHOT_INVALID",
        )

    def test_rejects_binding_inventory_reference_missing(self):
        observer = make_observer_record()
        binding = make_binding_record(
            1, "hqbk_" + "f" * 24, observer["backup_id"]
        )
        self.reject(
            observer=make_observer_snapshot([observer]),
            binding=make_binding_snapshot([binding]),
            code="BINDING_REFERENCE_MISSING",
        )

    def test_rejects_binding_observer_reference_missing(self):
        inventory = make_inventory_record()
        binding = make_binding_record(
            1, inventory["backup_id"], "hqfb_" + "f" * 24
        )
        self.reject(
            inventory=make_inventory_snapshot([inventory]),
            binding=make_binding_snapshot([binding]),
            code="BINDING_REFERENCE_MISSING",
        )

    def test_rejects_binding_inventory_generation_mismatch(self):
        inventory = make_inventory_record()
        observer = make_observer_record()
        binding = make_binding_record(
            1, inventory["backup_id"], observer["backup_id"], inventory_generation=2
        )
        self.reject(
            inventory=make_inventory_snapshot([inventory]),
            observer=make_observer_snapshot([observer]),
            binding=make_binding_snapshot([binding]),
            code="BINDING_GENERATION_MISMATCH",
        )

    def test_rejects_binding_observer_sequence_mismatch(self):
        inventory = make_inventory_record()
        observer = make_observer_record()
        binding = make_binding_record(
            1, inventory["backup_id"], observer["backup_id"], observer_sequence=2
        )
        self.reject(
            inventory=make_inventory_snapshot([inventory]),
            observer=make_observer_snapshot([observer]),
            binding=make_binding_snapshot([binding]),
            code="BINDING_OBSERVER_SEQUENCE_MISMATCH",
        )

    def test_rejects_binding_inventory_count_from_future(self):
        inventory = make_inventory_record()
        observer = make_observer_record()
        binding = make_binding_record(
            1, inventory["backup_id"], observer["backup_id"], inventory_record_count=2
        )
        self.reject(
            inventory=make_inventory_snapshot([inventory]),
            observer=make_observer_snapshot([observer]),
            binding=make_binding_snapshot([binding]),
            code="BINDING_INVENTORY_COUNT_INVALID",
        )

    def test_rejects_authorization_escalation_in_source_snapshot(self):
        snapshot = make_inventory_snapshot()
        snapshot["execution_authorized"] = True
        self.reject(inventory=snapshot, code="AUTHORIZATION_INVALID")

    def test_orchestrator_verifies_all_sources_and_returns_stable_aggregate(self):
        inventory_row = make_inventory_record()
        observer_row = make_observer_record()
        binding_row = make_binding_record(
            1, inventory_row["backup_id"], observer_row["backup_id"]
        )
        inventory = FakeLedger({"status": "INVENTORY_VALID"}, [inventory_row])
        observer = FakeLedger({"status": "OBSERVER_VALID"}, [observer_row])
        binding = FakeLedger(
            {"status": "BINDING_VALID"}, snapshot=make_binding_snapshot([binding_row])
        )
        result = reconcile_backup_generation_continuity(inventory, observer, binding)
        self.assertTrue(result["source_snapshot_stable"])
        self.assertEqual(result["source_ledger_verification_count"], 3)
        self.assertEqual(result["association_coverage"], "COMPLETE")
        self.assertGreaterEqual(inventory.calls, 2)
        self.assertGreaterEqual(observer.calls, 2)
        self.assertGreaterEqual(binding.calls, 2)

    def test_orchestrator_fails_closed_when_source_changes_during_read(self):
        inventory = FakeLedger(
            {"status": "INVENTORY_VALID"}, [make_inventory_record()], mutate_on_second=True
        )
        observer = FakeLedger({"status": "OBSERVER_VALID"}, [])
        binding = FakeLedger({"status": "BINDING_VALID"}, snapshot=make_binding_snapshot())
        with self.assertRaisesRegex(
            BackupGenerationContinuityError, "SOURCE_SNAPSHOT_CHANGED"
        ):
            reconcile_backup_generation_continuity(inventory, observer, binding)

    def test_orchestrator_rejects_missing_source_interface(self):
        with self.assertRaisesRegex(
            BackupGenerationContinuityError, "SOURCE_LEDGERS_REQUIRED"
        ):
            reconcile_backup_generation_continuity(object(), object(), object())


if __name__ == "__main__":
    unittest.main()
