import base64
import json
import unittest
from unittest.mock import patch

import scripts.enterprise_hq_company_observer as observer
from scripts.enterprise_hq_company_observer import ObserverError, summarize


def audit_fixture():
    safety = {key: False for key in observer.REQUIRED_SAFETY_BOOLEAN_FIELDS}
    safety.update({
        "active_in_progress_task_count": 0,
        "active_dispatch_task_count": 0,
        "task_scoped_build_authorizations": {},
    })
    return {
        "schema_version": "1.0.0",
        "timestamp": "2026-11-07T00:00:00Z",
        "enterprise_status": "ACTIVE_OPERATIONS",
        "safety": safety,
    }


def fixture():
    return {
        "identity": {
            "company": {
                "name": "Enterprise-HQ",
                "canonical_repository": "bhagyamehta1-lab/Enterprise-HQ",
                "is_product_app": False,
            },
            "project_portfolio": {
                "first_project": {
                    "project_id": "PROJECT-001",
                    "name": "PLY ERP",
                    "repository": "bhagyamehta1-lab/PLY_ERP",
                }
            },
            "readiness": {
                "company_operating_status": "IN_DEVELOPMENT_NOT_CERTIFIED",
                "legal_entity_status": "NOT_VERIFIED_FROM_REPOSITORY",
                "independent_ai_operations_status": "NOT_CERTIFIED",
                "continuous_24x7_status": "NOT_CERTIFIED",
            },
        },
        "audit": audit_fixture(),
        "register": {
            "schema_version": "1.0.0",
            "authority": {"scope": "Enterprise-HQ parent company only"},
            "status_vocabulary": sorted(observer.WORKSTREAM_STATUSES),
            "workstreams": [
                {"workstream_id": f"WS-{i:02d}", "status": "PLANNED"}
                for i in range(1, 12)
            ],
        },
    }


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class CompanyObserverTests(unittest.TestCase):
    def test_returns_counts_and_statuses_only(self):
        report = summarize(fixture())
        self.assertEqual(report["status"], "OBSERVED")
        self.assertEqual(report["scope_status"], "PARENT_COMPANY_ONLY")
        self.assertEqual(report["counts"]["workstreams"], 11)
        self.assertEqual(report["counts"]["workstreams_by_status"], {"PLANNED": 11})
        self.assertNotIn("generated_at", report)
        self.assertNotIn("source_audit_timestamp", report)
        self.assertNotIn("company", report)
        self.assertEqual(report["privacy_status"]["private_file_contents"], "NOT_EMITTED")

    def test_unknown_readiness_values_are_replaced_not_emitted(self):
        records = fixture()
        records["identity"]["readiness"]["company_operating_status"] = "PRIVATE_FREEFORM_TEXT"
        report = summarize(records)
        self.assertEqual(report["readiness"]["company_operating_status"], "UNKNOWN")
        self.assertNotIn("PRIVATE_FREEFORM_TEXT", json.dumps(report))

    def test_rejects_unknown_workstream_status(self):
        records = fixture()
        records["register"]["workstreams"][0]["status"] = "PRIVATE_FREEFORM_TEXT"
        with self.assertRaisesRegex(ObserverError, "COMPANY_WORKSTREAM_ROW_INVALID"):
            summarize(records)

    def test_rejects_project_boundary_drift(self):
        records = fixture()
        records["identity"]["project_portfolio"]["first_project"]["repository"] = "wrong/repo"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_unknown_workstream(self):
        records = fixture()
        records["register"]["workstreams"][0]["workstream_id"] = "PLY-ERP"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_wrong_parent_company_scope(self):
        records = fixture()
        records["register"]["authority"]["scope"] = "PLY_ERP"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_duplicate_or_missing_workstream(self):
        records = fixture()
        records["register"]["workstreams"][0]["workstream_id"] = "WS-02"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_malformed_audit_timestamp(self):
        records = fixture()
        records["audit"]["timestamp"] = "PRIVATE_TEXT"
        with self.assertRaisesRegex(ObserverError, "CEO_AUDIT_SCHEMA_INVALID"):
            summarize(records)

    def test_rejects_incomplete_safety_schema_without_emitting_gate_values(self):
        records = fixture()
        records["audit"]["safety"].pop("dispatch_enabled")
        with self.assertRaisesRegex(ObserverError, "CEO_AUDIT_SAFETY_SCHEMA_INVALID"):
            summarize(records)

    def test_private_path_allowlist_blocks_other_files(self):
        with patch.object(observer.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_PATH_NOT_ALLOWED"):
                observer.fetch_private_json("src/private.py", "test-token")
            urlopen.assert_not_called()

    def test_base64_whitespace_is_decoded_safely(self):
        payload = {"safe": True}
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        wrapped = "\n".join((encoded[:8], encoded[8:16], encoded[16:]))
        body = json.dumps({"content": wrapped}).encode()
        with patch.object(observer.urllib.request, "urlopen", return_value=FakeResponse(body)):
            self.assertEqual(observer.fetch_private_json(observer.FILES["audit"], "test-token"), payload)

    def test_malformed_private_record_envelope_is_rejected(self):
        body = json.dumps({"content": ["not", "base64"]}).encode()
        with patch.object(observer.urllib.request, "urlopen", return_value=FakeResponse(body)):
            with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_PARSE_FAILED"):
                observer.fetch_private_json(observer.FILES["audit"], "test-token")

    def test_private_response_size_is_bounded(self):
        body = json.dumps({"content": base64.b64encode(b"{}").decode()}).encode()
        with patch.object(observer, "MAX_PRIVATE_RECORD_BYTES", 8):
            with patch.object(observer.urllib.request, "urlopen", return_value=FakeResponse(body)):
                with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_TOO_LARGE"):
                    observer.fetch_private_json(observer.FILES["audit"], "test-token")


if __name__ == "__main__":
    unittest.main()
