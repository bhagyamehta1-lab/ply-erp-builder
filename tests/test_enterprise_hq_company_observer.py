import base64
import json
import unittest
from unittest.mock import patch

import scripts.enterprise_hq_company_observer as observer
from scripts.enterprise_hq_company_observer import ObserverError, summarize


def fixture():
    return {
        "register": {
            "schema_version": "1.0.0",
            "authority": {"scope": "Enterprise-HQ parent company only"},
            "status_vocabulary": sorted(observer.WORKSTREAM_STATUSES),
            "workstreams": [
                {
                    "workstream_id": f"WS-{i:02d}",
                    "status": "PLANNED",
                    "title": "PRIVATE_TITLE_MUST_NOT_BE_EMITTED",
                    "blockers": ["PRIVATE_BLOCKER_MUST_NOT_BE_EMITTED"],
                }
                for i in range(1, 12)
            ],
        }
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
    def test_returns_aggregate_counts_and_statuses_only(self):
        report = summarize(fixture())
        self.assertEqual(report["status"], "OBSERVED")
        self.assertEqual(report["scope_status"], "PARENT_COMPANY_ONLY")
        self.assertEqual(report["project_001_scope"], "EXCLUDED_BY_COMPANY_WORKER_POLICY")
        self.assertEqual(report["counts"]["workstreams"], 11)
        self.assertEqual(report["counts"]["workstreams_by_status"], {"PLANNED": 11})
        self.assertNotIn("workstreams", report)
        self.assertNotIn("title", json.dumps(report))
        self.assertNotIn("PRIVATE_TITLE_MUST_NOT_BE_EMITTED", json.dumps(report))
        self.assertNotIn("PRIVATE_BLOCKER_MUST_NOT_BE_EMITTED", json.dumps(report))
        self.assertEqual(report["privacy_status"]["private_file_contents"], "NOT_EMITTED")
        self.assertEqual(
            report["privacy_status"]["ceo_command_audit"],
            "NOT_FETCHED_BY_PUBLIC_OBSERVER",
        )

    def test_rejects_unknown_workstream_status(self):
        records = fixture()
        records["register"]["workstreams"][0]["status"] = "PRIVATE_FREEFORM_TEXT"
        with self.assertRaisesRegex(ObserverError, "COMPANY_WORKSTREAM_ROW_INVALID"):
            summarize(records)

    def test_rejects_unknown_workstream(self):
        records = fixture()
        records["register"]["workstreams"][0]["workstream_id"] = "PLY-ERP"
        with self.assertRaisesRegex(ObserverError, "COMPANY_WORKSTREAM_ROW_INVALID"):
            summarize(records)

    def test_rejects_wrong_parent_company_scope(self):
        records = fixture()
        records["register"]["authority"]["scope"] = "PLY_ERP"
        with self.assertRaisesRegex(ObserverError, "COMPANY_REGISTER_SCOPE_INVALID"):
            summarize(records)

    def test_rejects_duplicate_or_missing_workstream(self):
        records = fixture()
        records["register"]["workstreams"][0]["workstream_id"] = "WS-02"
        with self.assertRaisesRegex(ObserverError, "COMPANY_WORKSTREAM_SET_INVALID"):
            summarize(records)

    def test_rejects_wrong_record_set_and_prevents_audit_fetch(self):
        records = fixture()
        records["audit"] = {"commands": ["PRIVATE_COMMAND"]}
        with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_SET_INVALID"):
            summarize(records)
        with patch.object(observer.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_PATH_NOT_ALLOWED"):
                observer.fetch_private_json("state/ceo_command_audit.json", "test-token")
            urlopen.assert_not_called()

    def test_private_path_allowlist_blocks_unapproved_files(self):
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
            self.assertEqual(
                observer.fetch_private_json(observer.FILES["register"], "test-token"),
                payload,
            )

    def test_malformed_private_record_envelope_is_rejected(self):
        body = json.dumps({"content": ["not", "base64"]}).encode()
        with patch.object(observer.urllib.request, "urlopen", return_value=FakeResponse(body)):
            with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_PARSE_FAILED"):
                observer.fetch_private_json(observer.FILES["register"], "test-token")

    def test_private_response_size_is_bounded(self):
        body = json.dumps({"content": base64.b64encode(b"{}").decode()}).encode()
        with patch.object(observer, "MAX_PRIVATE_RECORD_BYTES", 8):
            with patch.object(observer.urllib.request, "urlopen", return_value=FakeResponse(body)):
                with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_TOO_LARGE"):
                    observer.fetch_private_json(observer.FILES["register"], "test-token")

    def test_rejects_incomplete_status_vocabulary(self):
        records = fixture()
        records["register"]["status_vocabulary"] = ["PLANNED"]
        with self.assertRaisesRegex(ObserverError, "COMPANY_STATUS_VOCABULARY_INVALID"):
            summarize(records)

    def test_rejects_non_dictionary_register(self):
        with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_SCHEMA_INVALID"):
            summarize({"register": []})

    def test_rejects_non_dictionary_authority(self):
        records = fixture()
        records["register"]["authority"] = []
        with self.assertRaisesRegex(ObserverError, "PRIVATE_RECORD_SCHEMA_INVALID"):
            summarize(records)


if __name__ == "__main__":
    unittest.main()
