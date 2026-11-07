import json
import unittest

from scripts.enterprise_hq_company_observer import (
    ObserverError,
    fetch_private_json,
    summarize,
)


def fixture():
    statuses = (
        ["CONFIGURED"] * 3
        + ["PLANNED"] * 6
        + ["GOVERNANCE_ONLY"]
        + ["NOT_STARTED"]
    )
    workstreams = [
        {
            "workstream_id": f"WS-{index:02d}",
            "status": status,
            "evidence_refs": ["internal-evidence-ref"] if index <= 4 else [],
        }
        for index, status in enumerate(statuses, start=1)
    ]
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
        "audit": {
            "timestamp": "2026-11-07T00:00:00Z",
            "system_status": "ACTIVE_OPERATIONS",
            "enterprise_status": "ACTIVE_OPERATIONS",
            "safety": {
                "safe_hold": False,
                "execution_hold": False,
                "dispatch_enabled": False,
                "product_task_execution": False,
                "builds_enabled": False,
                "releases_enabled": False,
                "deployments_enabled": False,
                "task_scoped_build_authorizations": {
                    "PRIVATE_SENTINEL": "DO_NOT_EMIT"
                },
            },
        },
        "register": {
            "authority": {"scope": "Enterprise-HQ parent company only"},
            "workstreams": workstreams,
        },
    }


class CompanyObserverTests(unittest.TestCase):
    def test_returns_aggregate_only_report(self):
        report = summarize(fixture())
        rendered = json.dumps(report)
        self.assertEqual(report["schema_version"], "1.1.0")
        self.assertEqual(report["status"], "OBSERVED")
        self.assertEqual(report["counts"]["private_governance_records_read"], 3)
        self.assertEqual(report["counts"]["workstreams"], 11)
        self.assertEqual(
            report["counts"]["workstreams_by_status"],
            {
                "CONFIGURED": 3,
                "GOVERNANCE_ONLY": 1,
                "NOT_STARTED": 1,
                "PLANNED": 6,
            },
        )
        self.assertEqual(report["counts"]["workstreams_with_evidence"], 4)
        self.assertEqual(report["company_control"]["boolean_safety_gate_count"], 7)
        self.assertFalse(report["capability_truth"]["this_worker_executes_company_tasks"])
        self.assertFalse(report["capability_truth"]["this_worker_is_an_independent_ai_agent"])
        self.assertFalse(report["capability_truth"]["continuous_24x7_uptime_is_proven"])
        self.assertFalse(report["capability_truth"]["model_provider_is_authorized"])
        self.assertFalse(report["privacy"]["private_file_contents_in_report"])
        self.assertNotIn("PRIVATE_SENTINEL", rendered)
        self.assertNotIn("DO_NOT_EMIT", rendered)
        self.assertNotIn("source_audit_timestamp", report)

    def test_rejects_project_boundary_drift(self):
        records = fixture()
        records["identity"]["project_portfolio"]["first_project"]["repository"] = "wrong/repo"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_unknown_workstream(self):
        records = fixture()
        records["register"]["workstreams"][0]["workstream_id"] = "PROJECT-001"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_duplicate_workstream(self):
        records = fixture()
        records["register"]["workstreams"][1]["workstream_id"] = "WS-01"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_wrong_parent_company_scope(self):
        records = fixture()
        records["register"]["authority"]["scope"] = "PROJECT-001"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_invalid_audit_timestamp(self):
        records = fixture()
        records["audit"]["timestamp"] = "not-a-timestamp"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_missing_safety_gate_booleans(self):
        records = fixture()
        records["audit"]["safety"] = {"task_scoped_build_authorizations": {}}
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_non_allowlisted_private_path_before_network(self):
        with self.assertRaises(ObserverError) as caught:
            fetch_private_json("README.md", "not-used")
        self.assertEqual(str(caught.exception), "PRIVATE_RECORD_PATH_NOT_ALLOWED")


if __name__ == "__main__":
    unittest.main()
