import unittest
from scripts.enterprise_hq_company_observer import ObserverError, summarize


def fixture():
    return {
        "identity": {
            "company": {"name": "Enterprise-HQ", "canonical_repository": "bhagyamehta1-lab/Enterprise-HQ",
                        "is_product_app": False},
            "project_portfolio": {"first_project": {"project_id": "PROJECT-001", "name": "PLY ERP",
                                                    "repository": "bhagyamehta1-lab/PLY_ERP"}},
            "readiness": {"company_operating_status": "IN_DEVELOPMENT_NOT_CERTIFIED",
                          "legal_entity_status": "NOT_VERIFIED_FROM_REPOSITORY",
                          "independent_ai_operations_status": "NOT_CERTIFIED",
                          "continuous_24x7_status": "NOT_CERTIFIED"},
        },
        "audit": {"timestamp": "2026-11-07T00:00:00Z", "safety": {}},
        "register": {"authority": {"scope": "Enterprise-HQ parent company only"},
                     "workstreams": [{"workstream_id": f"WS-{i:02d}", "status": "PLANNED"}
                                     for i in range(1, 12)]},
        "departments": {"scope": "ENTERPRISE_HQ_PARENT_COMPANY_ONLY",
                        "departments": [{"status": "DESIGNED_NOT_OPERATIONAL"}]},
        "roles": {"scope": "ENTERPRISE_HQ_PARENT_COMPANY_ONLY",
                  "roles": [{"role_id": "CEO-01", "status": "ACCOUNTABLE_EXECUTIVE"},
                            {"role_id": "HQ-OPS-01", "status": "DESIGNED_NOT_ACTIVE"}]},
        "seed": {"scope": "ENTERPRISE_HQ_PARENT_COMPANY_ONLY",
                 "tasks": [{"task_id": "HQ-1", "workstream_id": "WS-01",
                            "task_kind": "READ_ONLY_AUDIT"}]},
    }


class CompanyObserverTests(unittest.TestCase):
    def test_returns_aggregate_only_report(self):
        report = summarize(fixture())
        self.assertEqual(report["status"], "OBSERVED")
        self.assertEqual(report["counts"]["workstreams"], 11)
        self.assertEqual(report["counts"]["active_software_roles"], 0)
        self.assertFalse(report["capability_truth"]["this_worker_executes_company_tasks"])
        self.assertFalse(report["privacy"]["private_file_contents_in_report"])

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

    def test_rejects_non_internal_seed_task(self):
        records = fixture()
        records["seed"]["tasks"][0]["task_kind"] = "DEPLOY"
        with self.assertRaises(ObserverError):
            summarize(records)

    def test_rejects_wrong_parent_company_scope(self):
        records = fixture()
        records["departments"]["scope"] = "PLY_ERP"
        with self.assertRaises(ObserverError):
            summarize(records)


if __name__ == "__main__":
    unittest.main()
