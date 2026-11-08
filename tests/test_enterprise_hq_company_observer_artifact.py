from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_company_observer_artifact import (
    ArtifactValidationError,
    EXPECTED_REPORT_NAME,
    MAX_REPORT_BYTES,
    main,
    validate_observer_report,
    validate_observer_report_text,
)


def valid_report():
    return {
        "schema_version": "1.0.0",
        "scope_status": "PARENT_COMPANY_ONLY",
        "project_001_scope": "EXCLUDED_BY_COMPANY_WORKER_POLICY",
        "status": "OBSERVED",
        "checks": {
            "company_register_scope": "PASS",
            "company_completion_register": "PASS",
            "company_workstream_set": "PASS",
        },
        "counts": {
            "workstreams": 11,
            "workstreams_by_status": {
                "CONFIGURED": 3,
                "PLANNED": 6,
                "GOVERNANCE_ONLY": 1,
                "NOT_STARTED": 1,
            },
        },
        "capability_status": {
            "company_task_execution": "NOT_IMPLEMENTED",
            "independent_agent_identity": "NOT_AUTHENTICATED",
            "continuous_24x7_uptime": "NOT_PROVEN",
        },
        "privacy_status": {
            "private_file_contents": "NOT_EMITTED",
            "secrets_or_tokens": "NOT_EMITTED",
            "ceo_command_audit": "NOT_FETCHED_BY_PUBLIC_OBSERVER",
            "product_source": "NOT_READ",
        },
    }


class CompanyObserverArtifactTests(unittest.TestCase):
    def reject_report(self, report):
        with self.assertRaises(ArtifactValidationError):
            validate_observer_report(report)

    def test_accepts_valid_aggregate_report(self):
        result = validate_observer_report(valid_report())
        self.assertEqual(result["status"], "ARTIFACT_VALIDATED")
        self.assertFalse(result["execution_authorized"])

    def test_returns_only_bounded_metadata(self):
        result = validate_observer_report(valid_report())
        self.assertEqual(
            set(result),
            {
                "status", "schema_version", "report_sha256", "workstreams",
                "status_class_count", "execution_authorized", "private_payload_emitted",
            },
        )
        self.assertFalse(result["private_payload_emitted"])
        self.assertNotIn("register", result)

    def test_digest_is_independent_of_object_key_order(self):
        first = valid_report()
        second = dict(reversed(list(first.items())))
        self.assertEqual(
            validate_observer_report(first)["report_sha256"],
            validate_observer_report(second)["report_sha256"],
        )

    def test_rejects_extra_top_level_field(self):
        report = valid_report()
        report["private_payload"] = {"unexpected": True}
        self.reject_report(report)

    def test_rejects_missing_top_level_field(self):
        report = valid_report()
        del report["privacy_status"]
        self.reject_report(report)

    def test_rejects_wrong_company_scope(self):
        report = valid_report()
        report["scope_status"] = "PROJECT_SCOPE"
        self.reject_report(report)

    def test_rejects_project_001_inclusion(self):
        report = valid_report()
        report["project_001_scope"] = "INCLUDED"
        self.reject_report(report)

    def test_rejects_wrong_observation_status(self):
        report = valid_report()
        report["status"] = "EXECUTED"
        self.reject_report(report)

    def test_rejects_non_pass_check(self):
        report = valid_report()
        report["checks"]["company_register_scope"] = "FAIL"
        self.reject_report(report)

    def test_rejects_extra_check(self):
        report = valid_report()
        report["checks"]["product_dispatch"] = "PASS"
        self.reject_report(report)

    def test_rejects_wrong_workstream_total(self):
        report = valid_report()
        report["counts"]["workstreams"] = 10
        self.reject_report(report)

    def test_rejects_boolean_workstream_total(self):
        report = valid_report()
        report["counts"]["workstreams"] = True
        self.reject_report(report)

    def test_rejects_negative_status_count(self):
        report = valid_report()
        report["counts"]["workstreams_by_status"]["PLANNED"] = -1
        self.reject_report(report)

    def test_rejects_unknown_status(self):
        report = valid_report()
        report["counts"]["workstreams_by_status"]["CUSTOMER_CONTACTED"] = 1
        self.reject_report(report)

    def test_rejects_status_count_sum_mismatch(self):
        report = valid_report()
        report["counts"]["workstreams_by_status"]["PLANNED"] = 5
        self.reject_report(report)

    def test_rejects_capability_claim_expansion(self):
        report = valid_report()
        report["capability_status"]["company_task_execution"] = "ACTIVE"
        self.reject_report(report)

    def test_rejects_privacy_claim_expansion(self):
        report = valid_report()
        report["privacy_status"]["private_file_contents"] = "EMITTED"
        self.reject_report(report)

    def test_rejects_duplicate_json_keys(self):
        with self.assertRaises(ArtifactValidationError):
            validate_observer_report_text(
                '{"schema_version":"1.0.0","schema_version":"1.0.0"}'
            )

    def test_rejects_invalid_json(self):
        with self.assertRaises(ArtifactValidationError):
            validate_observer_report_text("{not-json")

    def test_rejects_oversized_report_text(self):
        with self.assertRaises(ArtifactValidationError):
            validate_observer_report_text(" " * (MAX_REPORT_BYTES + 1))

    def test_cli_requires_runner_temp(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(output):
            code = main(["--report", "/tmp/" + EXPECTED_REPORT_NAME])
        self.assertEqual(code, 2)
        self.assertIn("ARTIFACT_RUNNER_TEMP_MISSING", output.getvalue())

    def test_cli_rejects_path_outside_runner_temp(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            report = Path(outside) / EXPECTED_REPORT_NAME
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            output = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": root}), contextlib.redirect_stdout(output):
                code = main(["--report", str(report)])
        self.assertEqual(code, 2)
        self.assertIn("ARTIFACT_PATH_INVALID", output.getvalue())

    def test_cli_rejects_wrong_filename(self):
        with tempfile.TemporaryDirectory() as root:
            report = Path(root) / "other.json"
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            output = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": root}), contextlib.redirect_stdout(output):
                code = main(["--report", str(report)])
        self.assertEqual(code, 2)
        self.assertIn("ARTIFACT_PATH_INVALID", output.getvalue())

    def test_cli_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "target.json"
            target.write_text(json.dumps(valid_report()), encoding="utf-8")
            report = Path(root) / EXPECTED_REPORT_NAME
            os.symlink(target, report)
            output = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": root}), contextlib.redirect_stdout(output):
                code = main(["--report", str(report)])
        self.assertEqual(code, 2)
        self.assertIn("ARTIFACT_PATH_INVALID", output.getvalue())

    def test_cli_validates_and_prints_aggregate_only(self):
        with tempfile.TemporaryDirectory() as root:
            report = Path(root) / EXPECTED_REPORT_NAME
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            output = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": root}), contextlib.redirect_stdout(output):
                code = main(["--report", str(report)])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "ARTIFACT_VALIDATED")
        self.assertFalse(result["execution_authorized"])
        self.assertNotIn("privacy_status", result)


if __name__ == "__main__":
    unittest.main()
