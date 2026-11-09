from __future__ import annotations

import unittest
from pathlib import Path

from scripts.enterprise_hq_company_observer_policy import (
    ObserverPolicyError,
    validate_company_observer_policy,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/enterprise-hq-parent-company-observer.yml").read_text(encoding="utf-8")
OBSERVER = (ROOT / "scripts/enterprise_hq_company_observer.py").read_text(encoding="utf-8")


class CompanyObserverPolicyTests(unittest.TestCase):
    def reject(self, workflow=None, observer=None):
        with self.assertRaises(ObserverPolicyError):
            validate_company_observer_policy(
                WORKFLOW if workflow is None else workflow,
                OBSERVER if observer is None else observer,
            )

    def test_accepts_current_contract(self):
        result = validate_company_observer_policy(WORKFLOW, OBSERVER)
        self.assertEqual(result["status"], "COMPANY_OBSERVER_POLICY_VALID")
        self.assertEqual(result["repository_permission"], "contents: read")
        self.assertFalse(result["execution_authorized"])

    def test_returns_only_bounded_metadata(self):
        result = validate_company_observer_policy(WORKFLOW, OBSERVER)
        self.assertEqual(result["workflow_trigger_count"], 3)
        self.assertEqual(result["private_path_allowlist_count"], 1)
        self.assertEqual(result["private_response_limit_bytes"], 512 * 1024)
        self.assertNotIn("token", result)

    def test_rejects_oversized_workflow(self):
        self.reject(workflow=WORKFLOW + " " * 20000)

    def test_rejects_tabs(self):
        self.reject(workflow=WORKFLOW.replace("permissions:", "\tpermissions:", 1))

    def test_rejects_repository_dispatch(self):
        self.reject(workflow=WORKFLOW.replace(
            "  workflow_dispatch:\n", "  workflow_dispatch:\n  repository_dispatch:\n", 1
        ))

    def test_rejects_pull_request_trigger(self):
        self.reject(workflow=WORKFLOW.replace(
            "  workflow_dispatch:\n", "  pull_request:\n  workflow_dispatch:\n", 1
        ))

    def test_rejects_main_push(self):
        self.reject(workflow=WORKFLOW.replace(
            "company/hq-lease-recovery-contract-verified-2026-11-07", "main", 1
        ))

    def test_rejects_extra_push_branch(self):
        self.reject(workflow=WORKFLOW.replace(
            "      - company/hq-lease-recovery-contract-verified-2026-11-07\n",
            "      - company/hq-lease-recovery-contract-verified-2026-11-07\n      - main\n", 1
        ))

    def test_rejects_wrong_schedule(self):
        self.reject(workflow=WORKFLOW.replace('cron: "17,47 * * * *"', 'cron: "*/5 * * * *"', 1))

    def test_rejects_write_permission(self):
        self.reject(workflow=WORKFLOW.replace("  contents: read", "  contents: write", 1))

    def test_rejects_models_permission(self):
        self.reject(workflow=WORKFLOW.replace("  contents: read", "  models: read", 1))

    def test_rejects_additional_job(self):
        self.reject(workflow=WORKFLOW.replace(
            "jobs:\n", "jobs:\n  extra-job:\n    runs-on: ubuntu-latest\n", 1
        ))

    def test_rejects_unapproved_action(self):
        self.reject(workflow=WORKFLOW.replace("actions/checkout@v4", "unknown/action@v1", 1))

    def test_rejects_persistent_checkout_credentials(self):
        self.reject(workflow=WORKFLOW.replace("persist-credentials: false", "persist-credentials: true", 1))

    def test_rejects_additional_secret(self):
        line = "          ENTERPRISE_HQ_READ_TOKEN: " + "$" + "{{ secrets.ENTERPRISE_HQ_READ_TOKEN }}"
        self.reject(workflow=WORKFLOW.replace(
            line, line + "\n          EXTRA_TOKEN: " + "$" + "{{ secrets.EXTRA_TOKEN }}", 1
        ))

    def test_rejects_unscoped_secret(self):
        self.reject(workflow=WORKFLOW.replace(
            "      - name: Read private HQ metadata and emit aggregate-only report\n        env:\n",
            "    env:\n", 1
        ))

    def test_rejects_changed_observer_command(self):
        self.reject(workflow=WORKFLOW.replace(
            "scripts/enterprise_hq_company_observer.py", "scripts/other.py", 1
        ))

    def test_rejects_public_artifact_path(self):
        old = "$" + "{{ runner.temp }}/enterprise-hq-company-summary.json"
        self.reject(workflow=WORKFLOW.replace(old, "public-report.json", 1))

    def test_rejects_long_artifact_retention(self):
        self.reject(workflow=WORKFLOW.replace("retention-days: 1", "retention-days: 30", 1))

    def test_rejects_non_company_test(self):
        self.reject(workflow=WORKFLOW.replace(
            "test_enterprise_hq_company_observer.py", "test_product.py", 1
        ))

    def test_rejects_missing_test_commands(self):
        lines = [line for line in WORKFLOW.splitlines() if "run: python -m unittest discover -s tests" not in line]
        self.reject(workflow="\n".join(lines) + "\n")

    def test_rejects_extra_private_file(self):
        altered = OBSERVER.replace(
            '"register": "state/company_completion_register.json",',
            '"register": "state/company_completion_register.json",\n    "audit": "state/ceo_command_audit.json",',
            1,
        )
        self.reject(observer=altered)

    def test_rejects_widened_private_path_guard(self):
        altered = OBSERVER.replace(
            "frozenset(FILES.values())",
            'frozenset({"state/company_completion_register.json", "state/ceo_command_audit.json"})',
            1,
        )
        self.reject(observer=altered)

    def test_rejects_oversized_private_response(self):
        self.reject(observer=OBSERVER.replace(
            "MAX_PRIVATE_RECORD_BYTES = 512 * 1024", "MAX_PRIVATE_RECORD_BYTES = 1024 * 1024", 1
        ))

    def test_rejects_unapproved_import(self):
        self.reject(observer=OBSERVER.replace("import os\n", "import os\nimport subprocess\n", 1))

    def test_rejects_network_outside_guarded_fetch(self):
        self.reject(observer=OBSERVER.replace(
            "import argparse\n", 'import argparse\nurllib.request.urlopen("https://example.invalid")\n', 1
        ))

    def test_rejects_missing_path_guard(self):
        self.reject(observer=OBSERVER.replace("if path not in ALLOWED_PRIVATE_PATHS:", "if False:", 1))

    def test_rejects_wrong_private_repository(self):
        self.reject(observer=OBSERVER.replace(
            "bhagyamehta1-lab/Enterprise-HQ", "bhagyamehta1-lab/PLY_ERP", 1
        ))

    def test_rejects_project_001_scope_expansion(self):
        self.reject(observer=OBSERVER.replace(
            "EXCLUDED_BY_COMPANY_WORKER_POLICY", "INCLUDED", 1
        ))

    def test_rejects_private_output_marker(self):
        self.reject(observer=OBSERVER.replace(
            '"private_file_contents": "NOT_EMITTED"', '"private_file_contents": "EMITTED"', 1
        ))

    def test_rejects_token_print(self):
        self.reject(observer=OBSERVER.replace(
            '    token = os.environ.get("ENTERPRISE_HQ_READ_TOKEN", "")',
            '    token = os.environ.get("ENTERPRISE_HQ_READ_TOKEN", "")\n    print(token)', 1
        ))

    def test_rejects_process_execution(self):
        altered = OBSERVER.replace("import os\n", "import os\nimport subprocess\n", 1)
        altered = altered.replace("HQ_REPOSITORY =", 'subprocess.run(["echo", "unsafe"])\nHQ_REPOSITORY =', 1)
        self.reject(observer=altered)

    def test_rejects_extra_report_field(self):
        self.reject(observer=OBSERVER.replace(
            '    return {\n        "schema_version": "1.0.0",',
            '    return {\n        "private_payload": register,\n        "schema_version": "1.0.0",', 1
        ))

    def test_rejects_24x7_claim(self):
        self.reject(observer=OBSERVER.replace(
            '"continuous_24x7_uptime": "NOT_PROVEN"', '"continuous_24x7_uptime": "PROVEN"', 1
        ))

    def test_rejects_extra_environment_lookup(self):
        self.reject(observer=OBSERVER.replace(
            '    token = os.environ.get("ENTERPRISE_HQ_READ_TOKEN", "")',
            '    token = os.environ.get("ENTERPRISE_HQ_READ_TOKEN", "")\n'
            '    extra = os.environ.get("EXTRA_PRIVATE_TOKEN", "")', 1
        ))

    def test_rejects_file_deletion(self):
        self.reject(observer=OBSERVER.replace(
            '        args.output.write_text(rendered + "\\n", encoding="utf-8")',
            '        args.output.write_text(rendered + "\\n", encoding="utf-8")\\n        args.output.unlink()', 1
        ))

    def test_rejects_missing_artifact_validation_step(self):
        step = (
            "      - name: Validate aggregate-only observer artifact\n"
            '        run: python scripts/enterprise_hq_company_observer_artifact.py --report "$RUNNER_TEMP/enterprise-hq-company-summary.json"\n'
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_artifact_validation_after_upload(self):
        step = (
            "      - name: Validate aggregate-only observer artifact\n"
            '        run: python scripts/enterprise_hq_company_observer_artifact.py --report "$RUNNER_TEMP/enterprise-hq-company-summary.json"\n'
        )
        altered = WORKFLOW.replace(step, "", 1).rstrip() + "\n" + step
        self.reject(workflow=altered)

    def test_rejects_unconditional_artifact_upload(self):
        self.reject(workflow=WORKFLOW.replace("if: success()", "if: always()", 1))



    def test_rejects_missing_public_workflow_boundary_inventory_suite(self):
        step = (
            "      - name: Test public workflow separation inventory\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_public_workflow_boundary.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_missing_observer_freshness_suite(self):
        step = (
            "      - name: Test deterministic observer freshness contract\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))


    def test_rejects_missing_observer_freshness_ledger_suite(self):
        step = (
            "      - name: Test persistent observer freshness receipt ledger\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness_ledger.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_missing_observer_freshness_backup_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_observer_freshness_backup.py",
            "test_missing_observer_freshness_backup.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_observer_freshness_backup_receipt_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_observer_freshness_backup_receipts.py",
            "test_missing_observer_freshness_backup_receipts.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_observer_freshness_backup_availability_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_observer_freshness_backup_availability.py",
            "test_missing_observer_freshness_backup_availability.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_observer_freshness_backup_availability_ledger_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_observer_freshness_backup_availability_ledger.py",
            "test_missing_observer_freshness_backup_availability_ledger.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_backup_availability_reconciliation_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_backup_availability_reconciliation.py",
            "test_missing_backup_availability_reconciliation.py",
            1,
        )
        self.reject(workflow=altered)


    def test_rejects_missing_backup_artifact_binding_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_backup_artifact_binding.py",
            "test_missing_backup_artifact_binding.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_backup_artifact_binding_ledger_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_backup_artifact_binding_ledger.py",
            "test_missing_backup_artifact_binding_ledger.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_backup_artifact_binding_service_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_backup_artifact_binding_service.py",
            "test_missing_backup_artifact_binding_service.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_independent_binding_snapshot_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_backup_artifact_binding_snapshot.py",
            "test_missing_backup_artifact_binding_snapshot.py",
            1,
        )
        self.reject(workflow=altered)

    def test_rejects_missing_backup_generation_continuity_suite(self):
        altered = WORKFLOW.replace(
            "test_enterprise_hq_backup_generation_continuity.py",
            "test_missing_backup_generation_continuity.py",
            1,
        )
        self.reject(workflow=altered)



    def test_rejects_missing_backup_predecessor_availability_suite(self):
        step = (
            "      - name: Test backup predecessor availability\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_predecessor_availability.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_missing_backup_recovery_readiness_suite(self):
        step = (
            "      - name: Test aggregate backup recovery readiness\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_missing_recovery_readiness_history_ledger_suite(self):
        step = (
            "      - name: Test persistent aggregate recovery-readiness history\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_ledger.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_missing_independent_recovery_readiness_snapshot_suite(self):
        step = (
            "      - name: Test independent recovery-readiness history snapshot\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_snapshot.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_missing_recovery_readiness_service_suite(self):
        step = (
            "      - name: Test persisted recovery-readiness service integration\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_service.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))

    def test_rejects_missing_recovery_readiness_transition_suite(self):
        step = (
            "      - name: Test independent recovery-readiness transition history\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_transitions.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))


    def test_rejects_missing_recovery_readiness_restart_suite(self):
        step = (
            "      - name: Test close-reopen recovery-readiness restart adapter\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_restart.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))


    def test_rejects_missing_recovery_interruption_suite(self):
        step = (
            "      - name: Test interrupted recovery-readiness append reconciliation\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_interruption.py'\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))


    def test_rejects_missing_recovery_readiness_crash_point_suite(self):
        step = (
            "      - name: Test recovery-readiness SQLite crash points\\n"
            "        run: python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_crash_points.py'\\n"
        )
        self.reject(workflow=WORKFLOW.replace(step, "", 1))


if __name__ == "__main__":
    unittest.main()
