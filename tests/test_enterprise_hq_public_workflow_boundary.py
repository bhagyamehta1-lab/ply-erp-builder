from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from scripts.enterprise_hq_public_workflow_boundary import (
    WorkflowBoundaryAuditError,
    audit_workflow_directory,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
OBSERVER_WORKFLOW = (
    WORKFLOW_DIR / "enterprise-hq-parent-company-observer.yml"
).read_text(encoding="utf-8")
OBSERVER_SOURCE = (
    ROOT / "scripts" / "enterprise_hq_company_observer.py"
).read_text(encoding="utf-8")
SCANNER_SOURCE = (
    ROOT / "scripts" / "enterprise_hq_public_workflow_boundary.py"
).read_text(encoding="utf-8")


class PublicWorkflowBoundaryTests(unittest.TestCase):
    def fixture(self, extra=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "enterprise-hq-parent-company-observer.yml").write_text(
            OBSERVER_WORKFLOW, encoding="utf-8"
        )
        for name, content in (extra or {}).items():
            target = root / name
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")
        return root

    def audit(self, root, observer=OBSERVER_SOURCE):
        return audit_workflow_directory(root, observer)

    def test_current_repository_inventory_is_bounded_and_reports_legacy_review(self):
        result = self.audit(WORKFLOW_DIR)
        self.assertEqual(result["workflow_count"], 9)
        self.assertEqual(result["company_observer_count"], 1)
        self.assertGreaterEqual(result["restricted_legacy_workflow_count"], 1)
        self.assertEqual(
            result["workflow_count"],
            result["company_observer_count"]
            + result["restricted_legacy_workflow_count"]
            + result["general_ci_workflow_count"],
        )
        self.assertEqual(result["repository_wide_status"], "REVIEW_REQUIRED")
        self.assertEqual(result["status"], "COMPANY_OBSERVER_ISOLATION_VERIFIED")

    def test_summary_does_not_emit_workflow_names(self):
        result = self.audit(WORKFLOW_DIR)
        rendered = str(result)
        self.assertNotIn("public_worker_executor.yml", rendered)
        self.assertNotIn("private-project-verification.yml", rendered)
        self.assertFalse(result["workflow_names_emitted"])

    def test_summary_keeps_all_authority_flags_false(self):
        result = self.audit(WORKFLOW_DIR)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["private_data_read"])
        self.assertFalse(result["workflow_commands_executed"])

    def test_rejects_inventory_without_company_observer(self):
        root = self.fixture({"general.yml": "name: General\n"})
        (root / "enterprise-hq-parent-company-observer.yml").unlink()
        with self.assertRaises(WorkflowBoundaryAuditError):
            self.audit(root)

    def test_rejects_empty_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(WorkflowBoundaryAuditError):
                self.audit(Path(temporary))

    def test_classifies_private_source_workflow(self):
        root = self.fixture({"legacy.yml": "PRIVATE_PAT: secrets.PRIVATE_PAT\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_legacy_workflow_count"], 1)
        self.assertEqual(result["restricted_signal_counts"]["private_source"], 1)

    def test_classifies_private_governance_reference(self):
        root = self.fixture({"legacy.yml": "path: state/ceo_command_audit.json\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["private_governance"], 1)

    def test_classifies_product_execution_reference(self):
        root = self.fixture({"legacy.yml": "mode: execute_task\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["product_execution"], 1)

    def test_classifies_repository_dispatch_reference(self):
        root = self.fixture({"legacy.yml": "repository_dispatch:\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["product_execution"], 1)

    def test_classifies_privileged_capability(self):
        root = self.fixture({"legacy.yml": "permissions:\n  models: read\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_extended_write_permission(self):
        root = self.fixture({"legacy.yml": "permissions:\n  pull-requests: write\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_write_all_permission(self):
        root = self.fixture({"legacy.yml": "permissions: write-all\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_quoted_block_write_permission(self):
        root = self.fixture({
            "legacy.yml": 'permissions:\n  "pull-requests": write # required\n'
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_multiline_flow_write_permission(self):
        root = self.fixture({
            "legacy.yml": (
                "permissions: {\n"
                "  'security-events': write,\n"
                "  contents: read\n"
                "}\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_does_not_classify_quoted_read_permission_as_privileged(self):
        root = self.fixture({
            "general.yml": 'permissions:\n  "pull-requests": read\n'
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 0)
        self.assertEqual(result["general_ci_workflow_count"], 1)

    def test_classifies_quoted_write_all_permission(self):
        root = self.fixture({
            "legacy.yml": 'permissions: "write-all" # unrestricted\n'
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_does_not_classify_read_all_permission_as_privileged(self):
        root = self.fixture({"general.yml": "permissions: read-all\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 0)
        self.assertEqual(result["general_ci_workflow_count"], 1)

    def test_classifies_inline_write_permission_mapping(self):
        root = self.fixture({
            "legacy.yml": "permissions: { contents: read, pull-requests: write }\n"
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_quoted_inline_write_permission_mapping(self):
        root = self.fixture({
            "legacy.yml": 'permissions: { "checks": write, contents: read }\n'
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_does_not_classify_inline_read_only_permission_mapping(self):
        root = self.fixture({
            "general.yml": "permissions: { contents: read, issues: read }\n"
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 0)
        self.assertEqual(result["general_ci_workflow_count"], 1)

    def test_classifies_write_all_permission_with_comment(self):
        root = self.fixture({
            "legacy.yml": "permissions: write-all # unrestricted\n"
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_counts_multiple_restriction_signals_without_exposing_content(self):
        root = self.fixture({
            "legacy.yml": (
                "PRIVATE_PAT: secrets.PRIVATE_PAT\n"
                "path: state/ceo_command_audit.json\n"
                "mode: execute_task\n"
                "  models: read\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_legacy_workflow_count"], 1)
        self.assertEqual(result["restricted_signal_counts"]["private_source"], 1)
        self.assertEqual(result["restricted_signal_counts"]["private_governance"], 1)
        self.assertEqual(result["restricted_signal_counts"]["product_execution"], 1)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)
        self.assertNotIn("legacy.yml", str(result))

    def test_classifies_unrecognized_workflow_as_general_ci(self):
        root = self.fixture({"general.yml": "name: Documentation lint\n"})
        result = self.audit(root)
        self.assertEqual(result["general_ci_workflow_count"], 1)
        self.assertEqual(result["restricted_legacy_workflow_count"], 0)
        self.assertEqual(
            result["repository_wide_status"], "NO_RESTRICTED_WORKFLOWS_DETECTED"
        )

    def test_ignores_nested_non_workflow_directories(self):
        root = self.fixture()
        nested = root / "nested"
        nested.mkdir()
        (nested / "hidden.yml").write_text(
            "execute_task: true\n", encoding="utf-8"
        )
        result = self.audit(root)
        self.assertEqual(result["workflow_count"], 1)

    def test_rejects_invalid_utf8_workflow(self):
        root = self.fixture({"legacy.yml": b"\xff\xfe"})
        with self.assertRaises(WorkflowBoundaryAuditError):
            self.audit(root)

    def test_rejects_oversized_workflow(self):
        root = self.fixture({"legacy.yml": "x" * (64 * 1024 + 1)})
        with self.assertRaises(WorkflowBoundaryAuditError):
            self.audit(root)

    def test_rejects_symlink_workflow(self):
        root = self.fixture()
        target = root / "target.yml"
        target.write_text("name: target\n", encoding="utf-8")
        (root / "linked.yml").symlink_to(target)
        with self.assertRaises(WorkflowBoundaryAuditError):
            self.audit(root)

    def test_rejects_more_than_64_workflow_files(self):
        extras = {f"extra-{index:02d}.yml": "name: Extra\n" for index in range(64)}
        root = self.fixture(extras)
        with self.assertRaises(WorkflowBoundaryAuditError):
            self.audit(root)

    def test_rejects_observer_policy_mutation(self):
        root = self.fixture()
        changed = OBSERVER_SOURCE.replace(
            "state/company_completion_register.json",
            "state/ceo_command_audit.json",
            1,
        )
        with self.assertRaises(WorkflowBoundaryAuditError):
            self.audit(root, changed)

    def test_rejects_root_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            actual = base / "actual"
            actual.mkdir()
            link = base / "link"
            link.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(WorkflowBoundaryAuditError):
                self.audit(link)

    def test_rejects_non_directory_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            file_path = Path(temporary) / "not-a-directory"
            file_path.write_text("x", encoding="utf-8")
            with self.assertRaises(WorkflowBoundaryAuditError):
                self.audit(file_path)

    def test_scanner_has_no_network_or_process_execution_imports(self):
        tree = ast.parse(SCANNER_SOURCE)
        imports = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module or "")
        self.assertFalse(any(
            name.startswith(("urllib", "http", "subprocess", "socket"))
            for name in imports
        ))
        self.assertFalse(any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
            for node in ast.walk(tree)
        ))


    def test_classifies_untrusted_pull_request_context(self):
        root = self.fixture({"legacy.yml": "on:\n  pull_request_target:\n"})
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["untrusted_event_context"], 1)

    def test_classifies_manual_and_external_dispatch(self):
        root = self.fixture({
            "legacy.yml": "on:\n  workflow_dispatch:\n  repository_dispatch:\n"
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["manual_or_external_dispatch"], 1)

    def test_classifies_unpinned_action_reference(self):
        root = self.fixture({
            "legacy.yml": "steps:\n  - name: Checkout\n    uses: actions/checkout@v4\n"
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["unpinned_action_reference"], 1)

    def test_does_not_flag_sha_pinned_action_reference(self):
        pinned = "0123456789abcdef0123456789abcdef01234567"
        root = self.fixture({
            "legacy.yml": f"steps:\n  - name: Checkout\n    uses: actions/checkout@{pinned}\n"
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["unpinned_action_reference"], 0)
        self.assertEqual(result["general_ci_workflow_count"], 1)

    def test_classifies_workflow_level_secret_environment(self):
        root = self.fixture({
            "legacy.yml": (
                "env:\n  READ_TOKEN: secrets.READ_TOKEN\n"
                "jobs:\n  check:\n    steps:\n      - run: echo safe\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["broad_secret_scope"], 1)

    def test_does_not_flag_step_scoped_secret_environment(self):
        root = self.fixture({
            "legacy.yml": (
                "jobs:\n  check:\n    steps:\n      - name: Read\n"
                "        env:\n          READ_TOKEN: secrets.READ_TOKEN\n"
                "        run: python observer.py\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["broad_secret_scope"], 0)
        self.assertEqual(result["general_ci_workflow_count"], 1)

    def test_classifies_unconditional_artifact_publication(self):
        root = self.fixture({
            "legacy.yml": (
                "steps:\n  - name: Upload\n    if: always()\n"
                "    uses: actions/upload-artifact@v4\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["unconditional_artifact_publication"], 1
        )

    def test_does_not_flag_success_conditioned_artifact_publication(self):
        root = self.fixture({
            "legacy.yml": (
                "steps:\n  - name: Upload\n    if: success()\n"
                "    uses: actions/upload-artifact@v4\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["unconditional_artifact_publication"], 0
        )

    def test_classifies_dependency_install_commands(self):
        root = self.fixture({"legacy.yml": "steps:\n  - run: npm install\n"})
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["network_or_dependency_install"], 1
        )


    def test_summary_initializes_derived_signal_counters(self):
        root = self.fixture({"legacy.yml": "name: Plain CI\n"})
        result = self.audit(root)
        self.assertIn("broad_secret_scope", result["restricted_signal_counts"])
        self.assertIn(
            "unconditional_artifact_publication", result["restricted_signal_counts"]
        )
        self.assertEqual(result["restricted_signal_counts"]["broad_secret_scope"], 0)
        self.assertEqual(
            result["restricted_signal_counts"]["unconditional_artifact_publication"], 0
        )


    def test_classifies_quoted_block_write_value(self):
        root = self.fixture({
            "legacy.yml": "permissions:\n  'pull-requests': 'write' # elevated\n"
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_quoted_inline_write_value(self):
        root = self.fixture({
            "legacy.yml": 'permissions: { "checks": "write", contents: read }\n'
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_quoted_multiline_flow_write_value(self):
        root = self.fixture({
            "legacy.yml": (
                "permissions: {\n"
                "  'security-events': 'write',\n"
                "  contents: read\n"
                "}\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)


    def test_classifies_quoted_inline_flow_write_with_trailing_comment(self):
        root = self.fixture({
            "legacy.yml": (
                "permissions: { contents: read, 'pull-requests': 'write' } # elevated\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_classifies_quoted_multiline_flow_write_with_trailing_comment(self):
        root = self.fixture({
            "legacy.yml": (
                "permissions: {\n"
                "  'security-events': 'write',\n"
                "  contents: read\n"
                "} # elevated\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 1)

    def test_does_not_classify_permission_text_inside_flow_comment(self):
        root = self.fixture({
            "general.yml": (
                "permissions: { contents: read } # pull-requests: write\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(result["restricted_signal_counts"]["privileged_capability"], 0)
        self.assertEqual(result["general_ci_workflow_count"], 1)

    def test_classifies_direct_permissions_alias_as_review_required(self):
        root = self.fixture({"legacy.yml": "permissions: *shared_permissions\n"})
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )

    def test_classifies_alias_inside_permissions_block(self):
        root = self.fixture({
            "legacy.yml": "permissions:\n  contents: *write_level\n"
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )

    def test_classifies_alias_inside_multiline_flow_permissions(self):
        root = self.fixture({
            "legacy.yml": (
                "permissions: {\n"
                "contents: *write_level\n"
                "}\n"
            )
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )

    def test_classifies_anchored_permissions_mapping_as_review_required(self):
        root = self.fixture({
            "legacy.yml": "permissions: &shared_permissions { contents: read }\n"
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )

    def test_ignores_permission_alias_text_inside_comments_and_quoted_scalars(self):
        root = self.fixture({
            "general.yml": (
                'permissions: { contents: read } # *shared_permissions\n'
                'jobs:\n  check:\n    permissions: { contents: "*literal" }\n'
            )
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 0
        )
        self.assertEqual(result["general_ci_workflow_count"], 1)


    def test_classifies_permission_alias_used_as_block_mapping_key(self):
        root = self.fixture({
            "legacy.yml": "permissions:\n  *permission_name: write\n"
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )

    def test_classifies_permission_alias_used_as_flow_mapping_key(self):
        root = self.fixture({
            "legacy.yml": "permissions: { *permission_name: write }\n"
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )


    def test_classifies_permission_alias_with_dotted_anchor_name(self):
        root = self.fixture({
            "legacy.yml": "permissions:\\n  *shared.policy: write\\n"
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )

    def test_classifies_permission_anchor_with_slash_name(self):
        root = self.fixture({
            "legacy.yml": "permissions: &team/policy { contents: read }\\n"
        })
        result = self.audit(root)
        self.assertEqual(
            result["restricted_signal_counts"]["permission_yaml_indirection"], 1
        )



if __name__ == "__main__":
    unittest.main()
