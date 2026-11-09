"""Static regression contract for the public Enterprise-HQ observer boundary."""
from __future__ import annotations

import ast
import re

EXPECTED_BRANCH = "company/hq-lease-recovery-contract-verified-2026-11-07"
EXPECTED_REPOSITORY = "bhagyamehta1-lab/Enterprise-HQ"
EXPECTED_PRIVATE_PATH = "state/company_completion_register.json"
MAX_WORKFLOW_BYTES = 16 * 1024
MAX_OBSERVER_BYTES = 32 * 1024
MAX_PRIVATE_RECORD_BYTES = 512 * 1024
ACTIONS = (
    "actions/checkout@v4",
    "actions/setup-python@v5",
    "actions/upload-artifact@v4",
)
IMPORTS = {
    "__future__.annotations", "argparse", "base64", "json", "os",
    "urllib.error", "urllib.parse", "urllib.request",
    "collections.Counter", "pathlib.Path",
}
FORBIDDEN = (
    "pull_request", "pull_request_target", "repository_dispatch", "workflow_run",
    "models:", "contents: write", "actions: write", "id-token: write",
    "packages: write", "GITHUB_TOKEN", "github.token", "ceo_command_audit.json",
    "company_identity.json", "PLY_ERP", "execute_task", "git push", "gh api",
    "curl ", "wget ", "pip install", "npm install",
)


class ObserverPolicyError(ValueError):
    """The checked-in company observer violates its read-only policy."""


def _fail(code):
    raise ObserverPolicyError(code)


def _block(text, name, indent=0):
    spaces = " " * indent
    pattern = rf"(?ms)^{spaces}{re.escape(name)}:[ \t]*\n(?P<body>.*?)(?=^{spaces}[A-Za-z0-9_-]+:[ \t]*$|\Z)"
    match = re.search(pattern, text)
    if match is None:
        _fail("OBSERVER_POLICY_BLOCK_MISSING")
    return match.group("body")


def _call_path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_path(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _assignment(tree, name):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return node.value
    return None


def _function(tree, name):
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    _fail("OBSERVER_POLICY_FUNCTION_MISSING")


def _dict_value(node, name):
    if not isinstance(node, ast.Dict):
        return None
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and key.value == name:
            return value
    return None


def _validate_workflow(text):
    if not text or len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES or "\t" in text or not text.endswith("\n"):
        _fail("OBSERVER_POLICY_WORKFLOW_FORMAT_INVALID")
    top = re.findall(r"(?m)^([A-Za-z0-9_-]+):(?:[ \t].*)?$", text)
    if set(top) != {"name", "on", "permissions", "concurrency", "jobs"} or len(top) != 5:
        _fail("OBSERVER_POLICY_TOP_LEVEL_SCHEMA_INVALID")
    if not re.search(r"(?m)^name:\s*Enterprise-HQ Parent Company Observer\s*$", text):
        _fail("OBSERVER_POLICY_NAME_INVALID")
    if any(marker.lower() in text.lower() for marker in FORBIDDEN):
        _fail("OBSERVER_POLICY_FORBIDDEN_CAPABILITY")

    triggers = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*$", _block(text, "on"))
    if triggers != ["push", "workflow_dispatch", "schedule"]:
        _fail("OBSERVER_POLICY_TRIGGER_SET_INVALID")
    push = _block(_block(text, "on"), "push", 2)
    if re.findall(r"(?m)^\s*-\s*([^\s#]+)\s*$", push) != [EXPECTED_BRANCH]:
        _fail("OBSERVER_POLICY_PUSH_BRANCH_INVALID")
    dispatch = _block(_block(text, "on"), "workflow_dispatch", 2)
    if any(line.strip() for line in dispatch.splitlines()):
        _fail("OBSERVER_POLICY_MANUAL_INPUTS_INVALID")
    schedule = _block(_block(text, "on"), "schedule", 2)
    if re.findall(r'(?m)^\s*-\s*cron:\s*"([^"]+)"\s*$', schedule) != ["17,47 * * * *"]:
        _fail("OBSERVER_POLICY_SCHEDULE_INVALID")

    permissions = [line.strip() for line in _block(text, "permissions").splitlines() if line.strip()]
    if permissions != ["contents: read"]:
        _fail("OBSERVER_POLICY_PERMISSIONS_INVALID")
    concurrency = _block(text, "concurrency")
    if "group: enterprise-hq-parent-company-observer" not in concurrency or "cancel-in-progress: false" not in concurrency:
        _fail("OBSERVER_POLICY_CONCURRENCY_INVALID")
    jobs = _block(text, "jobs")
    job_names = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*$", jobs)
    if job_names != ["observe-parent-company"] or "runs-on: ubuntu-latest" not in jobs or "timeout-minutes: 5" not in jobs:
        _fail("OBSERVER_POLICY_JOB_BOUND_INVALID")

    if tuple(re.findall(r"(?m)^[ \t]+uses:\s*([^\s]+)\s*$", text)) != ACTIONS:
        _fail("OBSERVER_POLICY_ACTION_ALLOWLIST_INVALID")
    if text.count("persist-credentials:") != 1 or "persist-credentials: false" not in text:
        _fail("OBSERVER_POLICY_CHECKOUT_CREDENTIALS_INVALID")
    if text.count("env:") != 1 or text.count("timeout-minutes:") != 1:
        _fail("OBSERVER_POLICY_ENV_SCOPE_INVALID")

    secrets = re.findall(r"\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", text)
    if secrets != ["ENTERPRISE_HQ_READ_TOKEN"]:
        _fail("OBSERVER_POLICY_SECRET_ALLOWLIST_INVALID")
    secret = "$" + "{{ secrets.ENTERPRISE_HQ_READ_TOKEN }}"
    expected_step = "\n".join((
        "      - name: Read private HQ metadata and emit aggregate-only report",
        "        env:",
        f"          ENTERPRISE_HQ_READ_TOKEN: {secret}",
        '        run: python scripts/enterprise_hq_company_observer.py --output "$RUNNER_TEMP/enterprise-hq-company-summary.json"',
    ))
    if expected_step not in text:
        _fail("OBSERVER_POLICY_SECRET_SCOPE_INVALID")

    tests = re.findall(
        r"(?m)^[ \t]+run:\s*python -m unittest discover -s tests -p '([^']+)'[ \t]*$",
        text,
    )
    if not tests or len(tests) != len(set(tests)) or any(
        not item.startswith("test_enterprise_hq_") or not item.endswith(".py") for item in tests
    ):
        _fail("OBSERVER_POLICY_TEST_COMMANDS_INVALID")
    if "test_enterprise_hq_public_workflow_boundary.py" not in tests:
        _fail("OBSERVER_POLICY_WORKFLOW_BOUNDARY_TEST_MISSING")
    if "test_enterprise_hq_observer_freshness.py" not in tests:
        _fail("OBSERVER_POLICY_FRESHNESS_TEST_MISSING")
    if "test_enterprise_hq_observer_freshness_ledger.py" not in tests:
        _fail("OBSERVER_POLICY_FRESHNESS_LEDGER_TEST_MISSING")
    if "test_enterprise_hq_observer_freshness_backup.py" not in tests:
        _fail("OBSERVER_POLICY_FRESHNESS_BACKUP_TEST_MISSING")
    if "test_enterprise_hq_observer_freshness_backup_receipts.py" not in tests:
        _fail("OBSERVER_POLICY_FRESHNESS_BACKUP_RECEIPT_TEST_MISSING")
    if "test_enterprise_hq_observer_freshness_backup_availability.py" not in tests:
        _fail("OBSERVER_POLICY_FRESHNESS_BACKUP_AVAILABILITY_TEST_MISSING")
    if "test_enterprise_hq_observer_freshness_backup_availability_ledger.py" not in tests:
        _fail("OBSERVER_POLICY_FRESHNESS_BACKUP_AVAILABILITY_LEDGER_TEST_MISSING")
    if "test_enterprise_hq_backup_availability_reconciliation.py" not in tests:
        _fail("OBSERVER_POLICY_BACKUP_AVAILABILITY_RECONCILIATION_TEST_MISSING")
    if "test_enterprise_hq_backup_artifact_binding.py" not in tests:
        _fail("OBSERVER_POLICY_BACKUP_ARTIFACT_BINDING_TEST_MISSING")
    if "test_enterprise_hq_backup_artifact_binding_ledger.py" not in tests:
        _fail("OBSERVER_POLICY_BACKUP_ARTIFACT_BINDING_LEDGER_TEST_MISSING")
    if "test_enterprise_hq_backup_artifact_binding_service.py" not in tests:
        _fail("OBSERVER_POLICY_BACKUP_ARTIFACT_BINDING_SERVICE_TEST_MISSING")
    if "test_enterprise_hq_backup_artifact_binding_snapshot.py" not in tests:
        _fail("OBSERVER_POLICY_BACKUP_ARTIFACT_BINDING_SNAPSHOT_TEST_MISSING")
    if "test_enterprise_hq_backup_generation_continuity.py" not in tests:
        _fail("OBSERVER_POLICY_BACKUP_GENERATION_CONTINUITY_TEST_MISSING")
    if "test_enterprise_hq_backup_predecessor_availability.py" not in tests:
        _fail("OBSERVER_POLICY_BACKUP_PREDECESSOR_AVAILABILITY_TEST_MISSING")
    run_lines = [
        line.split("run:", 1)[1].strip()
        for line in text.splitlines() if re.match(r"^[ \t]+run:", line)
    ]
    observer_command = (
        'python scripts/enterprise_hq_company_observer.py '
        '--output "$RUNNER_TEMP/enterprise-hq-company-summary.json"'
    )
    artifact_validation_command = (
        'python scripts/enterprise_hq_company_observer_artifact.py '
        '--report "$RUNNER_TEMP/enterprise-hq-company-summary.json"'
    )
    if (
        run_lines.count(observer_command) != 1
        or run_lines.count(artifact_validation_command) != 1
        or len(run_lines) != len(tests) + 2
        or run_lines.index(artifact_validation_command) != run_lines.index(observer_command) + 1
    ):
        _fail("OBSERVER_POLICY_COMMAND_SET_INVALID")

    artifact_step = "\n".join((
        "      - name: Validate aggregate-only observer artifact",
        '        run: python scripts/enterprise_hq_company_observer_artifact.py --report "$RUNNER_TEMP/enterprise-hq-company-summary.json"',
    ))
    upload_step = "      - name: Store aggregate-only report"
    if (
        text.count(artifact_step) != 1
        or text.index(artifact_step) < text.index(expected_step)
        or text.index(artifact_step) > text.index(upload_step)
    ):
        _fail("OBSERVER_POLICY_ARTIFACT_VALIDATION_STEP_INVALID")

    artifact_path = "path: " + "$" + "{{ runner.temp }}/enterprise-hq-company-summary.json"
    if (
        "uses: actions/upload-artifact@v4" not in text
        or artifact_path not in text
        or "retention-days: 1" not in text
        or "if-no-files-found: ignore" not in text
        or "if: success()" not in text
        or "if: always()" in text
        or text.count("retention-days:") != 1
    ):
        _fail("OBSERVER_POLICY_ARTIFACT_INVALID")
    return len(tests)


def _validate_observer(text):
    if not text or len(text.encode("utf-8")) > MAX_OBSERVER_BYTES:
        _fail("OBSERVER_POLICY_OBSERVER_SIZE_INVALID")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        _fail("OBSERVER_POLICY_OBSERVER_SYNTAX_INVALID")

    imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.update(f"{node.module or ''}.{alias.name}" for alias in node.names)
    if imports != IMPORTS:
        _fail("OBSERVER_POLICY_IMPORT_ALLOWLIST_INVALID")

    try:
        repository = ast.literal_eval(_assignment(tree, "HQ_REPOSITORY"))
        files = ast.literal_eval(_assignment(tree, "FILES"))
    except (ValueError, TypeError):
        _fail("OBSERVER_POLICY_PRIVATE_SOURCE_CONSTANT_INVALID")
    if repository != EXPECTED_REPOSITORY or files != {"register": EXPECTED_PRIVATE_PATH}:
        _fail("OBSERVER_POLICY_PRIVATE_SOURCE_ALLOWLIST_INVALID")

    allowed = _assignment(tree, "ALLOWED_PRIVATE_PATHS")
    if not (
        isinstance(allowed, ast.Call) and isinstance(allowed.func, ast.Name)
        and allowed.func.id == "frozenset" and len(allowed.args) == 1
        and isinstance(allowed.args[0], ast.Call)
        and isinstance(allowed.args[0].func, ast.Attribute)
        and isinstance(allowed.args[0].func.value, ast.Name)
        and allowed.args[0].func.value.id == "FILES"
        and allowed.args[0].func.attr == "values"
    ):
        _fail("OBSERVER_POLICY_PRIVATE_PATH_GUARD_INVALID")

    bound = _assignment(tree, "MAX_PRIVATE_RECORD_BYTES")
    if not (
        isinstance(bound, ast.BinOp) and isinstance(bound.op, ast.Mult)
        and isinstance(bound.left, ast.Constant) and type(bound.left.value) is int
        and isinstance(bound.right, ast.Constant) and type(bound.right.value) is int
        and 0 < bound.left.value * bound.right.value <= MAX_PRIVATE_RECORD_BYTES
    ):
        _fail("OBSERVER_POLICY_PRIVATE_RESPONSE_BOUND_INVALID")

    strings = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    if [value for value in strings if value.startswith("state/")] != [EXPECTED_PRIVATE_PATH]:
        _fail("OBSERVER_POLICY_PRIVATE_PATH_REFERENCE_INVALID")
    if any(
        marker in value for value in strings
        for marker in ("ceo_command_audit.json", "company_identity.json", "PLY_ERP")
    ):
        _fail("OBSERVER_POLICY_PRIVATE_CONTENT_REFERENCE_INVALID")

    fetch = _function(tree, "fetch_private_json")
    if not fetch.body or not isinstance(fetch.body[0], ast.If):
        _fail("OBSERVER_POLICY_PRIVATE_PATH_GUARD_MISSING")
    guard = fetch.body[0].test
    if not (
        isinstance(guard, ast.Compare) and isinstance(guard.left, ast.Name)
        and guard.left.id == "path" and len(guard.ops) == 1
        and isinstance(guard.ops[0], ast.NotIn) and len(guard.comparators) == 1
        and isinstance(guard.comparators[0], ast.Name)
        and guard.comparators[0].id == "ALLOWED_PRIVATE_PATHS"
        and any(isinstance(node, ast.Raise) for node in ast.walk(fetch.body[0]))
    ):
        _fail("OBSERVER_POLICY_PRIVATE_PATH_GUARD_MISSING")

    urlopen = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_path(node.func) == "urllib.request.urlopen"
    ]
    guarded_urlopen = [
        node for node in ast.walk(fetch)
        if isinstance(node, ast.Call) and _call_path(node.func) == "urllib.request.urlopen"
    ]
    if len(urlopen) != 1 or len(guarded_urlopen) != 1 or urlopen[0].lineno <= fetch.body[0].lineno:
        _fail("OBSERVER_POLICY_NETWORK_ACCESS_INVALID")

    summarize = _function(tree, "summarize")
    returns = [
        node.value for node in ast.walk(summarize)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
    ]
    if len(returns) != 1:
        _fail("OBSERVER_POLICY_AGGREGATE_OUTPUT_INVALID")
    report = returns[0]
    keys = {key.value for key in report.keys if isinstance(key, ast.Constant)}
    if keys != {
        "schema_version", "scope_status", "project_001_scope", "status",
        "checks", "counts", "capability_status", "privacy_status",
    }:
        _fail("OBSERVER_POLICY_AGGREGATE_OUTPUT_INVALID")

    counts = _dict_value(report, "counts")
    privacy = _dict_value(report, "privacy_status")
    capability = _dict_value(report, "capability_status")
    if not all(isinstance(item, ast.Dict) for item in (counts, privacy, capability)):
        _fail("OBSERVER_POLICY_AGGREGATE_OUTPUT_INVALID")
    if {key.value for key in counts.keys if isinstance(key, ast.Constant)} != {
        "workstreams", "workstreams_by_status"
    }:
        _fail("OBSERVER_POLICY_AGGREGATE_OUTPUT_INVALID")
    count_value = _dict_value(counts, "workstreams")
    if not (
        isinstance(count_value, ast.Call) and _call_path(count_value.func) == "len"
        and len(count_value.args) == 1
        and isinstance(count_value.args[0], ast.Name)
        and count_value.args[0].id == "workstreams"
    ):
        _fail("OBSERVER_POLICY_AGGREGATE_OUTPUT_INVALID")

    privacy_values = {
        key.value: value.value for key, value in zip(privacy.keys, privacy.values)
        if isinstance(key, ast.Constant) and isinstance(value, ast.Constant)
    }
    if privacy_values != {
        "private_file_contents": "NOT_EMITTED",
        "secrets_or_tokens": "NOT_EMITTED",
        "ceo_command_audit": "NOT_FETCHED_BY_PUBLIC_OBSERVER",
        "product_source": "NOT_READ",
    }:
        _fail("OBSERVER_POLICY_PRIVACY_OUTPUT_INVALID")
    capability_values = {
        key.value: value.value for key, value in zip(capability.keys, capability.values)
        if isinstance(key, ast.Constant) and isinstance(value, ast.Constant)
    }
    if capability_values != {
        "company_task_execution": "NOT_IMPLEMENTED",
        "independent_agent_identity": "NOT_AUTHENTICATED",
        "continuous_24x7_uptime": "NOT_PROVEN",
    }:
        _fail("OBSERVER_POLICY_CAPABILITY_CLAIMS_INVALID")
    report_values = {
        key.value: value.value for key, value in zip(report.keys, report.values)
        if isinstance(key, ast.Constant) and isinstance(value, ast.Constant)
    }
    if (
        report_values.get("scope_status") != "PARENT_COMPANY_ONLY"
        or report_values.get("project_001_scope") != "EXCLUDED_BY_COMPANY_WORKER_POLICY"
        or report_values.get("status") != "OBSERVED"
    ):
        _fail("OBSERVER_POLICY_SCOPE_OUTPUT_INVALID")

    main = _function(tree, "main")
    env_calls = [
        node for node in ast.walk(main)
        if isinstance(node, ast.Call) and _call_path(node.func) == "os.environ.get"
    ]
    env_names = [ast.literal_eval(node.args[0]) for node in env_calls if node.args]
    if env_names != ["ENTERPRISE_HQ_READ_TOKEN"]:
        _fail("OBSERVER_POLICY_ENVIRONMENT_ALLOWLIST_INVALID")
    for node in ast.walk(main):
        if isinstance(node, ast.Call) and _call_path(node.func) == "print":
            if any(
                isinstance(child, ast.Name) and child.id == "token"
                for arg in node.args for child in ast.walk(arg)
            ):
                _fail("OBSERVER_POLICY_TOKEN_OUTPUT_FORBIDDEN")

    forbidden_calls = {
        "eval", "exec", "compile", "__import__", "open", "os.system",
        "os.popen", "os.remove", "os.unlink", "subprocess.run",
        "subprocess.Popen", "shutil.rmtree",
    }
    if any(
        isinstance(node, ast.Call) and _call_path(node.func) in forbidden_calls
        for node in ast.walk(tree)
    ):
        _fail("OBSERVER_POLICY_UNSAFE_OPERATION_FORBIDDEN")
    file_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"write_text", "write_bytes", "unlink", "rmdir", "rename", "replace", "chmod"}
    ]
    main_nodes = list(ast.walk(main))
    if (
        len([node for node in file_calls if node.func.attr == "write_text"]) != 1
        or any(node.func.attr != "write_text" or node not in main_nodes for node in file_calls)
    ):
        _fail("OBSERVER_POLICY_FILE_WRITE_SCOPE_INVALID")
    return len(files)


def validate_company_observer_policy(workflow_text, observer_text):
    """Validate the read-only workflow and aggregate-only private observer."""
    if not isinstance(workflow_text, str) or not isinstance(observer_text, str):
        _fail("OBSERVER_POLICY_INPUT_TYPE_INVALID")
    test_count = _validate_workflow(workflow_text)
    path_count = _validate_observer(observer_text)
    return {
        "status": "COMPANY_OBSERVER_POLICY_VALID",
        "workflow_trigger_count": 3,
        "workflow_test_command_count": test_count,
        "private_path_allowlist_count": path_count,
        "private_response_limit_bytes": 512 * 1024,
        "repository_permission": "contents: read",
        "execution_authorized": False,
    }


__all__ = ["ObserverPolicyError", "validate_company_observer_policy"]
