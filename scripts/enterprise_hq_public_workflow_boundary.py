"""Read-only inventory of public workflow separation boundaries."""
from __future__ import annotations

import argparse
import json
import re
import stat
from pathlib import Path

from scripts.enterprise_hq_company_observer_policy import (
    ObserverPolicyError,
    validate_company_observer_policy,
)

EXPECTED_OBSERVER_FILE = "enterprise-hq-parent-company-observer.yml"
OBSERVER_SOURCE = Path("scripts/enterprise_hq_company_observer.py")
MAX_WORKFLOW_FILES = 64
MAX_WORKFLOW_BYTES = 64 * 1024
MAX_OBSERVER_BYTES = 32 * 1024

SIGNALS = {
    "private_source": re.compile(
        r"(?i)(?:secrets\.(?:private_pat|private_token)\b|private-source|"
        r"checkout private|private project repository)"
    ),
    "private_governance": re.compile(
        r"(?i)(?:ceo_command_audit\.json|"
        r"enterprise_hq_(?:read|write|audit_append)_token|"
        r"repos/bhagyamehta1-lab/Enterprise-HQ/contents/state/)"
    ),
    "product_execution": re.compile(
        r"(?i)(?:execute_task|repository_dispatch|enterprise_task|"
        r"ply[_ -]?erp|private[_ -]?project[_ -]?verification)"
    ),
    "privileged_capability": re.compile(
        r"(?im)^\s*(?:[\"']?models[\"']?:\s*read(?:\s+#.*)?|"
        r"[\"']?(?:actions|attestations|checks|contents|deployments|discussions|"
        r"id-token|issues|models|packages|pages|pull-requests|repository-projects|"
        r"security-events|statuses|vulnerability-alerts)[\"']?:\s*[\"']?write[\"']?(?:\s+#.*)?|"
        r"[\"']?permissions[\"']?:\s*[\"']?write-all[\"']?(?:\s+#.*)?|"
        r"[\"']?permissions[\"']?:\s*\{[^}]*[\"']?(?:actions|attestations|checks|contents|"
        r"deployments|discussions|id-token|issues|models|packages|pages|"
        r"pull-requests|repository-projects|security-events|statuses|"
        r"vulnerability-alerts)[\"']?\s*:\s*[\"']?write[\"']?[^}]*\}(?:[ \t]+#.*)?)[ \t]*$"
    ),
    "observer_boundary_overlap": re.compile(
        r"(?i)(?:scripts/enterprise_hq_company_observer\.py|"
        r"scripts/enterprise_hq_company_observer_artifact\.py|"
        r"ENTERPRISE_HQ_READ_TOKEN)"
    ),
    "untrusted_event_context": re.compile(
        r"(?im)^\s*(?:pull_request_target|pull_request|issue_comment|workflow_run):\s*$"
    ),
    "manual_or_external_dispatch": re.compile(
        r"(?im)^\s*(?:workflow_dispatch|repository_dispatch):\s*$"
    ),
    "unpinned_action_reference": re.compile(
        r"(?im)^\s*(?:-\s*)?uses:\s*(?!\./)[^\s@]+@(?!(?:[0-9a-f]{40})(?:\s|$))[^\s]+"
    ),
    "network_or_dependency_install": re.compile(
        r"(?i)(?:\bcurl\b|\bwget\b|\bpip\s+install\b|\bnpm\s+install\b|"
        r"\byarn\s+install\b|\bpnpm\s+install\b)"
    ),
}


class WorkflowBoundaryAuditError(ValueError):
    """The public workflow inventory cannot be safely classified."""


def _fail(code: str) -> None:
    raise WorkflowBoundaryAuditError(code)


def _read_regular_file(path: Path, limit: int) -> str:
    try:
        if path.is_symlink():
            _fail("WORKFLOW_BOUNDARY_SYMLINK_REJECTED")
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            _fail("WORKFLOW_BOUNDARY_NON_REGULAR_FILE")
        if metadata.st_size > limit:
            _fail("WORKFLOW_BOUNDARY_FILE_TOO_LARGE")
        raw = path.read_bytes()
    except WorkflowBoundaryAuditError:
        raise
    except OSError:
        _fail("WORKFLOW_BOUNDARY_FILE_READ_FAILED")
    if len(raw) > limit:
        _fail("WORKFLOW_BOUNDARY_FILE_TOO_LARGE")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("WORKFLOW_BOUNDARY_INVALID_UTF8")


def _observer_source(root: Path, supplied: str | None) -> str:
    if supplied is not None:
        if not isinstance(supplied, str) or len(supplied.encode("utf-8")) > MAX_OBSERVER_BYTES:
            _fail("WORKFLOW_BOUNDARY_OBSERVER_SOURCE_INVALID")
        return supplied
    candidate = root.parent.parent / OBSERVER_SOURCE
    return _read_regular_file(candidate, MAX_OBSERVER_BYTES)


def _has_broad_secret_scope(text: str) -> bool:
    """Detect workflow- or job-level secret environments, not step-scoped secrets."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^( {0,4})env:\s*$", line)
        if match is None:
            continue
        indent = len(match.group(1))
        block = []
        for candidate in lines[index + 1:]:
            candidate_indent = len(candidate) - len(candidate.lstrip(" "))
            if candidate.strip() and candidate_indent <= indent:
                break
            block.append(candidate)
        if re.search(r"(?:\$\{\{\s*)?secrets\.", "\n".join(block), re.IGNORECASE):
            return True
    return False


def _step_blocks(text: str):
    """Yield bounded YAML step blocks using indentation, without executing YAML."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^( *)(?:-\s+name:|-\s+uses:)", line)
        if match is None:
            continue
        indent = len(match.group(1))
        end = index + 1
        while end < len(lines):
            if re.match(rf"^ {{{indent}}}-\s+", lines[end]):
                break
            end += 1
        yield "\n".join(lines[index:end])


def _has_unconditional_artifact_upload(text: str) -> bool:
    always = re.compile(
        r"(?im)^\s*if:\s*(?:\$\{\{\s*)?always\(\)(?:\s*\}\})?\s*$"
    )
    upload = re.compile(r"(?im)^\s*uses:\s*actions/upload-artifact@")
    return any(upload.search(block) and always.search(block) for block in _step_blocks(text))


def _yaml_unquoted_content(line: str) -> str:
    """Return YAML line content with comments and quoted scalars masked."""
    visible = []
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is None:
            if char in {"'", '"'}:
                quote = char
                visible.append(" ")
                index += 1
                continue
            if char == "#" and (index == 0 or line[index - 1].isspace()):
                break
            visible.append(char)
            index += 1
            continue

        visible.append(" ")
        if quote == '"' and char == "\\" and index + 1 < len(line):
            visible.append(" ")
            index += 2
            continue
        if quote == "'" and char == "'" and index + 1 < len(line) and line[index + 1] == "'":
            visible.append(" ")
            index += 2
            continue
        if char == quote:
            quote = None
        index += 1
    return "".join(visible)


def _flow_collection_delta(line: str) -> int:
    visible = _yaml_unquoted_content(line)
    return (
        visible.count("{") + visible.count("[")
        - visible.count("}") - visible.count("]")
    )


def _has_permission_yaml_indirection(text: str) -> bool:
    """Conservatively flag anchors/aliases inside top-level or job permissions.

    Permission aliases cannot be resolved safely without a full YAML parser.
    Treating them as review-required avoids silently missing inherited write
    permissions while keeping ordinary quoted text and comments out of scope.
    """
    header = re.compile(r"^( *)(?:permissions|['\"]permissions['\"])\\s*:\\s*(.*)$", re.IGNORECASE)
    anchor_or_alias = re.compile(r"(?<![A-Za-z0-9_])(?:&|\\*)[A-Za-z0-9_-]+(?=$|[\\s,\\]}])")

    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = header.match(line)
        if match is None:
            continue
        indent = len(match.group(1))
        block = [match.group(2)]
        flow_depth = _flow_collection_delta(match.group(2))
        for candidate in lines[index + 1:]:
            if candidate.strip():
                candidate_indent = len(candidate) - len(candidate.lstrip(" "))
                if candidate_indent <= indent and flow_depth <= 0:
                    break
            block.append(candidate)
            flow_depth += _flow_collection_delta(candidate)
        if any(anchor_or_alias.search(_yaml_unquoted_content(item)) for item in block):
            return True
    return False


def _classify(text: str) -> set[str]:
    flags = {name for name, pattern in SIGNALS.items() if pattern.search(text)}
    if _has_permission_yaml_indirection(text):
        flags.add("permission_yaml_indirection")
    if _has_broad_secret_scope(text):
        flags.add("broad_secret_scope")
    if _has_unconditional_artifact_upload(text):
        flags.add("unconditional_artifact_publication")
    return flags


def audit_workflow_directory(
    workflow_directory: str | Path,
    observer_source: str | None = None,
) -> dict:
    """Classify workflow files and validate the single company observer.

    Only direct .yml/.yaml children are read. No workflow is executed and no
    private repository or private metadata is accessed.
    """
    supplied_root = Path(workflow_directory)
    try:
        if supplied_root.is_symlink():
            _fail("WORKFLOW_BOUNDARY_ROOT_SYMLINK_REJECTED")
        root = supplied_root.resolve(strict=True)
        if not root.is_dir():
            _fail("WORKFLOW_BOUNDARY_DIRECTORY_INVALID")
        entries = sorted(
            (
                item for item in root.iterdir()
                if item.suffix.lower() in {".yml", ".yaml"}
            ),
            key=lambda item: item.name,
        )
    except WorkflowBoundaryAuditError:
        raise
    except OSError:
        _fail("WORKFLOW_BOUNDARY_DIRECTORY_INVALID")

    if not entries:
        _fail("WORKFLOW_BOUNDARY_NO_WORKFLOWS")
    if len(entries) > MAX_WORKFLOW_FILES:
        _fail("WORKFLOW_BOUNDARY_FILE_COUNT_EXCEEDED")

    contents = {}
    for entry in entries:
        contents[entry.name] = _read_regular_file(entry, MAX_WORKFLOW_BYTES)

    observer_names = [
        name for name in contents if name == EXPECTED_OBSERVER_FILE
    ]
    if len(observer_names) != 1:
        _fail("WORKFLOW_BOUNDARY_COMPANY_OBSERVER_COUNT_INVALID")

    observer_text = _observer_source(root, observer_source)
    try:
        validate_company_observer_policy(
            contents[EXPECTED_OBSERVER_FILE], observer_text
        )
    except ObserverPolicyError:
        _fail("WORKFLOW_BOUNDARY_COMPANY_OBSERVER_POLICY_INVALID")

    restricted_count = 0
    general_count = 0
    signal_counts = {name: 0 for name in SIGNALS}
    signal_counts.update({
        "broad_secret_scope": 0,
        "unconditional_artifact_publication": 0,
        "permission_yaml_indirection": 0,
    })
    for name, content in contents.items():
        if name == EXPECTED_OBSERVER_FILE:
            continue
        flags = _classify(content)
        if flags:
            restricted_count += 1
            for flag in flags:
                signal_counts[flag] += 1
        else:
            general_count += 1

    return {
        "status": "COMPANY_OBSERVER_ISOLATION_VERIFIED",
        "repository_wide_status": (
            "REVIEW_REQUIRED" if restricted_count else "NO_RESTRICTED_WORKFLOWS_DETECTED"
        ),
        "workflow_count": len(contents),
        "company_observer_count": 1,
        "restricted_legacy_workflow_count": restricted_count,
        "general_ci_workflow_count": general_count,
        "restricted_signal_counts": signal_counts,
        "execution_authorized": False,
        "private_data_read": False,
        "workflow_commands_executed": False,
        "workflow_names_emitted": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflow-dir",
        default=str(Path(__file__).resolve().parents[1] / ".github" / "workflows"),
    )
    args = parser.parse_args(argv)
    try:
        summary = audit_workflow_directory(args.workflow_dir)
    except WorkflowBoundaryAuditError as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
