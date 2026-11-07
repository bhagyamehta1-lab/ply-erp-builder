"""Persistent binding of zero-spend resource budgets to internal task proposals.

This extension shares the local TaskLedger SQLite database and audit policy.
It persists proposals only; it never executes tasks or enforces runtime limits.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from scripts.enterprise_hq_resource_budget import validate_resource_budget
from scripts.enterprise_hq_task_contract import ContractError, validate_batch
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
    TaskLedger,
    _canonical_json,
    _utc_now,
    _validate_timestamp,
)

MAX_LEDGER_BUDGETS = 256


class BudgetedTaskLedger(TaskLedger):
    """Task ledger extension that atomically stores task and budget proposals."""

    def _initialize(self) -> None:
        super()._initialize()
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS resource_budgets (
                budget_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
                budget_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status = 'PROPOSED'),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS budget_audit_events (
                sequence INTEGER PRIMARY KEY,
                budget_id TEXT NOT NULL REFERENCES resource_budgets(budget_id),
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                event TEXT NOT NULL CHECK (event = 'BUDGET_BOUND'),
                occurred_at TEXT NOT NULL,
                previous_hash TEXT,
                record_hash TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS budget_audit_events_task_id_idx
                ON budget_audit_events(task_id);
            """
        )

    def _append_budget_event(self, budget_id: str, task_id: str) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM budget_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "budget_id": budget_id,
            "task_id": task_id,
            "event": "BUDGET_BOUND",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        self._connection.execute(
            """INSERT INTO budget_audit_events
               (sequence, budget_id, task_id, event, occurred_at,
                previous_hash, record_hash)
               VALUES (?, ?, ?, 'BUDGET_BOUND', ?, ?, ?)""",
            (sequence, budget_id, task_id, occurred_at, previous_hash, record_hash),
        )

    def propose_many_with_budgets(self, proposals: list[dict]) -> dict:
        """Atomically persist up to eight task/budget pairs for human review."""
        if not isinstance(proposals, list) or not 1 <= len(proposals) <= 8:
            raise ContractError("BUDGET_BATCH_SIZE_INVALID")

        tasks = []
        budgets = []
        for proposal in proposals:
            if not isinstance(proposal, Mapping) or set(proposal) != {"task", "budget"}:
                raise ContractError("BUDGET_PROPOSAL_SCHEMA_INVALID")
            if not isinstance(proposal["task"], Mapping) or not isinstance(proposal["budget"], Mapping):
                raise ContractError("BUDGET_PROPOSAL_SCHEMA_INVALID")
            tasks.append(dict(proposal["task"]))
            budgets.append(dict(proposal["budget"]))

        normalized_tasks = validate_batch(tasks)
        normalized_budgets = [
            validate_resource_budget(task, budget)
            for task, budget in zip(tasks, budgets)
        ]
        budget_ids = [item["budget_id"] for item in normalized_budgets]
        if len(budget_ids) != len(set(budget_ids)):
            raise ContractError("DUPLICATE_BUDGET_ID")

        canonical_tasks = [_canonical_json(task) for task in tasks]
        canonical_budgets = [_canonical_json(budget) for budget in budgets]
        created_tasks = 0
        created_budgets = 0
        budgets_already_present = 0

        with self._transaction():
            # Verify both audit chains before writing either task or budget data.
            self.verify()
            current_task_count = self._connection.execute(
                "SELECT COUNT(*) FROM tasks"
            ).fetchone()[0]
            current_budget_count = self._connection.execute(
                "SELECT COUNT(*) FROM resource_budgets"
            ).fetchone()[0]

            for task, budget, normalized, budget_result, task_json, budget_json in zip(
                tasks,
                budgets,
                normalized_tasks,
                normalized_budgets,
                canonical_tasks,
                canonical_budgets,
            ):
                existing_task = self._connection.execute(
                    "SELECT task_id, idempotency_key, task_json FROM tasks WHERE task_id = ?",
                    (normalized["task_id"],),
                ).fetchone()
                if existing_task is not None:
                    if (
                        existing_task["idempotency_key"] != normalized["idempotency_key"]
                        or existing_task["task_json"] != task_json
                    ):
                        raise TaskConflictError("TASK_ID_CONTENT_CONFLICT")
                else:
                    key_owner = self._connection.execute(
                        "SELECT task_id FROM tasks WHERE idempotency_key = ?",
                        (normalized["idempotency_key"],),
                    ).fetchone()
                    if key_owner is not None:
                        raise TaskConflictError("IDEMPOTENCY_KEY_CONTENT_CONFLICT")
                    if current_task_count >= 256:
                        raise LedgerError("LEDGER_CAPACITY_REACHED")
                    self._connection.execute(
                        """INSERT INTO tasks
                           (task_id, idempotency_key, task_json, status, created_at)
                           VALUES (?, ?, ?, 'PROPOSED', ?)""",
                        (
                            normalized["task_id"],
                            normalized["idempotency_key"],
                            task_json,
                            _utc_now(),
                        ),
                    )
                    self._append_proposal_event(
                        normalized["task_id"], normalized["logical_role"]
                    )
                    current_task_count += 1
                    created_tasks += 1

                existing_budget = self._connection.execute(
                    """SELECT budget_id, budget_json FROM resource_budgets
                       WHERE task_id = ?""",
                    (normalized["task_id"],),
                ).fetchone()
                if existing_budget is not None:
                    if (
                        existing_budget["budget_id"] == budget_result["budget_id"]
                        and existing_budget["budget_json"] == budget_json
                    ):
                        budgets_already_present += 1
                        continue
                    raise TaskConflictError("TASK_BUDGET_CONTENT_CONFLICT")

                budget_owner = self._connection.execute(
                    "SELECT task_id FROM resource_budgets WHERE budget_id = ?",
                    (budget_result["budget_id"],),
                ).fetchone()
                if budget_owner is not None:
                    raise TaskConflictError("BUDGET_ID_CONTENT_CONFLICT")
                if current_budget_count >= MAX_LEDGER_BUDGETS:
                    raise LedgerError("BUDGET_LEDGER_CAPACITY_REACHED")

                self._connection.execute(
                    """INSERT INTO resource_budgets
                       (budget_id, task_id, budget_json, status, created_at)
                       VALUES (?, ?, ?, 'PROPOSED', ?)""",
                    (
                        budget_result["budget_id"],
                        normalized["task_id"],
                        budget_json,
                        _utc_now(),
                    ),
                )
                self._append_budget_event(
                    budget_result["budget_id"], normalized["task_id"]
                )
                current_budget_count += 1
                created_budgets += 1

        return {
            "created_tasks": created_tasks,
            "created_budgets": created_budgets,
            "budgets_already_present": budgets_already_present,
            "task_count": current_task_count,
            "budget_count": current_budget_count,
            "status": "HUMAN_REVIEW_REQUIRED",
            "budget_enforcement_status": "NOT_ENFORCED",
            "execution_performed": False,
            "execution_authorized": False,
        }

    def verify(self) -> dict:
        """Verify task and budget rows plus both complete append-only hash chains."""
        base = super().verify()
        task_rows = self._connection.execute(
            "SELECT task_id, task_json FROM tasks"
        ).fetchall()
        task_json_by_id = {row["task_id"]: row["task_json"] for row in task_rows}

        budget_rows = self._connection.execute(
            """SELECT budget_id, task_id, budget_json, status, created_at
               FROM resource_budgets ORDER BY budget_id"""
        ).fetchall()
        if len(budget_rows) > MAX_LEDGER_BUDGETS:
            raise LedgerCorruptionError("BUDGET_LEDGER_CAPACITY_INVARIANT_FAILED")

        budget_map = {}
        for row in budget_rows:
            stored_task_json = task_json_by_id.get(row["task_id"])
            if stored_task_json is None:
                raise LedgerCorruptionError("BUDGET_TASK_REFERENCE_INVALID")
            try:
                stored_task = json.loads(stored_task_json)
                stored_budget = json.loads(row["budget_json"])
                normalized = validate_resource_budget(stored_task, stored_budget)
            except (ValueError, TypeError, ContractError):
                raise LedgerCorruptionError("STORED_BUDGET_CONTRACT_INVALID") from None
            if (
                _canonical_json(stored_budget) != row["budget_json"]
                or normalized["budget_id"] != row["budget_id"]
                or normalized["task_id"] != row["task_id"]
                or row["status"] != "PROPOSED"
                or not _validate_timestamp(row["created_at"])
            ):
                raise LedgerCorruptionError("STORED_BUDGET_INVARIANT_FAILED")
            budget_map[row["budget_id"]] = row

        events = self._connection.execute(
            """SELECT sequence, budget_id, task_id, event, occurred_at,
                      previous_hash, record_hash
               FROM budget_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(budget_rows):
            raise LedgerCorruptionError("BUDGET_AUDIT_EVENT_COUNT_MISMATCH")

        previous_hash = None
        seen_budgets = set()
        for expected_sequence, row in enumerate(events, start=1):
            proposal = budget_map.get(row["budget_id"])
            if (
                row["sequence"] != expected_sequence
                or proposal is None
                or row["budget_id"] in seen_budgets
                or row["task_id"] != proposal["task_id"]
                or row["event"] != "BUDGET_BOUND"
                or row["previous_hash"] != previous_hash
                or not _validate_timestamp(row["occurred_at"])
            ):
                raise LedgerCorruptionError("BUDGET_AUDIT_CHAIN_STRUCTURE_INVALID")
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "budget_id": row["budget_id"],
                "task_id": row["task_id"],
                "event": row["event"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = hashlib.sha256(
                _canonical_json(body).encode("utf-8")
            ).hexdigest()
            if row["record_hash"] != expected_hash:
                raise LedgerCorruptionError("BUDGET_AUDIT_CHAIN_HASH_INVALID")
            previous_hash = expected_hash
            seen_budgets.add(row["budget_id"])

        return {
            **base,
            "budget_count": len(budget_rows),
            "budget_audit_event_count": len(events),
            "budget_audit_chain": "VALID",
        }

    def recover_after_restart(self) -> dict:
        """Verify persisted budgets after reopen; never enforce or resume execution."""
        verified = self.verify()
        return {
            "recovery_status": "PASS",
            "tasks_recovered": verified["task_count"],
            "pending_human_review": verified["task_count"],
            "budget_proposals_recovered": verified["budget_count"],
            "budget_proposals_pending_human_review": verified["budget_count"],
            "budget_audit_event_count": verified["budget_audit_event_count"],
            "budget_audit_chain": verified["budget_audit_chain"],
            "budget_enforcement_status": "NOT_ENFORCED",
            "execution_resumed": False,
            "automatic_retry": False,
        }
