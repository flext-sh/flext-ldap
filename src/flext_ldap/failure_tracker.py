"""Failure tracking and retry system for LDAP sync operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
import operator
from datetime import UTC, datetime
from pathlib import Path

from flext_core import FlextCore


class FlextLdapFailureTracker(FlextCore.Service[None]):
    """Track and manage LDAP sync failures with retry support.

    Failures are persisted to JSONL files for durability across restarts.
    Supports retry of failed entries with failure resolution tracking.
    """

    def __init__(self, output_dir: Path) -> None:
        """Initialize failure tracker.

        Args:
            output_dir: Directory for failure logs

        """
        super().__init__()
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._failures_file = self._output_dir / ".sync_failures.jsonl"

    def log_failure(
        self,
        dn: str,
        phase: str,
        operation: str,
        error: str,
        context: dict[str, object] | None = None,
    ) -> FlextCore.Result[None]:
        """Log sync failure to persistent JSONL file.

        Args:
            dn: Distinguished name of failed entry
            phase: Phase name (schema, hierarchy, users, groups, acl)
            operation: Operation type (create, update, delete)
            error: Error message
            context: Optional context information

        Returns:
            FlextCore.Result[None]: Success or failure of logging operation

        """
        try:
            failure_record = {
                "dn": dn,
                "phase": phase,
                "operation": operation,
                "error": error,
                "context": context or {},
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "retry_count": 0,
                "resolved": False,
            }

            with self._failures_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(failure_record) + "\n")

            return FlextCore.Result[None].ok(None)
        except OSError as e:
            return FlextCore.Result[None].fail(f"Failed to log failure: {e}")
        except Exception as e:
            return FlextCore.Result[None].fail(f"Unexpected error logging failure: {e}")

    def get_failures_by_phase(
        self, phase: str
    ) -> FlextCore.Result[list[dict[str, object]]]:
        """Load all unresolved failures for specific phase.

        Args:
            phase: Phase name to filter by

        Returns:
            FlextCore.Result containing list of failure records for phase

        """
        if not self._failures_file.exists():
            return FlextCore.Result[list[dict[str, object]]].ok([])

        try:
            failures = []
            with self._failures_file.open("r", encoding="utf-8") as f:
                for line in f:
                    failure = json.loads(line)
                    if failure["phase"] == phase and not failure.get("resolved", False):
                        failures.append(failure)

            return FlextCore.Result[list[dict[str, object]]].ok(failures)
        except OSError as e:
            return FlextCore.Result[list[dict[str, object]]].fail(
                f"Failed to read failures: {e}"
            )
        except json.JSONDecodeError as e:
            return FlextCore.Result[list[dict[str, object]]].fail(
                f"Invalid JSON in failures file: {e}"
            )
        except Exception as e:
            return FlextCore.Result[list[dict[str, object]]].fail(
                f"Unexpected error reading failures: {e}"
            )

    def get_all_failures(self) -> FlextCore.Result[list[dict[str, object]]]:
        """Load all unresolved failures across all phases.

        Returns:
            FlextCore.Result containing list of all failure records

        """
        if not self._failures_file.exists():
            return FlextCore.Result[list[dict[str, object]]].ok([])

        try:
            failures = []
            with self._failures_file.open("r", encoding="utf-8") as f:
                for line in f:
                    failure = json.loads(line)
                    if not failure.get("resolved", False):
                        failures.append(failure)

            return FlextCore.Result[list[dict[str, object]]].ok(failures)
        except OSError as e:
            return FlextCore.Result[list[dict[str, object]]].fail(
                f"Failed to read failures: {e}"
            )
        except json.JSONDecodeError as e:
            return FlextCore.Result[list[dict[str, object]]].fail(
                f"Invalid JSON in failures file: {e}"
            )
        except Exception as e:
            return FlextCore.Result[list[dict[str, object]]].fail(
                f"Unexpected error reading failures: {e}"
            )

    def mark_resolved(self, dn: str, phase: str) -> FlextCore.Result[None]:
        """Mark failure as resolved (remove from active failures).

        Args:
            dn: Distinguished name of resolved entry
            phase: Phase name

        Returns:
            FlextCore.Result indicating success or failure

        """
        if not self._failures_file.exists():
            return FlextCore.Result[None].fail("No failures file exists")

        # Read all failures
        all_failures: list[dict[str, object]] = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            all_failures = [json.loads(line) for line in f]

        # Mark matching failures as resolved
        found = False
        for failure in all_failures:
            if failure["dn"] == dn and failure["phase"] == phase:
                failure["resolved"] = True
                failure["resolved_at"] = datetime.now(tz=UTC).isoformat()
                found = True

        if not found:
            return FlextCore.Result[None].fail(
                f"No failure found for DN {dn} in phase {phase}"
            )

        # Rewrite file
        with self._failures_file.open("w", encoding="utf-8") as f:
            for failure in all_failures:
                f.write(json.dumps(failure) + "\n")

        return FlextCore.Result[None].ok(None)

    def increment_retry_count(self, dn: str, phase: str) -> FlextCore.Result[None]:
        """Increment retry count for failure.

        Args:
            dn: Distinguished name
            phase: Phase name

        Returns:
            FlextCore.Result indicating success or failure

        """
        if not self._failures_file.exists():
            return FlextCore.Result[None].fail("No failures file exists")

        # Read all failures
        all_failures: list[dict[str, object]] = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            all_failures = [json.loads(line) for line in f]

        # Increment retry count
        found = False
        for failure in all_failures:
            if failure["dn"] == dn and failure["phase"] == phase:
                failure["retry_count"] = int(str(failure.get("retry_count", 0))) + 1
                failure["last_retry"] = datetime.now(tz=UTC).isoformat()
                found = True

        if not found:
            return FlextCore.Result[None].fail(
                f"No failure found for DN {dn} in phase {phase}"
            )

        # Rewrite file
        with self._failures_file.open("w", encoding="utf-8") as f:
            for failure in all_failures:
                f.write(json.dumps(failure) + "\n")

        return FlextCore.Result[None].ok(None)

    def generate_report(self) -> FlextCore.Result[dict[str, object]]:
        """Generate comprehensive failure summary report.

        Returns:
            FlextCore.Result containing report dict

        """
        if not self._failures_file.exists():
            return FlextCore.Result[dict[str, object]].ok({
                "total": 0,
                "by_phase": {},
                "by_operation": {},
                "most_common_errors": [],
            })

        failures = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            for line in f:
                failure = json.loads(line)
                if not failure.get("resolved", False):
                    failures.append(failure)

        # Group by phase
        by_phase: dict[str, list[dict[str, object]]] = {}
        for failure in failures:
            phase = failure["phase"]
            by_phase.setdefault(phase, []).append(failure)

        # Group by operation
        by_operation: dict[str, int] = {}
        for failure in failures:
            operation = failure["operation"]
            by_operation[operation] = by_operation.get(operation, 0) + 1

        # Most common errors
        error_counts: dict[str, int] = {}
        for failure in failures:
            error = failure["error"]
            error_counts[error] = error_counts.get(error, 0) + 1

        most_common_errors = sorted(
            error_counts.items(),
            key=operator.itemgetter(1),
            reverse=True,
        )[:10]  # Top 10

        report = {
            "total": len(failures),
            "by_phase": {
                phase: {
                    "count": len(items),
                    "dns": [f["dn"] for f in items],
                }
                for phase, items in by_phase.items()
            },
            "by_operation": by_operation,
            "most_common_errors": [
                {"error": error, "count": count} for error, count in most_common_errors
            ],
        }

        return FlextCore.Result[dict[str, object]].ok(report)

    def clear_resolved(self) -> FlextCore.Result[int]:
        """Remove resolved failures from log file.

        Returns:
            FlextCore.Result containing count of removed failures

        """
        if not self._failures_file.exists():
            return FlextCore.Result[int].ok(0)

        # Read all failures
        all_failures: list[dict[str, object]] = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            all_failures = [json.loads(line) for line in f]

        # Filter out resolved
        unresolved = [f for f in all_failures if not f.get("resolved", False)]
        removed_count = len(all_failures) - len(unresolved)

        # Rewrite file with only unresolved
        with self._failures_file.open("w", encoding="utf-8") as f:
            for failure in unresolved:
                f.write(json.dumps(failure) + "\n")

        return FlextCore.Result[int].ok(removed_count)

    def execute(self) -> FlextCore.Result[None]:
        """Execute the main service operation (required by FlextCore.Service).

        For FlextLdapFailureTracker, there is no single "main" operation.
        Use specific methods (log_failure, get_all_failures, etc.) directly.

        Returns:
            FlextCore.Result[None]: Success indicator

        """
        return FlextCore.Result[None].ok(None)


__all__ = ["FlextLdapFailureTracker"]
