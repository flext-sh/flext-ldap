"""Failure tracking and retry system for LDAP sync operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
import operator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from flext_core import FlextResult, FlextService

from flext_ldap.typings import LdapConfigDict


class FlextLdapFailureTracker(FlextService[None]):
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
        context: LdapConfigDict | None = None,
    ) -> FlextResult[None]:
        """Log sync failure to persistent JSONL file.

        Args:
        dn: Distinguished name of failed entry
        phase: Phase name (schema, hierarchy, users, groups, acl)
        operation: Operation type (create, update, delete)
        error: Error message
        context: Optional context information

        Returns:
        FlextResult[None]: Success or failure of logging operation

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

            return FlextResult[None].ok(None)
        except OSError as e:
            return FlextResult[None].fail(f"Failed to log failure: {e}")
        except Exception as e:
            return FlextResult[None].fail(f"Unexpected error logging failure: {e}")

    def get_failures_by_phase(self, phase: str) -> FlextResult[list[dict[str, object]]]:
        """Load all unresolved failures for specific phase.

        Args:
        phase: Phase name to filter by

        Returns:
        FlextResult containing list of failure records for phase

        """
        if not self._failures_file.exists():
            return FlextResult[list[dict[str, object]]].ok([])

        try:
            failures: list[dict[str, object]] = []
            with self._failures_file.open("r", encoding="utf-8") as f:
                for line in f:
                    failure = cast("dict[str, object]", json.loads(line))
                    if failure.get("phase") == phase and not failure.get(
                        "resolved", False
                    ):
                        failures.append(failure)

            return FlextResult[list[dict[str, object]]].ok(failures)
        except OSError as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Failed to read failures: {e}"
            )
        except json.JSONDecodeError as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Invalid JSON in failures file: {e}"
            )
        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Unexpected error reading failures: {e}"
            )

    def get_all_failures(
        self,
    ) -> FlextResult[list[dict[str, object]]]:
        """Load all unresolved failures across all phases.

        Returns:
        FlextResult containing list of all failure records

        """
        if not self._failures_file.exists():
            return FlextResult[list[dict[str, object]]].ok([])

        try:
            failures: list[dict[str, object]] = []
            with self._failures_file.open("r", encoding="utf-8") as f:
                for line in f:
                    failure = cast("dict[str, object]", json.loads(line))
                    if not failure.get("resolved", False):
                        failures.append(failure)

            return FlextResult[list[dict[str, object]]].ok(failures)
        except OSError as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Failed to read failures: {e}"
            )
        except json.JSONDecodeError as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Invalid JSON in failures file: {e}"
            )
        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Unexpected error reading failures: {e}"
            )

    def mark_resolved(self, dn: str, phase: str) -> FlextResult[None]:
        """Mark failure as resolved (remove from active failures).

        Args:
        dn: Distinguished name of resolved entry
        phase: Phase name

        Returns:
        FlextResult indicating success or failure

        """
        if not self._failures_file.exists():
            return FlextResult[None].fail("No failures file exists")

        # Read all failures
        all_failures: list[dict[str, object]] = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            all_failures = [cast("dict[str, object]", json.loads(line)) for line in f]

        # Mark matching failures as resolved
        found = False
        for failure in all_failures:
            if failure.get("dn") == dn and failure.get("phase") == phase:
                failure["resolved"] = True
                failure["resolved_at"] = datetime.now(tz=UTC).isoformat()
                found = True

        if not found:
            return FlextResult[None].fail(
                f"No failure found for DN {dn} in phase {phase}"
            )

        # Rewrite file
        with self._failures_file.open("w", encoding="utf-8") as f:
            for failure in all_failures:
                f.write(json.dumps(failure) + "\n")

        return FlextResult[None].ok(None)

    def increment_retry_count(self, dn: str, phase: str) -> FlextResult[None]:
        """Increment retry count for failure.

        Args:
        dn: Distinguished name
        phase: Phase name

        Returns:
        FlextResult indicating success or failure

        """
        if not self._failures_file.exists():
            return FlextResult[None].fail("No failures file exists")

        # Read all failures
        all_failures: list[dict[str, object]] = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            all_failures = [cast("dict[str, object]", json.loads(line)) for line in f]

        # Increment retry count
        found = False
        for failure in all_failures:
            if failure.get("dn") == dn and failure.get("phase") == phase:
                failure["retry_count"] = int(str(failure.get("retry_count", 0))) + 1
                failure["last_retry"] = datetime.now(tz=UTC).isoformat()
                found = True

        if not found:
            return FlextResult[None].fail(
                f"No failure found for DN {dn} in phase {phase}"
            )

        # Rewrite file
        with self._failures_file.open("w", encoding="utf-8") as f:
            for failure in all_failures:
                f.write(json.dumps(failure) + "\n")

        return FlextResult[None].ok(None)

    def generate_report(self) -> FlextResult[dict[str, object]]:
        """Generate failure summary report.

        Returns:
        FlextResult containing report dict

        """
        if not self._failures_file.exists():
            return FlextResult[dict[str, object]].ok(
                cast(
                    "dict[str, object]",
                    {
                        "total": 0,
                        "by_phase": {},
                        "by_operation": {},
                        "most_common_errors": [],
                    },
                )
            )

        failures: list[dict[str, object]] = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            for line in f:
                failure = cast("dict[str, object]", json.loads(line))
                if not failure.get("resolved", False):
                    failures.append(failure)

        # Group by phase
        by_phase: dict[str, list[dict[str, object]]] = {}
        for failure in failures:
            phase = failure.get("phase")
            if isinstance(phase, str):
                by_phase.setdefault(phase, []).append(failure)

        # Group by operation
        by_operation: dict[str, int] = {}
        for failure in failures:
            operation = failure.get("operation")
            if isinstance(operation, str):
                by_operation[operation] = by_operation.get(operation, 0) + 1

        # Most common errors
        error_counts: dict[str, int] = {}
        for failure in failures:
            error = failure.get("error")
            if isinstance(error, str):
                error_counts[error] = error_counts.get(error, 0) + 1

        most_common_errors = sorted(
            error_counts.items(),
            key=operator.itemgetter(1),
            reverse=True,
        )[:10]  # Top 10

        report: dict[str, object] = cast(
            "dict[str, object]",
            {
                "total": len(failures),
                "by_phase": {
                    phase: {
                        "count": len(items),
                        "dns": [f.get("dn") for f in items if f.get("dn") is not None],
                    }
                    for phase, items in by_phase.items()
                },
                "by_operation": by_operation,
                "most_common_errors": [
                    {"error": error, "count": count}
                    for error, count in most_common_errors
                ],
            },
        )

        return FlextResult[dict[str, object]].ok(report)

    def clear_resolved(self) -> FlextResult[int]:
        """Remove resolved failures from log file.

        Returns:
        FlextResult containing count of removed failures

        """
        if not self._failures_file.exists():
            return FlextResult[int].ok(0)

        # Read all failures
        all_failures: list[dict[str, object]] = []
        with self._failures_file.open("r", encoding="utf-8") as f:
            all_failures = [cast("dict[str, object]", json.loads(line)) for line in f]

        # Filter out resolved
        unresolved = [f for f in all_failures if not f.get("resolved", False)]
        removed_count = len(all_failures) - len(unresolved)

        # Rewrite file with only unresolved
        with self._failures_file.open("w", encoding="utf-8") as f:
            for failure in unresolved:
                f.write(json.dumps(failure) + "\n")

        return FlextResult[int].ok(removed_count)

    def execute(self) -> FlextResult[None]:
        """Execute the main service operation (required by FlextService).

        For FlextLdapFailureTracker, there is no single "main" operation.
        Use specific methods (log_failure, get_all_failures, etc.) directly.

        Returns:
            FlextResult[None]: Success indicator

        """
        return FlextResult[None].ok(None)


__all__ = ["FlextLdapFailureTracker"]
