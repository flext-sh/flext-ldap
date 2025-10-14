"""Tests for failure tracking system.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flext_ldap.failure_tracker import FlextLdapFailureTracker


class TestFailureTrackerInitialization:
    """Test FlextLdapFailureTracker initialization."""

    def test_init_creates_output_directory(self, tmp_path: Path) -> None:
        """Should create output directory if it doesn't exist."""
        output_dir = tmp_path / "test_output"
        assert not output_dir.exists()

        FlextLdapFailureTracker(output_dir)

        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_init_with_existing_directory(self, tmp_path: Path) -> None:
        """Should work with existing directory."""
        output_dir = tmp_path / "existing"
        output_dir.mkdir()

        tracker = FlextLdapFailureTracker(output_dir)

        assert tracker._output_dir == output_dir
        assert tracker._failures_file == output_dir / ".sync_failures.jsonl"


class TestLogFailure:
    """Test logging failures to JSONL file."""

    def test_log_failure_creates_file(self, tmp_path: Path) -> None:
        """Should create failures file on first log."""
        tracker = FlextLdapFailureTracker(tmp_path)
        failures_file = tmp_path / ".sync_failures.jsonl"

        assert not failures_file.exists()

        tracker.log_failure(
            dn="cn=test,dc=client-a",
            phase="users",
            operation="create",
            error="Connection timeout",
        )

        assert failures_file.exists()

    def test_log_failure_writes_correct_format(self, tmp_path: Path) -> None:
        """Should write failure in correct JSONL format."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure(
            dn="cn=test,dc=client-a",
            phase="users",
            operation="create",
            error="Connection timeout",
            context={"retry_count": 0},
        )

        failures_file = tmp_path / ".sync_failures.jsonl"
        with failures_file.open("r", encoding="utf-8") as f:
            line = f.readline()
            failure = json.loads(line)

            assert failure["dn"] == "cn=test,dc=client-a"
            assert failure["phase"] == "users"
            assert failure["operation"] == "create"
            assert failure["error"] == "Connection timeout"
            assert failure["context"] == {"retry_count": 0}
            assert failure["retry_count"] == 0
            assert failure["resolved"] is False
            assert "timestamp" in failure

    def test_log_failure_without_context(self, tmp_path: Path) -> None:
        """Should handle missing context parameter."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure(
            dn="cn=test,dc=client-a",
            phase="users",
            operation="create",
            error="Error message",
        )

        failures_file = tmp_path / ".sync_failures.jsonl"
        with failures_file.open("r", encoding="utf-8") as f:
            failure = json.loads(f.readline())
            assert failure["context"] == {}

    def test_log_multiple_failures(self, tmp_path: Path) -> None:
        """Should append multiple failures to file."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=user1,dc=client-a", "users", "create", "Error 1")
        tracker.log_failure("cn=user2,dc=client-a", "users", "update", "Error 2")
        tracker.log_failure("cn=group1,dc=client-a", "groups", "create", "Error 3")

        failures_file = tmp_path / ".sync_failures.jsonl"
        with failures_file.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) == 3


class TestGetFailuresByPhase:
    """Test filtering failures by phase."""

    def test_get_failures_empty_file(self, tmp_path: Path) -> None:
        """Should return empty list when no failures file exists."""
        tracker = FlextLdapFailureTracker(tmp_path)

        failures = tracker.get_failures_by_phase("users").unwrap()

        assert failures == []

    def test_get_failures_by_phase_filters_correctly(self, tmp_path: Path) -> None:
        """Should return only failures for specified phase."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=user1,dc=client-a", "users", "create", "Error 1")
        tracker.log_failure("cn=group1,dc=client-a", "groups", "create", "Error 2")
        tracker.log_failure("cn=user2,dc=client-a", "users", "create", "Error 3")

        users_failures = tracker.get_failures_by_phase("users").unwrap()
        groups_failures = tracker.get_failures_by_phase("groups").unwrap()

        assert len(users_failures) == 2
        assert len(groups_failures) == 1
        assert all(f["phase"] == "users" for f in users_failures)
        assert all(f["phase"] == "groups" for f in groups_failures)

    def test_get_failures_excludes_resolved(self, tmp_path: Path) -> None:
        """Should not return resolved failures."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=test2,dc=client-a", "users", "create", "Error")

        # Mark one as resolved
        tracker.mark_resolved("cn=test1,dc=client-a", "users")

        failures = tracker.get_failures_by_phase("users").unwrap()

        assert len(failures) == 1
        assert failures[0]["dn"] == "cn=test2,dc=client-a"


class TestGetAllFailures:
    """Test getting all unresolved failures."""

    def test_get_all_failures_empty(self, tmp_path: Path) -> None:
        """Should return empty list when no failures exist."""
        tracker = FlextLdapFailureTracker(tmp_path)

        failures = tracker.get_all_failures().unwrap()

        assert failures == []

    def test_get_all_failures_returns_all_phases(self, tmp_path: Path) -> None:
        """Should return failures from all phases."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=user1,dc=client-a", "users", "create", "Error 1")
        tracker.log_failure("cn=group1,dc=client-a", "groups", "create", "Error 2")
        tracker.log_failure("cn=acl1,dc=client-a", "acl", "create", "Error 3")

        failures = tracker.get_all_failures().unwrap()

        assert len(failures) == 3
        phases = {f["phase"] for f in failures}
        assert phases == {"users", "groups", "acl"}

    def test_get_all_failures_excludes_resolved(self, tmp_path: Path) -> None:
        """Should not return resolved failures."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=test2,dc=client-a", "groups", "create", "Error")

        tracker.mark_resolved("cn=test1,dc=client-a", "users")

        failures = tracker.get_all_failures().unwrap()

        assert len(failures) == 1
        assert failures[0]["dn"] == "cn=test2,dc=client-a"


class TestMarkResolved:
    """Test marking failures as resolved."""

    def test_mark_resolved_success(self, tmp_path: Path) -> None:
        """Should mark failure as resolved successfully."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test,dc=client-a", "users", "create", "Error")

        result = tracker.mark_resolved("cn=test,dc=client-a", "users")

        assert result.is_success

    def test_mark_resolved_adds_timestamp(self, tmp_path: Path) -> None:
        """Should add resolved_at timestamp."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test,dc=client-a", "users", "create", "Error")
        tracker.mark_resolved("cn=test,dc=client-a", "users")

        failures_file = tmp_path / ".sync_failures.jsonl"
        with failures_file.open("r", encoding="utf-8") as f:
            failure = json.loads(f.readline())
            assert failure["resolved"] is True
            assert "resolved_at" in failure

    def test_mark_resolved_not_in_active_failures(self, tmp_path: Path) -> None:
        """Should remove from active failures list."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test,dc=client-a", "users", "create", "Error")
        tracker.mark_resolved("cn=test,dc=client-a", "users")

        failures = tracker.get_failures_by_phase("users").unwrap()

        assert len(failures) == 0

    def test_mark_resolved_no_file_fails(self, tmp_path: Path) -> None:
        """Should fail when no failures file exists."""
        tracker = FlextLdapFailureTracker(tmp_path)

        result = tracker.mark_resolved("cn=test,dc=client-a", "users")

        assert result.is_failure
        assert "No failures file exists" in (result.error or "")

    def test_mark_resolved_not_found_fails(self, tmp_path: Path) -> None:
        """Should fail when failure not found."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")

        result = tracker.mark_resolved("cn=test2,dc=client-a", "users")

        assert result.is_failure
        assert "No failure found" in (result.error or "")


class TestIncrementRetryCount:
    """Test incrementing retry count."""

    def test_increment_retry_count_success(self, tmp_path: Path) -> None:
        """Should increment retry count successfully."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test,dc=client-a", "users", "create", "Error")

        result = tracker.increment_retry_count("cn=test,dc=client-a", "users")

        assert result.is_success

    def test_increment_retry_count_updates_value(self, tmp_path: Path) -> None:
        """Should increment retry_count field."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test,dc=client-a", "users", "create", "Error")
        tracker.increment_retry_count("cn=test,dc=client-a", "users")

        failures = tracker.get_failures_by_phase("users").unwrap()
        assert failures[0]["retry_count"] == 1

    def test_increment_retry_count_multiple_times(self, tmp_path: Path) -> None:
        """Should increment multiple times."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test,dc=client-a", "users", "create", "Error")
        tracker.increment_retry_count("cn=test,dc=client-a", "users")
        tracker.increment_retry_count("cn=test,dc=client-a", "users")
        tracker.increment_retry_count("cn=test,dc=client-a", "users")

        failures = tracker.get_failures_by_phase("users").unwrap()
        assert failures[0]["retry_count"] == 3

    def test_increment_retry_count_adds_timestamp(self, tmp_path: Path) -> None:
        """Should add last_retry timestamp."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test,dc=client-a", "users", "create", "Error")
        tracker.increment_retry_count("cn=test,dc=client-a", "users")

        failures = tracker.get_failures_by_phase("users").unwrap()
        assert "last_retry" in failures[0]

    def test_increment_retry_count_no_file_fails(self, tmp_path: Path) -> None:
        """Should fail when no failures file exists."""
        tracker = FlextLdapFailureTracker(tmp_path)

        result = tracker.increment_retry_count("cn=test,dc=client-a", "users")

        assert result.is_failure
        assert "No failures file exists" in (result.error or "")

    def test_increment_retry_count_not_found_fails(self, tmp_path: Path) -> None:
        """Should fail when failure not found."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")

        result = tracker.increment_retry_count("cn=test2,dc=client-a", "users")

        assert result.is_failure
        assert "No failure found" in (result.error or "")


class TestGenerateReport:
    """Test failure report generation."""

    def test_generate_report_empty(self, tmp_path: Path) -> None:
        """Should generate empty report when no failures."""
        tracker = FlextLdapFailureTracker(tmp_path)

        report_result = tracker.generate_report()

        assert report_result.is_success
        report = report_result.unwrap()
        assert report["total"] == 0
        assert report["by_phase"] == {}
        assert report["by_operation"] == {}
        assert report["most_common_errors"] == []

    def test_generate_report_with_failures(self, tmp_path: Path) -> None:
        """Should generate comprehensive report."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=user1,dc=client-a", "users", "create", "Error A")
        tracker.log_failure("cn=user2,dc=client-a", "users", "update", "Error A")
        tracker.log_failure("cn=group1,dc=client-a", "groups", "create", "Error B")

        report_result = tracker.generate_report()

        assert report_result.is_success
        report = report_result.unwrap()
        assert report["total"] == 3

    def test_generate_report_by_phase(self, tmp_path: Path) -> None:
        """Should group failures by phase."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=user1,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=user2,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=group1,dc=client-a", "groups", "create", "Error")

        report_result = tracker.generate_report()
        report = report_result.unwrap()

        assert report["by_phase"]["users"]["count"] == 2
        assert report["by_phase"]["groups"]["count"] == 1
        assert len(report["by_phase"]["users"]["dns"]) == 2

    def test_generate_report_by_operation(self, tmp_path: Path) -> None:
        """Should group failures by operation."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=test2,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=test3,dc=client-a", "users", "update", "Error")

        report_result = tracker.generate_report()
        report = report_result.unwrap()

        assert report["by_operation"]["create"] == 2
        assert report["by_operation"]["update"] == 1

    def test_generate_report_most_common_errors(self, tmp_path: Path) -> None:
        """Should identify most common errors."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error A")
        tracker.log_failure("cn=test2,dc=client-a", "users", "create", "Error A")
        tracker.log_failure("cn=test3,dc=client-a", "users", "create", "Error B")

        report_result = tracker.generate_report()
        report = report_result.unwrap()

        assert len(report["most_common_errors"]) == 2
        assert report["most_common_errors"][0]["error"] == "Error A"
        assert report["most_common_errors"][0]["count"] == 2
        assert report["most_common_errors"][1]["error"] == "Error B"
        assert report["most_common_errors"][1]["count"] == 1

    def test_generate_report_excludes_resolved(self, tmp_path: Path) -> None:
        """Should not count resolved failures."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=test2,dc=client-a", "users", "create", "Error")
        tracker.mark_resolved("cn=test1,dc=client-a", "users")

        report_result = tracker.generate_report()
        report = report_result.unwrap()

        assert report["total"] == 1


class TestClearResolved:
    """Test removing resolved failures from log."""

    def test_clear_resolved_no_file(self, tmp_path: Path) -> None:
        """Should return 0 when no failures file exists."""
        tracker = FlextLdapFailureTracker(tmp_path)

        result = tracker.clear_resolved()

        assert result.is_success
        assert result.unwrap() == 0

    def test_clear_resolved_removes_resolved(self, tmp_path: Path) -> None:
        """Should remove resolved failures from file."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=test2,dc=client-a", "users", "create", "Error")
        tracker.mark_resolved("cn=test1,dc=client-a", "users")

        result = tracker.clear_resolved()

        assert result.is_success
        assert result.unwrap() == 1

        # Verify only unresolved remains
        failures_file = tmp_path / ".sync_failures.jsonl"
        with failures_file.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) == 1
            failure = json.loads(lines[0])
            assert failure["dn"] == "cn=test2,dc=client-a"

    def test_clear_resolved_preserves_unresolved(self, tmp_path: Path) -> None:
        """Should keep unresolved failures in file."""
        tracker = FlextLdapFailureTracker(tmp_path)

        tracker.log_failure("cn=test1,dc=client-a", "users", "create", "Error")
        tracker.log_failure("cn=test2,dc=client-a", "users", "create", "Error")

        result = tracker.clear_resolved()

        assert result.is_success
        assert result.unwrap() == 0

        failures = tracker.get_all_failures().unwrap()
        assert len(failures) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
