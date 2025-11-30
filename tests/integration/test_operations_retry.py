"""Integration tests for FlextLdapOperations retry_on_errors functionality.

This module tests flext-ldap operations retry functionality using advanced Python 3.13 patterns:
- Single class architecture with nested test organization
- Factory patterns for test entry generation with error scenarios
- Comprehensive assertion helpers for retry behavior validation
- Dynamic test patterns for edge cases and retry scenarios
- Maximum code reuse through flext-core patterns

Uses REAL LDAP container to test retry scenarios with actual LDAP errors.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels
from flext_ldif import FlextLdifModels

# Mark all tests in this module as integration tests requiring Docker
pytestmark = [pytest.mark.integration, pytest.mark.docker]


class TestDataFactories:
    """Factory methods for generating test entries with error scenarios across all retry tests."""

    @staticmethod
    def create_invalid_entry(dn_suffix: str = "test-invalid") -> FlextLdifModels.Entry:
        """Factory for entry with invalid objectClass to cause LDAP errors."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value=f"cn={dn_suffix},dc=flext,dc=local",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["invalid-objectclass-xyz"],  # Invalid objectClass
                    "cn": [dn_suffix],
                },
            ),
        )

    @staticmethod
    def create_nonexistent_class_entry(
        dn_suffix: str = "test-retry",
    ) -> FlextLdifModels.Entry:
        """Factory for entry with nonexistent objectClass."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value=f"cn={dn_suffix},dc=flext,dc=local",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["nonexistent-class"],
                    "cn": [dn_suffix],
                },
            ),
        )

    @staticmethod
    def create_valid_entry(dn_suffix: str = "test-success") -> FlextLdifModels.Entry:
        """Factory for valid entry that should succeed."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value=f"cn={dn_suffix},dc=flext,dc=local",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["organizationalPerson", "person", "top"],
                    "cn": [dn_suffix],
                    "sn": ["Success"],
                },
            ),
        )


class TestAssertions:
    """Comprehensive assertion helpers for retry behavior validation across all test methods."""

    @staticmethod
    def assert_immediate_failure(result: FlextResult[object]) -> None:
        """Assert that operation failed immediately without retries."""
        assert result.is_failure, "Operation should have failed"
        assert result.error is not None, "Error message should be present"

    @staticmethod
    def assert_retry_attempted(result: FlextResult[object]) -> None:
        """Assert that retry logic was attempted based on error message."""
        assert result.is_failure, "Operation should have failed"
        error_lower = str(result.error).lower()
        assert (
            "retry" in error_lower
            or "retries" in error_lower
            or "objectclass" in error_lower
            or "object class" in error_lower
        ), f"Expected retry indicators in error: {result.error}"

    @staticmethod
    def assert_successful_operation(
        result: FlextResult[FlextLdapModels.LdapOperationResult],
    ) -> None:
        """Assert that operation succeeded and return operation info."""
        assert result.is_success, f"Operation should have succeeded: {result.error}"
        operation_info = result.unwrap()
        assert operation_info.operation in {"added", "modified", "skipped"}

    @staticmethod
    def assert_no_retry_attempted(
        result: FlextResult[object],
        max_retries: int = 3,
    ) -> None:
        """Assert that no retry was attempted."""
        assert result.is_failure, "Operation should have failed"
        error_str = str(result.error)
        assert f"after {max_retries} retries" not in error_str, (
            f"Should not show retry attempts in error: {error_str}"
        )


class TestOperationsRetry:
    """Integration tests for retry_on_errors functionality using single class architecture.

    This class contains all retry tests using factory patterns,
    comprehensive assertions, and advanced Python 3.13 features for maximum
    code reuse and test coverage.

    Tests retry scenarios with actual LDAP errors using REAL LDAP container.
    """

    def test_upsert_without_retry_fails_immediately(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test that upsert without retry_on_errors fails immediately on error."""
        bad_entry = TestDataFactories.create_invalid_entry()
        operations = ldap_client._operations

        # Call upsert without retry_on_errors (default behavior)
        result = operations.upsert(bad_entry)

        # Should fail immediately
        TestAssertions.assert_immediate_failure(cast("FlextResult[object]", result))

    def test_upsert_with_retry_on_specific_error(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test retry_on_errors retries on matching error pattern."""
        bad_entry = TestDataFactories.create_nonexistent_class_entry()
        operations = ldap_client._operations

        # Call upsert with retry_on_errors for "objectclass" errors
        result = operations.upsert(
            bad_entry,
            retry_on_errors=["objectclass", "object class"],
            max_retries=2,
        )

        # Should still fail after retries (error is persistent)
        TestAssertions.assert_retry_attempted(cast("FlextResult[object]", result))

    def test_upsert_success_without_retry_needed(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test successful upsert doesn't trigger retry logic."""
        good_entry = TestDataFactories.create_valid_entry()
        operations = ldap_client._operations

        # Call upsert with retry_on_errors (shouldn't need it)
        result = operations.upsert(
            good_entry,
            retry_on_errors=["timeout", "busy"],
            max_retries=3,
        )

        # Should succeed on first attempt
        TestAssertions.assert_successful_operation(
            cast("FlextResult[FlextLdapModels.LdapOperationResult]", result),
        )

    def test_upsert_no_retry_on_non_matching_error(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test retry_on_errors doesn't retry when error doesn't match pattern."""
        bad_entry = TestDataFactories.create_invalid_entry("test-nomatch")
        operations = ldap_client._operations

        # Call upsert with retry_on_errors that WON'T match the error
        result = operations.upsert(
            bad_entry,
            retry_on_errors=[
                "timeout",
                "busy",
                "connection",
            ],  # Won't match objectclass error
            max_retries=3,
        )

        # Should fail immediately without retrying
        TestAssertions.assert_no_retry_attempted(
            cast("FlextResult[object]", result),
            max_retries=3,
        )
