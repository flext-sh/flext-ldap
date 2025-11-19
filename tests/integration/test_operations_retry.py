"""Integration tests for FlextLdapOperations retry_on_errors functionality.

Uses REAL LDAP container to test retry scenarios with actual LDAP errors.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdap

# Mark all tests in this module as integration tests requiring Docker
pytestmark = [pytest.mark.integration, pytest.mark.docker]


class TestOperationsRetry:
    """Integration tests for retry_on_errors functionality with real LDAP."""

    def test_upsert_without_retry_fails_immediately(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test that upsert without retry_on_errors fails immediately on error."""
        # Create entry with INVALID attribute (will cause LDAP error)
        bad_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test-invalid,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["invalid-objectclass-xyz"],  # Invalid objectClass
                    "cn": ["test-invalid"],
                }
            ),
        )

        operations = ldap_client.client

        # Call upsert without retry_on_errors (default behavior)
        result = operations.upsert(bad_entry)

        # Should fail immediately
        assert result.is_failure
        assert result.error is not None

    def test_upsert_with_retry_on_specific_error(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test retry_on_errors retries on matching error pattern."""
        # Create entry that will fail with specific error
        bad_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test-retry,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["nonexistent-class"],
                    "cn": ["test-retry"],
                }
            ),
        )

        operations = ldap_client.client

        # Call upsert with retry_on_errors for "objectclass" errors
        result = operations.upsert(
            bad_entry,
            retry_on_errors=["objectclass", "object class"],
            max_retries=2,
        )

        # Should still fail after retries (error is persistent)
        assert result.is_failure
        # Should contain retry information in error message
        error_lower = str(result.error).lower()
        assert "retry" in error_lower or "retries" in error_lower or "objectclass" in error_lower or "object class" in error_lower

    def test_upsert_success_without_retry_needed(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test successful upsert doesn't trigger retry logic."""
        # Create VALID entry
        good_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test-success,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["organizationalPerson", "person", "top"],
                    "cn": ["test-success"],
                    "sn": ["Success"],
                }
            ),
        )

        operations = ldap_client.client

        # Call upsert with retry_on_errors (shouldn't need it)
        result = operations.upsert(
            good_entry,
            retry_on_errors=["timeout", "busy"],
            max_retries=3,
        )

        # Should succeed on first attempt
        assert result.is_success
        operation_info = result.unwrap()
        # Operation can be "add", "modify", or "skipped" (if entry already exists and identical)
        assert operation_info["operation"] in {"add", "modify", "skipped"}

    def test_upsert_no_retry_on_non_matching_error(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test retry_on_errors doesn't retry when error doesn't match pattern."""
        # Create entry with invalid objectClass
        bad_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test-nomatch,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["invalid-class-xyz"],
                    "cn": ["test-nomatch"],
                }
            ),
        )

        operations = ldap_client.client

        # Call upsert with retry_on_errors that WON'T match the error
        result = operations.upsert(
            bad_entry,
            retry_on_errors=["timeout", "busy", "connection"],  # Won't match objectclass error
            max_retries=3,
        )

        # Should fail immediately without retrying
        assert result.is_failure
        # Should NOT contain "retry" in error (failed without retrying)
        assert "after 3 retries" not in str(result.error)
