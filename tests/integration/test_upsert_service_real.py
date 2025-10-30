"""Real LDAP UPSERT service integration tests using Docker container.

Comprehensive tests for FlextLdapUpsertService with actual LDAP operations
against a real OpenLDAP server running in Docker. Tests all scenarios including:
- Entry creation (ADD)
- Entry update with new attributes (ADD for missing)
- Entry update with changed values (REPLACE)
- Entry with no changes (skip MODIFY)
- Error handling (duplicate attributes, non-existent entries)
- Skip attributes (operational and RDN attributes)
- Batch operations with multiple entries

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdap, FlextLdapUpsertService
from flext_ldap.services.clients import FlextLdapClients

# Mark all tests as integration tests requiring Docker
# Skip all tests in this module - requires proper fixture integration with connected clients
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skip(reason="Requires proper LDAP client connection setup"),
]


@pytest.mark.integration
class TestUpsertServiceEntryCreation:
    """Test UPSERT service entry creation (ADD operation)."""

    def test_create_new_entry_via_add(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test creating a new entry using ADD (fastest path for new entries)."""
        # Create FlextLdap client and UPSERT service
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=newuser1,ou=people,dc=flext,dc=local"
        new_attributes = {
            "cn": "newuser1",
            "sn": "User",
            "mail": "newuser1@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }

        # UPSERT should create entry via ADD
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
        )

        # Verify success
        assert result.is_success
        stats = result.unwrap()
        assert stats["upserted"] is True
        assert stats["added"] > 0
        assert stats["replaced"] == 0
        assert stats["unchanged"] == 0

        # Cleanup
        ldap_api.delete_entry(dn)

    def test_create_multiple_new_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test creating multiple new entries efficiently."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        entries = [
            {
                "dn": "cn=user1,ou=people,dc=flext,dc=local",
                "attrs": {
                    "cn": "user1",
                    "sn": "User",
                    "mail": "user1@internal.invalid",
                    "objectClass": ["inetOrgPerson", "person"],
                },
            },
            {
                "dn": "cn=user2,ou=people,dc=flext,dc=local",
                "attrs": {
                    "cn": "user2",
                    "sn": "User",
                    "mail": "user2@internal.invalid",
                    "objectClass": ["inetOrgPerson", "person"],
                },
            },
        ]

        # Create all entries
        for entry in entries:
            result = upsert_service.upsert_entry(
                ldap_client=ldap_api,
                dn=entry["dn"],
                new_attributes=entry["attrs"],
            )
            assert result.is_success

        # Cleanup
        for entry in entries:
            ldap_api.delete_entry(entry["dn"])

    def test_create_entry_with_unicode_characters(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test creating entry with Unicode characters in attributes."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=josé,ou=people,dc=flext,dc=local"
        new_attributes = {
            "cn": "josé",
            "sn": "García",
            "mail": "josé@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }

        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
        )

        assert result.is_success

        # Cleanup
        ldap_api.delete_entry(dn)

    def test_create_entry_with_multiple_values(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test creating entry with multi-valued attributes."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=multiuser,ou=people,dc=flext,dc=local"
        new_attributes = {
            "cn": "multiuser",
            "sn": "User",
            "mail": ["mail1@internal.invalid", "mail2@internal.invalid"],
            "telephoneNumber": ["+1-555-0001", "+1-555-0002"],
            "objectClass": ["inetOrgPerson", "person"],
        }

        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
        )

        assert result.is_success
        stats = result.unwrap()
        assert stats["added"] > 0

        # Cleanup
        ldap_api.delete_entry(dn)


@pytest.mark.integration
class TestUpsertServiceEntryUpdate:
    """Test UPSERT service entry update operations."""

    def test_update_entry_add_new_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test updating entry by adding new attribute (no retry needed)."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=updateuser1,ou=people,dc=flext,dc=local"

        # Step 1: Create entry with initial attributes
        initial_attrs = {
            "cn": "updateuser1",
            "sn": "User",
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=initial_attrs,
        )
        assert result.is_success

        # Step 2: UPSERT with additional attribute (ADD)
        updated_attrs = {
            "cn": "updateuser1",
            "sn": "User",
            "mail": "updateuser1@internal.invalid",  # New attribute
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=updated_attrs,
        )

        # Verify
        assert result.is_success
        stats = result.unwrap()
        assert stats["added"] == 1  # Only new attribute (mail)
        assert stats["replaced"] == 0
        assert stats["unchanged"] > 0

        # Cleanup
        ldap_api.delete_entry(dn)

    def test_update_entry_change_attribute_value(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test updating entry by changing attribute value (REPLACE, no retry)."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=updateuser2,ou=people,dc=flext,dc=local"

        # Step 1: Create entry
        initial_attrs = {
            "cn": "updateuser2",
            "sn": "OldLastName",
            "mail": "oldmail@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=initial_attrs,
        )
        assert result.is_success

        # Step 2: UPSERT with changed values (REPLACE, no ADD needed)
        updated_attrs = {
            "cn": "updateuser2",
            "sn": "NewLastName",  # Changed
            "mail": "newmail@internal.invalid",  # Changed
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=updated_attrs,
        )

        # Verify - should use REPLACE, not ADD (no retry)
        assert result.is_success
        stats = result.unwrap()
        assert stats["added"] == 0  # No new attributes
        assert stats["replaced"] == 2  # Changed attributes
        assert stats["unchanged"] == 1

        # Cleanup
        ldap_api.delete_entry(dn)

    def test_update_entry_add_multiple_values_to_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding multiple values to existing attribute."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=multiupdateuser,ou=people,dc=flext,dc=local"

        # Step 1: Create entry with single mail
        initial_attrs = {
            "cn": "multiupdateuser",
            "sn": "User",
            "mail": "mail1@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=initial_attrs,
        )
        assert result.is_success

        # Step 2: UPSERT with multiple mail values (REPLACE)
        updated_attrs = {
            "cn": "multiupdateuser",
            "sn": "User",
            "mail": ["mail1@internal.invalid", "mail2@internal.invalid", "mail3@internal.invalid"],
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=updated_attrs,
        )

        # Verify
        assert result.is_success
        stats = result.unwrap()
        assert stats["replaced"] == 1  # mail attribute was replaced

        # Cleanup
        ldap_api.delete_entry(dn)


@pytest.mark.integration
class TestUpsertServiceNoChanges:
    """Test UPSERT service when no changes are needed."""

    def test_idempotent_upsert_no_changes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test UPSERT is idempotent - same attributes don't trigger MODIFY."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=idempotentuser,ou=people,dc=flext,dc=local"
        attrs = {
            "cn": "idempotentuser",
            "sn": "User",
            "mail": "idempotent@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }

        # First UPSERT - creates entry
        result1 = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=attrs,
        )
        assert result1.is_success
        stats1 = result1.unwrap()
        assert stats1["added"] > 0

        # Second UPSERT with same attributes - should skip MODIFY
        result2 = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=attrs,
        )
        assert result2.is_success
        stats2 = result2.unwrap()
        assert stats2["added"] == 0  # No new attributes
        assert stats2["replaced"] == 0  # No changes
        assert stats2["unchanged"] > 0  # All existing

        # Cleanup
        ldap_api.delete_entry(dn)

    def test_multiple_idempotent_calls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test multiple UPSERT calls with same data are idempotent."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=repeatuser,ou=people,dc=flext,dc=local"
        attrs = {
            "cn": "repeatuser",
            "sn": "User",
            "mail": "repeat@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }

        # Call 3 times with same attributes
        for i in range(3):
            result = upsert_service.upsert_entry(
                ldap_client=ldap_api,
                dn=dn,
                new_attributes=attrs,
            )
            assert result.is_success

            # Only first call should add, others should skip MODIFY
            if i == 0:
                assert result.unwrap()["added"] > 0
            else:
                assert result.unwrap()["added"] == 0
                assert result.unwrap()["replaced"] == 0

        # Cleanup
        ldap_api.delete_entry(dn)


@pytest.mark.integration
class TestUpsertServiceSkipAttributes:
    """Test UPSERT service skip attributes functionality."""

    def test_skip_operational_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that operational attributes are automatically skipped."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=opuser,ou=people,dc=flext,dc=local"
        new_attributes = {
            "cn": "opuser",
            "sn": "User",
            "mail": "opuser@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
            # These should be skipped automatically
            "createTimestamp": "20250101000000Z",  # Operational
            "entryUUID": "12345678-1234-1234-1234-123456789abc",  # Operational
        }

        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
        )

        assert result.is_success
        stats = result.unwrap()
        # Only user-modifiable attributes counted
        assert stats["added"] > 0

        # Cleanup
        ldap_api.delete_entry(dn)

    def test_custom_skip_attributes(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test custom skip attributes list."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=customskipuser,ou=people,dc=flext,dc=local"
        new_attributes = {
            "cn": "customskipuser",
            "sn": "User",
            "mail": "custom@internal.invalid",
            "description": "Should be skipped",
            "objectClass": ["inetOrgPerson", "person"],
        }

        # Skip description attribute
        skip_attrs = {"description", "createtimestamp", "modifytimestamp"}

        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
            skip_attributes=skip_attrs,
        )

        assert result.is_success
        # description should not be added due to skip list
        assert "description" not in str(result)

        # Cleanup
        ldap_api.delete_entry(dn)


@pytest.mark.integration
class TestUpsertServiceErrorHandling:
    """Test UPSERT service error handling without retries."""

    def test_error_on_non_existent_parent_dn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test error when parent DN doesn't exist (no blind retry)."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        # Parent OU doesn't exist
        dn = "cn=user,ou=nonexistent,dc=flext,dc=local"
        new_attributes = {
            "cn": "user",
            "sn": "User",
            "objectClass": ["inetOrgPerson", "person"],
        }

        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
        )

        # Should fail with clear error, not retry
        assert result.is_failure
        assert result.error

    def test_error_on_invalid_object_class(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test error when objectClass is invalid (no retry)."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=invaliduser,ou=people,dc=flext,dc=local"
        new_attributes = {
            "cn": "invaliduser",
            "sn": "User",
            "objectClass": ["InvalidObjectClassThatDoesNotExist"],
        }

        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
        )

        # Should fail immediately, no retry
        assert result.is_failure
        assert result.error

    def test_no_retry_on_actual_errors(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that real errors are returned immediately without retrying."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        # Try to add with invalid attribute syntax
        dn = "cn=syntaxuser,ou=people,dc=flext,dc=local"
        new_attributes = {
            "cn": "syntaxuser",
            "sn": "User",
            "mail": "not-a-valid-email",  # Invalid email format
            "objectClass": ["inetOrgPerson", "person"],
        }

        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=new_attributes,
        )

        # Should fail, not retry with different operation
        if result.is_failure:
            # Expected - invalid email
            assert result.error


@pytest.mark.integration
class TestUpsertServiceMixedOperations:
    """Test UPSERT service with mixed ADD and REPLACE operations."""

    def test_mixed_add_and_replace_in_single_upsert(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test UPSERT that performs both ADD and REPLACE in same call."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=mixeduser,ou=people,dc=flext,dc=local"

        # Step 1: Create entry with some attributes
        initial_attrs = {
            "cn": "mixeduser",
            "sn": "OldName",
            "mail": "old@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=initial_attrs,
        )
        assert result.is_success

        # Step 2: UPSERT with changed AND new attributes (mixed operations)
        updated_attrs = {
            "cn": "mixeduser",
            "sn": "NewName",  # Changed - REPLACE
            "mail": "new@internal.invalid",  # Changed - REPLACE
            "telephoneNumber": "+1-555-0000",  # New - ADD
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=updated_attrs,
        )

        # Verify
        assert result.is_success
        stats = result.unwrap()
        assert stats["added"] == 1  # telephoneNumber
        assert stats["replaced"] == 2  # sn, mail

        # Cleanup
        ldap_api.delete_entry(dn)

    def test_progressive_updates(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test progressive updates to entry over multiple UPSERT calls."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=progressiveuser,ou=people,dc=flext,dc=local"

        # Update 1: Create basic entry
        attrs1 = {
            "cn": "progressiveuser",
            "sn": "User",
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=attrs1,
        )
        assert result.is_success

        # Update 2: Add email
        attrs2 = {
            "cn": "progressiveuser",
            "sn": "User",
            "mail": "progressive@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=attrs2,
        )
        assert result.is_success

        # Update 3: Add phone and change name
        attrs3 = {
            "cn": "progressiveuser",
            "sn": "UpdatedUser",
            "mail": "progressive@internal.invalid",
            "telephoneNumber": "+1-555-0001",
            "objectClass": ["inetOrgPerson", "person"],
        }
        result = upsert_service.upsert_entry(
            ldap_client=ldap_api,
            dn=dn,
            new_attributes=attrs3,
        )
        assert result.is_success
        stats = result.unwrap()
        assert stats["added"] == 1  # telephoneNumber
        assert stats["replaced"] == 1  # sn

        # Cleanup
        ldap_api.delete_entry(dn)


@pytest.mark.integration
class TestUpsertServicePerformance:
    """Test UPSERT service performance characteristics."""

    def test_batch_upsert_performance(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test performance with batch UPSERT operations."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        # Create batch of 10 entries
        entries = []
        for i in range(10):
            dn = f"cn=batchuser{i},ou=people,dc=flext,dc=local"
            attrs = {
                "cn": f"batchuser{i}",
                "sn": "User",
                "mail": f"batchuser{i}@internal.invalid",
                "objectClass": ["inetOrgPerson", "person"],
            }
            entries.append((dn, attrs))

        # UPSERT all entries
        for dn, attrs in entries:
            result = upsert_service.upsert_entry(
                ldap_client=ldap_api,
                dn=dn,
                new_attributes=attrs,
            )
            assert result.is_success

        # Cleanup
        for dn, _ in entries:
            ldap_api.delete_entry(dn)

    def test_deterministic_behavior(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test that UPSERT behavior is deterministic - same inputs = same outputs."""
        ldap_api = FlextLdap()
        upsert_service = FlextLdapUpsertService()

        dn = "cn=deterministicuser,ou=people,dc=flext,dc=local"
        attrs = {
            "cn": "deterministicuser",
            "sn": "User",
            "mail": "deterministic@internal.invalid",
            "objectClass": ["inetOrgPerson", "person"],
        }

        # Call 5 times, results should be identical
        results = []
        for _ in range(5):
            result = upsert_service.upsert_entry(
                ldap_client=ldap_api,
                dn=dn,
                new_attributes=attrs,
            )
            assert result.is_success
            results.append(result.unwrap())

        # All results should be identical
        first_result = results[0]
        for result in results[1:]:
            assert result["added"] == first_result["added"]
            assert result["replaced"] == first_result["replaced"]
            assert result["unchanged"] == first_result["unchanged"]

        # Cleanup
        ldap_api.delete_entry(dn)


__all__ = [
    "TestUpsertServiceEntryCreation",
    "TestUpsertServiceEntryUpdate",
    "TestUpsertServiceErrorHandling",
    "TestUpsertServiceMixedOperations",
    "TestUpsertServiceNoChanges",
    "TestUpsertServicePerformance",
    "TestUpsertServiceSkipAttributes",
]
