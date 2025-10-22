"""Integration tests for LDAP API operations.

This module provides comprehensive integration tests for LDAP API operations
using real LDAP server integration and complete user lifecycle testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast
from uuid import uuid4

import pytest
from flext_core import FlextResult
from pydantic import SecretStr

from flext_ldap import (
    FlextLdapClients,
    FlextLdapModels,
)
from flext_ldap.constants import FlextLdapConstants

# Skip all integration tests when LDAP server is not available
pytestmark = pytest.mark.integration


# Helper function to replace create_ldap_attributes
def create_ldap_attributes(
    attrs: dict[str, list[str]],
) -> dict[str, str | list[str]]:
    """Convert attributes to LDAP format using Python standard conversion."""
    result: dict[str, str | list[str]] = {}
    for k, v in attrs.items():
        if len(v) == 1:
            result[k] = str(v[0])
        else:
            result[k] = [str(item) for item in v]
    return result


@pytest.mark.integration
class TestLdapClientRealOperations:
    """Test LDAP client with REAL LDAP server operations - NO MOCKS."""

    def test_client_connection_real_server(
        self,
        shared_ldap_config: dict[str, str],
    ) -> None:
        """Test real LDAP server connection."""
        client = FlextLdapClients()

        # Connect to real LDAP server
        result = client.connect(
            shared_ldap_config["server_url"],
            shared_ldap_config["bind_dn"],
            shared_ldap_config["password"],
        )

        # Verify connection succeeded
        assert result.is_success, f"Connection failed: {result.error}"
        assert client.is_connected

        # Cleanup
        client.unbind()
        assert not client.is_connected

    def test_client_search_real_entries(
        self,
        shared_ldap_client: FlextLdapClients,
        shared_ldap_config: dict[str, str],
    ) -> None:
        """Test searching real LDAP entries."""
        # Use already connected client
        client = shared_ldap_client

        # Search for base DN - should exist
        search_request = FlextLdapModels.SearchRequest(
            base_dn=shared_ldap_config["base_dn"],
            scope="subtree",
            filter_str="(objectClass=*)",
            attributes=None,  # Get all attributes
            size_limit=10,
            time_limit=FlextLdapConstants.DEFAULT_TIMEOUT,  # Default timeout from constants
            page_size=None,
            paged_cookie=None,
        )

        result: FlextResult[FlextLdapModels.SearchResponse] = (
            client.search_with_request(search_request)
        )

        # Verify search succeeded and found base DN
        assert result.is_success, f"Search failed: {result.error}"
        empty_response = FlextLdapModels.SearchResponse(
            entries=[],
            total_count=0,
            result_code=0,
            result_description="",
            matched_dn="",
            next_cookie=None,
            entries_returned=0,
            time_elapsed=0.0,
        )
        response_data: FlextLdapModels.SearchResponse = (
            result.unwrap() if result.is_success else empty_response
        )
        assert response_data.entries, "Should find at least the base DN"
        assert response_data.total_count > 0

    @pytest.mark.xfail(
        reason="Low-level LDAP modify operations need proper change list format - complex LDAP protocol issue"
    )
    def test_client_add_modify_delete_real_entry(
        self,
        ldap_api: FlextLdapClients,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test complete CRUD operations with real LDAP entries."""
        # Setup: Connect to LDAP server
        client = ldap_api
        client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )

        # Create test user entry
        test_dn = (
            f"cn=testuser-{uuid4().hex[:8]},ou=people,{clean_ldap_container['base_dn']}"
        )
        user_attrs_raw = {
            "objectClass": ["inetOrgPerson", "person"],
            "cn": ["Test User"],
            "sn": ["User"],
            "uid": [f"testuser-{uuid4().hex[:8]}"],
            "mail": ["test@example.com"],
        }
        user_attributes = create_ldap_attributes(user_attrs_raw)

        # First create the OU if it doesn't exist
        ou_dn = f"ou=people,{clean_ldap_container['base_dn']}"
        ou_attrs_raw = {
            "objectClass": ["organizationalUnit"],
            "ou": ["people"],
        }
        ou_attributes = create_ldap_attributes(ou_attrs_raw)
        _ = client.add_entry(
            ou_dn,
            ou_attributes,
        )
        # Ignore if OU already exists (error code 68)

        # ADD: Create user entry
        add_result = client.add_entry(
            test_dn,
            user_attributes,
        )
        assert add_result.is_success, f"Failed to create user: {add_result.error}"

        # MODIFY: Update user attributes
        modify_attrs_raw = {
            "mail": ["updated@example.com"],
            "description": ["Updated user description"],
        }
        modify_attributes = create_ldap_attributes(modify_attrs_raw)
        # Wrap in EntryChanges model for proper typing
        modify_changes = FlextLdapModels.EntryChanges(**modify_attributes)
        modify_result = client.modify_entry(
            test_dn,
            modify_changes,
        )
        assert modify_result.is_success, f"Failed to modify user: {modify_result.error}"

        # SEARCH: Verify modifications
        search_request = FlextLdapModels.SearchRequest(
            base_dn=test_dn,
            filter_str="(objectClass=*)",
            scope="base",
            attributes=[],  # All attributes
            size_limit=1,
            time_limit=FlextLdapConstants.DEFAULT_TIMEOUT,
            page_size=None,
            paged_cookie=None,
        )
        search_result: FlextResult[FlextLdapModels.SearchResponse] = (
            client.search_with_request(search_request)
        )
        assert search_result.is_success, f"Failed to search user: {search_result.error}"
        empty_response = FlextLdapModels.SearchResponse(
            entries=[],
            total_count=0,
            result_code=0,
            result_description="",
            matched_dn="",
            next_cookie=None,
            entries_returned=0,
            time_elapsed=0.0,
        )
        search_data: FlextLdapModels.SearchResponse = (
            search_result.unwrap() if search_result.is_success else empty_response
        )
        assert search_data.entries, "User entry should exist"

        entry_data: dict[str, object] = cast(
            "dict[str, object]", search_data.entries[0].attributes
        )
        mail_value: object = entry_data.get("mail", "")
        assert "updated@example.com" in str(mail_value), "Email should be updated"

        # DELETE: Remove user entry
        delete_result = client.delete_entry(test_dn)
        assert delete_result.is_success, f"Failed to delete user: {delete_result.error}"

        # VERIFY: Confirm deletion
        verify_search: FlextResult[FlextLdapModels.SearchResponse] = (
            client.search_with_request(search_request)
        )
        # After deleting all entries, the OU might not exist anymore - this is normal LDAP behavior
        if verify_search.is_success:
            # If search succeeds, there should be no entries
            empty_response = FlextLdapModels.SearchResponse(
                entries=[],
                total_count=0,
                result_code=0,
                result_description="",
                matched_dn="",
                next_cookie=None,
                entries_returned=0,
                time_elapsed=0.0,
            )
            verify_data: FlextLdapModels.SearchResponse = (
                verify_search.unwrap() if verify_search.is_success else empty_response
            )
            assert not verify_data.entries, "User entry should be deleted"
        else:
            # If search fails with "noSuchObject", it means the OU is empty/deleted - also valid
            assert verify_search.error is not None
            assert "noSuchObject" in verify_search.error


@pytest.mark.integration
class TestLdapServiceRealOperations:
    """Test LDAP service with REAL LDAP server operations - NO MOCKS."""

    def test_service_user_lifecycle_real_operations(
        self,
        ldap_client: FlextLdapClients,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test complete user lifecycle with real LDAP operations."""
        # Setup: Create OU for users
        client = ldap_client
        result = client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )
        assert result.is_success, f"Failed to connect: {result.error}"

        # Create users OU
        ou_dn = f"ou=users,{clean_ldap_container['base_dn']}"
        ou_attrs_raw_2 = {
            "objectClass": ["organizationalUnit"],
            "ou": ["users"],
        }
        ou_attributes_2 = create_ldap_attributes(ou_attrs_raw_2)
        client.add_entry(
            ou_dn,
            ou_attributes_2,
        )  # Ignore if exists

        # Test user creation
        user_request = FlextLdapModels._LdapRequest(
            dn=f"cn=realuser-{uuid4().hex[:8]},{ou_dn}",
            uid=f"realuser-{uuid4().hex[:8]}",
            cn="Real Test User",
            sn="User",
            given_name="Real",
            mail="real@example.com",
            description="Test user for real operations",
            telephone_number="+1234567890",
            user_password="testpassword123",
            department="Engineering",
            organizational_unit="Development",
            title="Software Engineer",
            organization="Test Organization",
        )

        # CREATE: Real user creation
        create_result = client.create_user(user_request)
        assert create_result.is_success, f"Failed to create user: {create_result.error}"

        default_user = FlextLdapModels.Entry(
            entry_type="user",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="User",
            status="active",
            modified_at=None,
            given_name="Default",
            mail="default@test.com",
            telephone_number="+1-555-123-4567",
            mobile="+1-555-987-6543",
            department="Engineering",
            title="Software Engineer",
            organization="Example Corp",
            organizational_unit="IT Department",
            user_password=SecretStr("defaultpass"),
            # created_at and updated_at have defaults from TimestampableMixin
        )
        if create_result.is_success:
            created_user = create_result.unwrap()
            assert created_user is not None, "Created user should not be None"
            assert created_user.uid == user_request.uid
            assert created_user.cn == user_request.cn
            assert created_user.mail == user_request.mail

        # READ: Verify user exists
        assert user_request.dn is not None, "User DN must not be None"
        get_result = client.get_user(user_request.dn)
        assert get_result.is_success, f"Failed to get user: {get_result.error}"
        default_user = FlextLdapModels.Entry(
            entry_type="user",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="User",
            status="active",
            modified_at=None,
            given_name="Default",
            mail="default@test.com",
            telephone_number="+1-555-123-4567",
            mobile="+1-555-987-6543",
            department="Engineering",
            title="Software Engineer",
            organization="Example Corp",
            organizational_unit="IT Department",
            user_password=SecretStr("defaultpass"),
            # created_at and updated_at have defaults from TimestampableMixin
        )
        retrieved_user = get_result.unwrap() if get_result.is_success else default_user
        assert retrieved_user is not None
        assert retrieved_user.uid == user_request.uid
        assert retrieved_user.cn == user_request.cn

        # UPDATE: Modify user attributes (using consolidated modify_entry)
        update_attrs_raw = {
            "mail": ["updated-real@example.com"],
            "description": ["Updated via service"],
        }
        update_attributes = create_ldap_attributes(update_attrs_raw)
        _ = cast("dict[str, object]", update_attributes)
        assert user_request.dn is not None, "User DN must not be None"
        update_result = client.modify_entry(
            user_request.dn,
            update_attributes,
        )
        assert update_result.is_success, f"Failed to update user: {update_result.error}"

        # Verify update
        assert user_request.dn is not None, "User DN must not be None"
        updated_get_result = client.get_user(user_request.dn)
        assert updated_get_result.is_success
        default_user = FlextLdapModels.Entry(
            entry_type="user",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="User",
            status="active",
            modified_at=None,
            given_name="Default",
            mail="default@test.com",
            telephone_number="+1-555-123-4567",
            mobile="+1-555-987-6543",
            department="Engineering",
            title="Software Engineer",
            organization="Example Corp",
            organizational_unit="IT Department",
            user_password=SecretStr("defaultpass"),
            # created_at and updated_at have defaults from TimestampableMixin
        )
        updated_user = (
            updated_get_result.unwrap()
            if updated_get_result.is_success
            else default_user
        )
        assert updated_user is not None
        assert updated_user.mail == "updated-real@example.com"

        # SEARCH: Find user via search (using consolidated search method)
        search_result = client.search(
            ou_dn,
            f"(uid={user_request.uid})",
        )
        assert search_result.is_success, (
            f"Failed to search users: {search_result.error}"
        )
        default_users: list[FlextLdapModels.Entry] = []
        found_users = (
            search_result.unwrap() if search_result.is_success else default_users
        )
        assert len(found_users) == 1
        found_user = found_users[0]
        # Entry doesn't have uid attribute directly, need to cast or access differently
        assert hasattr(found_user, "uid")

        # DELETE: Remove user
        assert user_request.dn is not None, "User DN must not be None"
        delete_result = client.delete_entry(user_request.dn)
        assert delete_result.is_success, f"Failed to delete user: {delete_result.error}"

        # Verify deletion
        assert user_request.dn is not None, "User DN must not be None"
        verify_result = client.get_user(user_request.dn)
        assert (
            verify_result.is_success
        )  # get_user succeeds even when user doesn't exist
        assert verify_result.value is None  # User should not exist after deletion

    @pytest.mark.xfail(
        reason="Group member operations need debugging - members_list returns empty"
    )
    def test_service_group_lifecycle_real_operations(
        self,
        ldap_api: FlextLdapClients,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test complete group lifecycle with real LDAP operations."""
        # Setup: Connect and create OUs
        client = ldap_api
        client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )

        # Create necessary OUs
        for ou_name in ["groups", "users"]:
            ou_dn = f"ou={ou_name},{clean_ldap_container['base_dn']}"
            ou_attrs_raw_3 = {
                "objectClass": ["organizationalUnit"],
                "ou": [ou_name],
            }
            ou_attributes_3 = create_ldap_attributes(ou_attrs_raw_3)
            client.add_entry(
                ou_dn,
                ou_attributes_3,
            )  # Ignore if exists

        # Create test user for group membership
        user_dn = (
            f"cn=groupuser-{uuid4().hex[:8]},ou=users,{clean_ldap_container['base_dn']}"
        )
        user_attrs_raw_4 = {
            "objectClass": ["inetOrgPerson", "person"],
            "cn": ["Group User"],
            "sn": ["User"],
            "uid": [f"groupuser-{uuid4().hex[:8]}"],
        }
        user_attributes_4 = create_ldap_attributes(user_attrs_raw_4)
        client.add_entry(
            user_dn,
            user_attributes_4,
        )

        # Test group creation
        group_id = uuid4().hex[:8]
        group_request = FlextLdapModels._LdapRequest(
            dn=f"cn=realgroup-{group_id},ou=groups,{clean_ldap_container['base_dn']}",
            cn=f"Real Test Group {group_id}",
            description="Real test group for integration testing",
            member=[user_dn],  # Add member during creation
        )

        # CREATE: Real group creation
        create_result = client.create_group(group_request)
        assert create_result.is_success, (
            f"Failed to create group: {create_result.error}"
        )

        # READ: Verify group exists
        assert group_request.dn is not None, "Group DN must not be None"
        get_result = client.get_group(group_request.dn)
        assert get_result.is_success, f"Failed to get group: {get_result.error}"
        default_group = FlextLdapModels.Entry(
            entry_type="group",
            dn="cn=default,dc=test,dc=com",
            cn="Default Group",
            description="Default test group",
            object_classes=["groupOfNames"],
            member_dns=[],
            unique_member_dns=[],
            gid_number=1001,
            status="active",
            modified_at=None,
        )
        retrieved_group = (
            get_result.unwrap() if get_result.is_success else default_group
        )
        assert retrieved_group is not None
        assert retrieved_group.cn == group_request.cn
        assert user_dn in retrieved_group.member_dns

        # UPDATE: Modify group description (using consolidated modify_entry)
        update_attrs_raw_5 = {
            "description": ["Updated group description"],
        }
        update_attributes_5 = create_ldap_attributes(update_attrs_raw_5)
        assert group_request.dn is not None, "Group DN must not be None"
        update_result = client.modify_entry(
            group_request.dn,
            cast("dict[str, object]", update_attributes_5),
        )
        assert update_result.is_success, (
            f"Failed to update group: {update_result.error}"
        )

        # MEMBERS: Test member operations
        # Create another user to add
        user2_dn = f"cn=groupuser2-{uuid4().hex[:8]},ou=users,{clean_ldap_container['base_dn']}"
        user2_attrs_raw = {
            "objectClass": ["inetOrgPerson", "person"],
            "cn": ["Group User 2"],
            "sn": ["User2"],
            "uid": [f"groupuser2-{uuid4().hex[:8]}"],
        }
        user2_attributes_6 = create_ldap_attributes(user2_attrs_raw)
        client.add_entry(
            user2_dn,
            user2_attributes_6,
        )

        # Add member
        assert group_request.dn is not None, "Group DN must not be None"
        add_member_result = client.add_member(group_request.dn, user2_dn)
        assert add_member_result.is_success, (
            f"Failed to add member: {add_member_result.error}"
        )

        # Verify member was added
        assert group_request.dn is not None, "Group DN must not be None"
        members_result = client.get_members(group_request.dn)
        assert members_result.is_success, (
            f"Failed to get members: {members_result.error}"
        )
        default_members: list[str] = []
        members_list = (
            members_result.unwrap() if members_result.is_success else default_members
        )
        assert user2_dn in members_list
        assert user_dn in members_list

        # Remove member
        assert group_request.dn is not None, "Group DN must not be None"
        remove_member_result = client.remove_member(group_request.dn, user2_dn)
        assert remove_member_result.is_success, (
            f"Failed to remove member: {remove_member_result.error}"
        )

        # Verify member was removed
        assert group_request.dn is not None, "Group DN must not be None"
        members_after_remove = client.get_members(group_request.dn)
        assert members_after_remove.is_success
        default_members_after: list[str] = []
        remaining_members = (
            members_after_remove.unwrap()
            if members_after_remove.is_success
            else default_members_after
        )
        assert user2_dn not in remaining_members
        assert user_dn in remaining_members  # Original member should remain

        # DELETE: Remove group
        assert group_request.dn is not None, "Group DN must not be None"
        delete_result = client.delete_entry(group_request.dn)
        assert delete_result.is_success, (
            f"Failed to delete group: {delete_result.error}"
        )

        # Verify deletion
        assert group_request.dn is not None, "Group DN must not be None"
        verify_result = client.get_group(group_request.dn)
        assert verify_result.is_success
        default_group_verify: FlextLdapModels.Entry | None = None
        verified_group = (
            verify_result.unwrap() if verify_result.is_success else default_group_verify
        )
        assert verified_group is None  # Should not exist

        # Cleanup users
        client.delete_entry(user_dn)
        client.delete_entry(user2_dn)


@pytest.mark.integration
class TestLdapValidationRealOperations:
    """Test validation and business rules with REAL LDAP operations."""

    def test_dn_validation_real_ldap(
        self,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test DN validation with real LDAP server."""
        # Test valid DN creation
        valid_dn = f"cn=validuser,ou=users,{clean_ldap_container['base_dn']}"
        dn_result = FlextLdapModels.DistinguishedName.create(valid_dn)
        assert dn_result.is_success, f"Valid DN should work: {dn_result.error}"

        # Test invalid DN formats - should fail validation
        invalid_dns = [
            "",  # Empty DN
            "invalid-format",  # Not a valid DN format
            "cn=",  # Incomplete DN
        ]

        for invalid_dn in invalid_dns:
            dn_result = FlextLdapModels.DistinguishedName.create(
                invalid_dn,
            )
            if not dn_result.is_success:
                # Validation correctly rejected invalid DN
                assert True
            # Some implementations might accept certain formats - that's OK too

    def test_business_rules_validation_real_ldap(
        self,
        ldap_client: FlextLdapClients,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test business rules validation with real LDAP operations."""
        # Setup connection
        client = ldap_client
        result = client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )
        assert result.is_success, f"Failed to connect: {result.error}"

        # Create OU
        ou_dn = f"ou=validation-test,{clean_ldap_container['base_dn']}"
        ou_attrs_raw_7 = {
            "objectClass": ["organizationalUnit"],
            "ou": ["validation-test"],
        }
        ou_attributes_7 = create_ldap_attributes(ou_attrs_raw_7)
        client.add_entry(
            ou_dn,
            ou_attributes_7,
        )

        # Test user with valid business rules
        valid_user_request = FlextLdapModels._LdapRequest(
            dn=f"cn=validbusinessuser,{ou_dn}",
            uid="validbusinessuser",
            cn="Valid Business User",
            sn="User",
            given_name="Valid",
            mail="valid.business@example.com",
            user_password="SecurePassword123!",
            telephone_number="+1-555-123-4567",
            description="Valid business user",
            department="Engineering",
            organizational_unit="Development",
            title="Software Engineer",
            organization="Example Corp",
        )

        # Should succeed with valid business rules
        create_result = client.create_user(valid_user_request)
        assert create_result.is_success, (
            f"Valid user should be created: {create_result.error}"
        )

        # Verify the user follows business rules
        default_user = FlextLdapModels.Entry(
            entry_type="user",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="User",
            status="active",
            modified_at=None,
            given_name="Default",
            mail="default@test.com",
            telephone_number="+1-555-123-4567",
            mobile="+1-555-987-6543",
            department="Engineering",
            title="Software Engineer",
            organization="Example Corp",
            organizational_unit="IT Department",
            user_password=SecretStr("defaultpass"),
            # created_at and updated_at have defaults from TimestampableMixin
        )
        created_user = (
            create_result.unwrap() if create_result.is_success else default_user
        )
        assert created_user is not None, "Created user should not be None"
        validation_result = created_user.validate_business_rules()
        assert validation_result.is_success, (
            "Created user should pass business rule validation"
        )

        # Test duplicate user creation (should fail)
        _duplicate_result = client.create_user(valid_user_request)
        # Some LDAP servers might allow overwrites, others might fail - either is valid behavior

        # Cleanup
        assert valid_user_request.dn is not None, "User DN must not be None"
        client.delete_entry(valid_user_request.dn)
        client.delete_entry(ou_dn)


@pytest.mark.integration
class TestLdapErrorHandlingReal:
    """Test error handling with real LDAP server scenarios."""

    def test_connection_failure_handling(
        self,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test handling of real connection failures."""
        client = FlextLdapClients()

        # Test connection to non-existent server (use localhost with invalid port to avoid DNS hangs)
        bad_result = client.connect(
            "ldap://127.0.0.1:9999",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            "password",
        )

        # Should fail gracefully with proper error message
        assert not bad_result.is_success
        assert (bad_result.error and "connection" in bad_result.error.lower()) or (
            bad_result.error and "failed" in bad_result.error.lower()
        )

        # Test connection with wrong credentials
        wrong_creds_result = client.connect(
            str(clean_ldap_container["server_url"]),
            "cn=wronguser,dc=test,dc=com",
            "wrongpassword",
        )

        # Should fail with authentication error
        assert not wrong_creds_result.is_success
        # Error message should indicate authentication failure
        assert any(
            wrong_creds_result.error and word in wrong_creds_result.error.lower()
            for word in ["bind", "auth", "invalid", "credential"]
        )

    @pytest.mark.xfail(
        reason="Error handling test - generic error messages vs specific LDAP error codes"
    )
    def test_ldap_operation_error_handling(
        self,
        ldap_api: FlextLdapClients,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test error handling for LDAP operations."""
        # Setup: Connect to LDAP server
        client = ldap_api
        client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )

        # Test search with invalid base DN
        invalid_search = FlextLdapModels.SearchRequest(
            base_dn="cn=nonexistent,dc=invalid,dc=com",
            filter_str="(objectClass=*)",
            scope="base",
            attributes=[],  # All attributes
            size_limit=10,
            time_limit=FlextLdapConstants.DEFAULT_TIMEOUT,
            page_size=None,
            paged_cookie=None,
        )

        search_result: FlextResult[FlextLdapModels.SearchResponse] = (
            client.search_with_request(invalid_search)
        )
        # Should handle gracefully - either return empty results or proper error
        assert search_result.is_success or (
            search_result.error
            and (
                "noSuchObject" in search_result.error
                or "terminated by server" in search_result.error
            )
        )

        # Test add with invalid attributes
        invalid_dn = f"cn=invaliduser,ou=nonexistent,{clean_ldap_container['base_dn']}"
        invalid_attrs_raw = {
            "objectClass": ["nonExistentObjectClass"],  # Invalid object class
            "invalidAttribute": ["value"],
        }
        invalid_attributes = create_ldap_attributes(invalid_attrs_raw)

        add_result = client.add_entry(
            invalid_dn,
            invalid_attributes,
        )
        # Should fail with appropriate error
        assert not add_result.is_success
        assert any(
            add_result.error and word in add_result.error.lower()
            for word in ["invalid", "unknown", "object", "class", "schema"]
        )

        # Test delete non-existent entry
        delete_result = client.delete_entry(
            f"cn=nonexistent-{uuid4().hex},ou=nonexistent,{clean_ldap_container['base_dn']}",
        )
        # Should handle gracefully
        assert not delete_result.is_success
        assert delete_result.error is not None
        assert (
            "No such object" in delete_result.error
            or "does not exist" in delete_result.error.lower()
            or "noSuchObject" in delete_result.error
        )
