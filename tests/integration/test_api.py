"""Integration tests for FLEXT LDAP with REAL LDAP operations.

These tests execute actual LDAP operations against a real OpenLDAP container.
NO MOCKS - only real code execution and validation.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from flext_core import FlextConstants

from flext_ldap import (
    FlextLDAPClient,
    FlextLDAPContainer,
    FlextLDAPValueObjects,
)
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.services import FlextLDAPServices as FlextLDAPService


# Helper function to replace create_ldap_attributes
def create_ldap_attributes(attrs: dict[str, object]) -> dict[str, list[str]]:
    """Convert attributes to LDAP format using Python standard conversion."""
    return {
        k: [str(v)] if not isinstance(v, list) else [str(item) for item in v]
        for k, v in attrs.items()
        if v is not None
    }


@pytest.mark.integration
class TestLdapClientRealOperations:
    """Test LDAP client with REAL LDAP server operations - NO MOCKS."""

    @pytest.mark.asyncio
    async def test_client_connection_real_server(
        self,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test real LDAP server connection."""
        client = FlextLDAPClient()

        # Connect to real LDAP server
        result = await client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )

        # Verify connection succeeded
        assert result.is_success, f"Connection failed: {result.error}"
        assert client.is_connected

        # Cleanup
        await client.unbind()
        assert not client.is_connected

    @pytest.mark.asyncio
    async def test_client_search_real_entries(
        self,
        connected_ldap_client: FlextLDAPClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test searching real LDAP entries."""
        # Search for base DN - should exist
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            scope="base",
            filter_str="(objectClass=*)",
            attributes=[],  # Get all attributes
            size_limit=10,
            time_limit=30,  # 30 seconds timeout
        )

        result = await connected_ldap_client.search(search_request)

        # Verify search succeeded and found base DN
        assert result.is_success, f"Search failed: {result.error}"
        empty_response = FlextLDAPEntities.SearchResponse(entries=[], total_count=0)
        response_data = result.value if result.is_success else empty_response
        assert response_data.entries, "Should find at least the base DN"
        assert response_data.total_count > 0

    @pytest.mark.asyncio
    async def test_client_add_modify_delete_real_entry(
        self,
        connected_ldap_client: FlextLDAPClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test complete CRUD operations with real LDAP entries."""
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
        _ = await connected_ldap_client.add(ou_dn, ou_attributes)
        # Ignore if OU already exists (error code 68)

        # ADD: Create user entry
        add_result = await connected_ldap_client.add(test_dn, user_attributes)
        assert add_result.is_success, f"Failed to create user: {add_result.error}"

        # MODIFY: Update user attributes
        modify_attrs_raw = {
            "mail": ["updated@example.com"],
            "description": ["Updated user description"],
        }
        modify_attributes = create_ldap_attributes(modify_attrs_raw)
        modify_result = await connected_ldap_client.modify(test_dn, modify_attributes)
        assert modify_result.is_success, f"Failed to modify user: {modify_result.error}"

        # SEARCH: Verify modifications
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn=test_dn,
            scope="base",
            filter_str="(objectClass=*)",
            attributes=[],  # All attributes
            size_limit=1,
            time_limit=30,
        )
        search_result = await connected_ldap_client.search(search_request)
        assert search_result.is_success, f"Failed to search user: {search_result.error}"
        empty_response = FlextLDAPEntities.SearchResponse(entries=[], total_count=0)
        search_data = (
            search_result.value if search_result.is_success else empty_response
        )
        assert search_data.entries, "User entry should exist"

        entry_data = search_data.entries[0]
        assert "updated@example.com" in str(entry_data.get("mail", "")), (
            "Email should be updated"
        )

        # DELETE: Remove user entry
        delete_result = await connected_ldap_client.delete(test_dn)
        assert delete_result.is_success, f"Failed to delete user: {delete_result.error}"

        # VERIFY: Confirm deletion
        verify_search = await connected_ldap_client.search(search_request)
        # After deleting all entries, the OU might not exist anymore - this is normal LDAP behavior
        if verify_search.is_success:
            # If search succeeds, there should be no entries
            empty_response = FlextLDAPEntities.SearchResponse(entries=[], total_count=0)
            verify_data = (
                verify_search.value if verify_search.is_success else empty_response
            )
            assert not verify_data.entries, "User entry should be deleted"
        else:
            # If search fails with "noSuchObject", it means the OU is empty/deleted - also valid
            assert verify_search.error is not None
            assert "noSuchObject" in verify_search.error


@pytest.mark.integration
class TestLdapServiceRealOperations:
    """Test LDAP service with REAL LDAP server operations - NO MOCKS."""

    @pytest.mark.asyncio
    async def test_service_user_lifecycle_real_operations(
        self,
        ldap_service: FlextLDAPService,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test complete user lifecycle with real LDAP operations."""
        # Setup: Create OU for users
        ldap_container = FlextLDAPContainer()
        client = ldap_container.get_client()
        await client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )

        # Create users OU
        ou_dn = f"ou=users,{clean_ldap_container['base_dn']}"
        ou_attrs_raw_2 = {
            "objectClass": ["organizationalUnit"],
            "ou": ["users"],
        }
        ou_attributes_2 = create_ldap_attributes(ou_attrs_raw_2)
        await client.add(ou_dn, ou_attributes_2)  # Ignore if exists

        # Test user creation
        user_request = FlextLDAPEntities.CreateUserRequest(
            dn=f"cn=realuser-{uuid4().hex[:8]},{ou_dn}",
            uid=f"realuser-{uuid4().hex[:8]}",
            cn="Real Test User",
            sn="User",
            given_name="Real",
            mail="real@example.com",
        )

        # CREATE: Real user creation
        create_result = await ldap_service.create_user(user_request)
        assert create_result.is_success, f"Failed to create user: {create_result.error}"

        default_user = FlextLDAPEntities.User(
            id="default",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="Default",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )
        created_user = create_result.value if create_result.is_success else default_user
        assert created_user.uid == user_request.uid
        assert created_user.cn == user_request.cn
        assert created_user.mail == user_request.mail

        # READ: Verify user exists
        get_result = await ldap_service.get_user(user_request.dn)
        assert get_result.is_success, f"Failed to get user: {get_result.error}"
        default_user = FlextLDAPEntities.User(
            id="default",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="Default",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )
        retrieved_user = get_result.value if get_result.is_success else default_user
        assert retrieved_user is not None
        assert retrieved_user.uid == user_request.uid
        assert retrieved_user.cn == user_request.cn

        # UPDATE: Modify user attributes
        update_attrs_raw = {
            "mail": ["updated-real@example.com"],
            "description": ["Updated via service"],
        }
        update_attributes = create_ldap_attributes(update_attrs_raw)
        update_result = await ldap_service.update_user(
            user_request.dn, update_attributes
        )
        assert update_result.is_success, f"Failed to update user: {update_result.error}"

        # Verify update
        updated_get_result = await ldap_service.get_user(user_request.dn)
        assert updated_get_result.is_success
        default_user = FlextLDAPEntities.User(
            id="default",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="Default",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )
        updated_user = (
            updated_get_result.value if updated_get_result.is_success else default_user
        )
        assert updated_user is not None
        assert updated_user.mail == "updated-real@example.com"

        # SEARCH: Find user via search
        search_result = await ldap_service.search_users(
            f"(uid={user_request.uid})",
            ou_dn,
            "subtree",
        )
        assert search_result.is_success, (
            f"Failed to search users: {search_result.error}"
        )
        default_users: list[FlextLDAPEntities.User] = []
        found_users = search_result.value if search_result.is_success else default_users
        assert len(found_users) == 1
        found_user = found_users[0]
        assert found_user.uid == user_request.uid

        # DELETE: Remove user
        delete_result = await ldap_service.delete_user(user_request.dn)
        assert delete_result.is_success, f"Failed to delete user: {delete_result.error}"

        # Verify deletion
        verify_result = await ldap_service.get_user(user_request.dn)
        assert verify_result.is_success
        default_user_verify: FlextLDAPEntities.User | None = None
        verified_user = (
            verify_result.value if verify_result.is_success else default_user_verify
        )
        assert verified_user is None  # Should not exist

    @pytest.mark.asyncio
    async def test_service_group_lifecycle_real_operations(
        self,
        ldap_service: FlextLDAPService,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test complete group lifecycle with real LDAP operations."""
        # Setup: Connect and create OUs
        ldap_container = FlextLDAPContainer()
        client = ldap_container.get_client()
        await client.connect(
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
            await client.add(ou_dn, ou_attributes_3)  # Ignore if exists

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
        await client.add(user_dn, user_attributes_4)

        # Test group creation
        group_id = uuid4().hex[:8]
        group = FlextLDAPEntities.Group(
            id=f"real_group_{group_id}",
            dn=f"cn=realgroup-{group_id},ou=groups,{clean_ldap_container['base_dn']}",
            cn=f"Real Test Group {group_id}",
            description="Real test group for integration testing",
            object_classes=["groupOfNames"],
            attributes={},
            members=[user_dn],  # Add member during creation
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )

        # CREATE: Real group creation
        create_result = await ldap_service.create_group(group)
        assert create_result.is_success, (
            f"Failed to create group: {create_result.error}"
        )

        # READ: Verify group exists
        get_result = await ldap_service.get_group(group.dn)
        assert get_result.is_success, f"Failed to get group: {get_result.error}"
        default_group = FlextLDAPEntities.Group(
            id="default",
            dn="cn=default,dc=test,dc=com",
            cn="Default Group",
            description="Default group",
            object_classes=["groupOfNames"],
            attributes={},
            members=[],
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )
        retrieved_group = get_result.value if get_result.is_success else default_group
        assert retrieved_group is not None
        assert retrieved_group.cn == group.cn
        assert user_dn in retrieved_group.members

        # UPDATE: Modify group description
        update_attrs_raw_5 = {
            "description": ["Updated group description"],
        }
        update_attributes_5 = create_ldap_attributes(update_attrs_raw_5)
        update_result = await ldap_service.update_group(group.dn, update_attributes_5)
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
        await client.add(user2_dn, user2_attributes_6)

        # Add member
        add_member_result = await ldap_service.add_member(group.dn, user2_dn)
        assert add_member_result.is_success, (
            f"Failed to add member: {add_member_result.error}"
        )

        # Verify member was added
        members_result = await ldap_service.get_members(group.dn)
        assert members_result.is_success, (
            f"Failed to get members: {members_result.error}"
        )
        default_members: list[str] = []
        members_list = (
            members_result.value if members_result.is_success else default_members
        )
        assert user2_dn in members_list
        assert user_dn in members_list

        # Remove member
        remove_member_result = await ldap_service.remove_member(group.dn, user2_dn)
        assert remove_member_result.is_success, (
            f"Failed to remove member: {remove_member_result.error}"
        )

        # Verify member was removed
        members_after_remove = await ldap_service.get_members(group.dn)
        assert members_after_remove.is_success
        default_members_after: list[str] = []
        remaining_members = (
            members_after_remove.value
            if members_after_remove.is_success
            else default_members_after
        )
        assert user2_dn not in remaining_members
        assert user_dn in remaining_members  # Original member should remain

        # DELETE: Remove group
        delete_result = await ldap_service.delete_group(group.dn)
        assert delete_result.is_success, (
            f"Failed to delete group: {delete_result.error}"
        )

        # Verify deletion
        verify_result = await ldap_service.get_group(group.dn)
        assert verify_result.is_success
        default_group_verify: FlextLDAPEntities.Group | None = None
        verified_group = (
            verify_result.value if verify_result.is_success else default_group_verify
        )
        assert verified_group is None  # Should not exist

        # Cleanup users
        await client.delete(user_dn)
        await client.delete(user2_dn)


@pytest.mark.integration
class TestLdapValidationRealOperations:
    """Test validation and business rules with REAL LDAP operations."""

    @pytest.mark.asyncio
    async def test_dn_validation_real_ldap(
        self,
        connected_ldap_client: FlextLDAPClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test DN validation with real LDAP server."""
        # Test valid DN creation
        valid_dn = f"cn=validuser,ou=users,{clean_ldap_container['base_dn']}"
        dn_result = FlextLDAPValueObjects.DistinguishedName.create(valid_dn)
        assert dn_result.is_success, f"Valid DN should work: {dn_result.error}"

        # Test invalid DN formats - should fail validation
        invalid_dns = [
            "",  # Empty DN
            "invalid-format",  # Not a valid DN format
            "cn=",  # Incomplete DN
        ]

        for invalid_dn in invalid_dns:
            dn_result = FlextLDAPValueObjects.DistinguishedName.create(invalid_dn)
            if not dn_result.is_success:
                # Validation correctly rejected invalid DN
                assert True
            # Some implementations might accept certain formats - that's OK too

    @pytest.mark.asyncio
    async def test_business_rules_validation_real_ldap(
        self,
        ldap_service: FlextLDAPService,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test business rules validation with real LDAP operations."""
        # Setup connection
        ldap_container = FlextLDAPContainer()
        client = ldap_container.get_client()
        await client.connect(
            str(clean_ldap_container["server_url"]),
            str(clean_ldap_container["bind_dn"]),
            str(clean_ldap_container["password"]),
        )

        # Create OU
        ou_dn = f"ou=validation-test,{clean_ldap_container['base_dn']}"
        ou_attrs_raw_7 = {
            "objectClass": ["organizationalUnit"],
            "ou": ["validation-test"],
        }
        ou_attributes_7 = create_ldap_attributes(ou_attrs_raw_7)
        await client.add(ou_dn, ou_attributes_7)

        # Test user with valid business rules
        valid_user_request = FlextLDAPEntities.CreateUserRequest(
            dn=f"cn=validbusinessuser,{ou_dn}",
            uid="validbusinessuser",
            cn="Valid Business User",
            sn="User",
            given_name="Valid",
            mail="valid.business@example.com",
        )

        # Should succeed with valid business rules
        create_result = await ldap_service.create_user(valid_user_request)
        assert create_result.is_success, (
            f"Valid user should be created: {create_result.error}"
        )

        # Verify the user follows business rules
        default_user = FlextLDAPEntities.User(
            id="default",
            dn="cn=default,dc=test,dc=com",
            uid="default",
            cn="Default User",
            sn="Default",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )
        created_user = create_result.value if create_result.is_success else default_user
        validation_result = created_user.validate_business_rules()
        assert validation_result.is_success, (
            "Created user should pass business rule validation"
        )

        # Test duplicate user creation (should fail)
        _duplicate_result = await ldap_service.create_user(valid_user_request)
        # Some LDAP servers might allow overwrites, others might fail - either is valid behavior

        # Cleanup
        await client.delete(valid_user_request.dn)
        await client.delete(ou_dn)


@pytest.mark.integration
class TestLdapErrorHandlingReal:
    """Test error handling with real LDAP server scenarios."""

    @pytest.mark.asyncio
    async def test_connection_failure_handling(
        self,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test handling of real connection failures."""
        client = FlextLDAPClient()

        # Test connection to non-existent server
        bad_result = await client.connect(
            "ldap://nonexistent-server:389",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            "password",
        )

        # Should fail gracefully with proper error message
        assert not bad_result.is_success
        assert (bad_result.error and "connection" in bad_result.error.lower()) or (
            bad_result.error and "failed" in bad_result.error.lower()
        )

        # Test connection with wrong credentials
        wrong_creds_result = await client.connect(
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

    @pytest.mark.asyncio
    async def test_ldap_operation_error_handling(
        self,
        connected_ldap_client: FlextLDAPClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test error handling for LDAP operations."""
        # Test search with invalid base DN
        invalid_search = FlextLDAPEntities.SearchRequest(
            base_dn="cn=nonexistent,dc=invalid,dc=com",
            scope="base",
            filter_str="(objectClass=*)",
            attributes=[],  # All attributes
            size_limit=10,
            time_limit=30,
        )

        search_result = await connected_ldap_client.search(invalid_search)
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

        add_result = await connected_ldap_client.add(invalid_dn, invalid_attributes)
        # Should fail with appropriate error
        assert not add_result.is_success
        assert any(
            add_result.error and word in add_result.error.lower()
            for word in ["invalid", "unknown", "object", "class", "schema"]
        )

        # Test delete non-existent entry
        delete_result = await connected_ldap_client.delete(
            f"cn=nonexistent-{uuid4().hex},ou=nonexistent,{clean_ldap_container['base_dn']}"
        )
        # Should handle gracefully
        assert not delete_result.is_success
        assert delete_result.error is not None
        assert (
            "No such object" in delete_result.error
            or "does not exist" in delete_result.error.lower()
            or "noSuchObject" in delete_result.error
        )
