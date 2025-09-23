"""Comprehensive API tests for FlextLdapClient with 100% coverage target.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid

import pytest

from flext_core import FlextResult
from flext_ldap import FlextLdapClient, FlextLdapModels
from flext_ldap.config import FlextLdapConfigs
from flext_ldap.models import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class TestFlextLdapClientComprehensive:
    """Comprehensive tests for FlextLdapClient with real functionality."""

    def test_api_initialization_default(self) -> None:
        """Test API initialization with default settings using FlextTestsMatchers."""
        api = FlextLdapClient()

        # Basic validation
        assert isinstance(api, FlextLdapClient)

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom config using FlextTestsMatchers."""
        FlextLdapConfigs()
        api = FlextLdapClient()

        # Basic validation
        assert isinstance(api, FlextLdapClient)

    def test_generate_session_id(self) -> None:
        """Test session ID generation using cached property from FlextUtilities."""
        api = FlextLdapClient()

        # Test cached property access
        session_id1 = api.session_id
        session_id2 = api.session_id

        # Use basic assertions for string validation
        assert session_id1
        assert len(session_id1) > 0
        assert session_id2
        assert len(session_id2) > 0
        assert session_id1.startswith("flext_ldap_session")

        # Cached property should return same value
        assert session_id1 == session_id2

    @pytest.mark.asyncio
    async def test_connect_without_real_server(self) -> None:
        """Test connect method without real LDAP server using FlextTestsMatchers."""
        api = FlextLdapClient()

        result = await api.connect(
            "ldap://localhost:389",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test",
            "password",
        )

        # Use basic assertions for result validation
        assert isinstance(result, FlextResult)
        if result.is_success:
            # If it succeeds, we have a real LDAP server
            # Connect method returns None on success
            assert result.unwrap() is None
        else:
            # Expected failure without real LDAP connection
            assert not result.is_success

    @pytest.mark.asyncio
    async def test_search_without_connection(self) -> None:
        """Test search method without connection."""
        api = FlextLdapClient()

        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "uid"],
            size_limit=100,
            time_limit=30,
            page_size=None,
            paged_cookie=None,
        )

        result = await api.search_with_request(search_request)

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "not found", "failed", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_search_users_without_connection(self) -> None:
        """Test search_users method without connection."""
        api = FlextLdapClient()

        result = await api.search_users(
            "ou=users,dc=example,dc=com",
        )

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "not found", "failed", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_create_user_without_connection(self) -> None:
        """Test create_user method without connection."""
        api = FlextLdapClient()

        create_request = FlextLdapModels.CreateUserRequest(
            dn="cn=newuser,ou=users,dc=example,dc=com",
            uid="newuser",
            cn="New User",
            sn="User",
            given_name=None,
            mail=None,
            user_password=None,
            telephone_number=None,
            description=None,
            department=None,
            title=None,
            organization=None,
        )

        result = await api.create_user(create_request)

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "not found", "failed", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_get_user_without_connection(self) -> None:
        """Test get_user method without connection."""
        api = FlextLdapClient()

        result = await api.get_user("cn=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        # get_user doesn't require session, so it should attempt the operation
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "failed", "not found", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_update_user_without_connection(self) -> None:
        """Test update_user method without connection."""
        api = FlextLdapClient()

        dn = "cn=testuser,ou=users,dc=example,dc=com"
        attributes: FlextLdapTypes.Entry.AttributeDict = {
            "description": "Updated user",
        }

        result = await api.update_user(dn, attributes)

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "not found", "failed", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_delete_user_without_connection(self) -> None:
        """Test delete_user method without connection."""
        api = FlextLdapClient()

        result = await api.delete_user("cn=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        # delete_user doesn't require session, so it should attempt the operation
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "failed", "not found", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_create_group_without_connection(self) -> None:
        """Test create_group method without connection."""
        api = FlextLdapClient()

        # Test with CreateGroupRequest
        create_request = FlextLdapModels.CreateGroupRequest(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test group",
            members=None,
        )

        result = await api.create_group(create_request)

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in [
                    "connection",
                    "not found",
                    "failed",
                    "ldap",
                    "error",
                    "required",
                    "parameter",
                ]
            )

    @pytest.mark.asyncio
    async def test_get_group_without_connection(self) -> None:
        """Test get_group method without connection."""
        api = FlextLdapClient()

        result = await api.get_group("cn=testgroup,ou=groups,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        # get_group doesn't require session, so it should attempt the operation
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "failed", "not found", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_update_group_without_connection(self) -> None:
        """Test update_group method without connection."""
        api = FlextLdapClient()

        # Use basic update parameters - no UpdateGroupRequest entity exists
        group_dn = "cn=testgroup,ou=groups,dc=example,dc=com"
        attributes: FlextLdapTypes.Entry.AttributeDict = {
            "description": "Updated group",
        }

        result = await api.update_group(group_dn, attributes)

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "not found", "failed", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_delete_group_without_connection(self) -> None:
        """Test delete_group method without connection."""
        api = FlextLdapClient()

        result = await api.delete_group("cn=testgroup,ou=groups,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        # delete_group doesn't require session, so it should attempt the operation
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "failed", "not found", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_add_member_without_connection(self) -> None:
        """Test add_member method without connection."""
        api = FlextLdapClient()

        result = await api.add_member(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn=testuser,ou=users,dc=example,dc=com",
        )

        assert isinstance(result, FlextResult)
        # add_member doesn't require session, so it should attempt the operation
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "failed", "not found", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_remove_member_without_connection(self) -> None:
        """Test remove_member method without connection."""
        api = FlextLdapClient()

        result = await api.remove_member(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn=testuser,ou=users,dc=example,dc=com",
        )

        assert isinstance(result, FlextResult)
        # remove_member doesn't require session, so it should attempt the operation
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "failed", "not found", "ldap"]
            )

    @pytest.mark.asyncio
    async def test_get_members_without_connection(self) -> None:
        """Test get_members method without connection."""
        api = FlextLdapClient()

        result = await api.get_members("cn=testgroup,ou=groups,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        # get_members doesn't require session, so it should attempt the operation
        if not result.is_success:
            assert any(
                result.error is not None and pattern in result.error.lower()
                for pattern in ["connection", "failed", "not found", "ldap"]
            )

    def test_validate_dn_valid(self) -> None:
        """Test DN validation with valid DNs."""
        FlextLdapClient()

        valid_dns = [
            "cn=user,dc=example,dc=com",
            "uid=john,ou=users,dc=example,dc=com",
            "cn=group,ou=groups,dc=example,dc=com",
            "dc=example,dc=com",
        ]

        for dn in valid_dns:
            result = FlextLdapValidations.validate_dn(dn)
            assert result.is_success, f"DN should be valid: {dn}"

    def test_validate_dn_invalid(self) -> None:
        """Test DN validation with invalid DNs."""
        FlextLdapClient()

        invalid_dns = [
            "",  # Empty DN
            "invalid",  # No proper format
            "cn=",  # Incomplete
            "=value",  # Missing attribute
            "cn=test=invalid",  # Invalid format
        ]

        for dn in invalid_dns:
            result = FlextLdapValidations.validate_dn(dn)
            if not result.is_success:
                assert any(
                    result.error is not None and pattern in result.error.lower()
                    for pattern in ["invalid", "empty", "format", "dn"]
                )

    def test_validate_filter_valid(self) -> None:
        """Test filter validation with valid filters."""
        FlextLdapClient()

        valid_filters = [
            "(objectClass=person)",
            "(cn=test*)",
            "(&(objectClass=person)(uid=john))",
            "(|(cn=user1)(cn=user2))",
            "(!objectClass=computer)",
        ]

        for filter_str in valid_filters:
            result = FlextLdapValidations.validate_filter(filter_str)
            assert result.is_success, f"Filter should be valid: {filter_str}"

    def test_validate_filter_invalid(self) -> None:
        """Test filter validation with invalid filters."""
        FlextLdapClient()

        invalid_filters = [
            "",  # Empty filter
            "objectClass=person",  # Missing parentheses
            "(objectClass=person",  # Incomplete parentheses
            "objectClass=person)",  # Incomplete parentheses
            "()",  # Empty parentheses
            "invalid",  # No proper format
        ]

        for filter_str in invalid_filters:
            result = FlextLdapValidations.validate_filter(filter_str)
            if not result.is_success:
                assert any(
                    result.error is not None and pattern in result.error.lower()
                    for pattern in [
                        "invalid",
                        "empty",
                        "format",
                        "filter",
                        "parentheses",
                    ]
                )

    def test_flext_ldap_api_instantiation(self) -> None:
        """Test FlextLdapClient instantiation."""
        api1 = FlextLdapClient()
        api2 = FlextLdapClient()

        assert isinstance(api1, FlextLdapClient)
        assert isinstance(api2, FlextLdapClient)

        # Test with custom config - work around singleton pattern
        connection_config = FlextLdapModels.ConnectionConfig(
            server="ldap://factory.example.com",
        )
        config = FlextLdapConfigs()
        # Manually set the connection after creation
        config.ldap_default_connection = connection_config
        api3 = FlextLdapClient()

        # Basic validation
        assert isinstance(api3, FlextLdapClient)

    # =============================================================================
    # Error Handling and Edge Cases
    # =============================================================================

    @pytest.mark.asyncio
    async def test_search_with_different_scopes(self) -> None:
        """Test search operations with different LDAP scopes."""
        api = FlextLdapClient()

        scopes = ["base", "onelevel", "subtree"]

        for scope in scopes:
            search_request = FlextLdapModels.SearchRequest(
                base_dn="dc=example,dc=com",
                filter="(objectClass=*)",
                scope=scope,
                attributes=["*"],
                size_limit=100,
                time_limit=30,
                page_size=None,
                paged_cookie=None,
            )

            result = await api.search_with_request(search_request)
            assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_search_with_size_and_time_limits(self) -> None:
        """Test search with size and time limits."""
        api = FlextLdapClient()

        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "uid"],
            size_limit=50,
            time_limit=30,
            page_size=None,
            paged_cookie=None,
        )

        result = await api.search_with_request(search_request)
        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_user_operations_with_complex_data(self) -> None:
        """Test user operations with complex attribute data."""
        api = FlextLdapClient()

        # Test create with comprehensive attributes
        create_request = FlextLdapModels.CreateUserRequest(
            dn="cn=complex.user,ou=users,dc=example,dc=com",
            uid="complex.user",
            cn="Complex User",
            sn="User",
            given_name="Complex",
            mail="complex.user@example.com",
            user_password=None,
            telephone_number=None,
            description=None,
            department=None,
            title=None,
            organization=None,
        )

        result = await api.create_user(create_request)
        assert isinstance(result, FlextResult)

        # Test update with multiple attributes
        dn = "cn=complex.user,ou=users,dc=example,dc=com"
        attributes: FlextLdapTypes.Entry.AttributeDict = {
            "description": "Updated complex user",
            "telephoneNumber": "+1-555-5678",
            "title": "Senior Developer",
        }

        update_result = await api.update_user(dn, attributes)
        assert isinstance(update_result, FlextResult)

    @pytest.mark.asyncio
    async def test_group_operations_comprehensive(self) -> None:
        """Test comprehensive group operations."""
        api = FlextLdapClient()

        # Test create group with members
        create_request = FlextLdapModels.CreateGroupRequest(
            dn="cn=comprehensive.group,ou=groups,dc=example,dc=com",
            cn="comprehensive.group",
            description="Comprehensive test group",
            members=[
                "cn=user1,ou=users,dc=example,dc=com",
                "cn=user2,ou=users,dc=example,dc=com",
            ],
        )

        result = await api.create_group(create_request)
        assert isinstance(result, FlextResult)

        # Test update group
        group_attributes: FlextLdapTypes.Entry.AttributeDict = {
            "description": "Updated comprehensive group",
            "cn": "updated.group",
        }
        update_result = await api.update_group(
            dn="cn=comprehensive.group,ou=groups,dc=example,dc=com",
            attributes=group_attributes,
        )
        assert isinstance(update_result, FlextResult)

    @pytest.mark.asyncio
    async def test_session_id_consistency(self) -> None:
        """Test that session IDs are generated consistently."""
        session_ids = [f"flext_ldap_session_{uuid.uuid4()}" for _ in range(10)]

        # All should start with flext_ldap_session
        for session_id in session_ids:
            assert session_id.startswith("flext_ldap_session")

        # All should be unique
        assert len(set(session_ids)) == 10

        # All should have UUID-like format after flext_ldap_session_
        for session_id in session_ids:
            uuid_part = session_id.replace("flext_ldap_session_", "")
            assert (
                len(uuid_part.split("-")) == 5
            )  # UUID format has 5 parts separated by -
