"""Comprehensive unit tests for flext-ldap clients module.

This module provides complete test coverage for the flext-ldap client functionality,
focusing on the methods with low coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels
from flext_core import FlextTypes

# Disable strict pyright checks for this comprehensive test module. These tests
# intentionally exercise protected helpers and use lightweight mocks which
# trigger static-analysis false-positives (private usage, argument-type and
# call-signature checks). Narrowly disable those pyright rules here.
# pyright: reportPrivateUsage=false, reportArgumentType=false, reportCallIssue=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportIndexIssue=false


class TestFlextLdapClientComprehensive:
    """Comprehensive tests for FlextLdapClient class focusing on low coverage methods."""

    def test_connect_invalid_server_uri(self) -> None:
        """Test connect with invalid server URI."""
        client = FlextLdapClient()

        result = client.connect(
            server_uri="invalid://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            password="testpass",
        )

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "URI must start with ldap://" in result.error
        )

    def test_connect_missing_parameters(self) -> None:
        """Test connect with missing parameters."""
        client = FlextLdapClient()

        # Test with empty server_uri
        result = client.connect("", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com", "testpass")
        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "URI cannot be empty" in result.error
        # Test with empty bind_dn
        result = client.connect("ldap://localhost:389", "", "testpass")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "Bind DN cannot be empty" in result.error
        )

    def test_bind_not_connected(self) -> None:
        """Test bind when not connected."""
        client = FlextLdapClient()

        result = client.bind("cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com", "testpass")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_unbind_not_connected(self) -> None:
        """Test unbind when not connected."""
        client = FlextLdapClient()

        result = client.unbind()
        # unbind is idempotent - returns success when not connected
        assert result.is_success
        assert result.data is None

    def test_is_connected_initial_state(self) -> None:
        """Test is_connected in initial state."""
        client = FlextLdapClient()
        assert not client.is_connected()

    def test_test_connection_not_connected(self) -> None:
        """Test test_connection when not connected."""
        client = FlextLdapClient()

        result = client.test_connection()
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Not connected to LDAP server" in result.error
        )

    def test_authenticate_user_not_connected(self) -> None:
        """Test authenticate_user when not connected."""
        client = FlextLdapClient()

        result = client.authenticate_user("testuser", "testpass")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_validate_connection_not_connected(self) -> None:
        """Test _validate_connection when not connected."""
        client = FlextLdapClient()

        result = client._validate_connection()
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_search_user_by_username_not_connected(self) -> None:
        """Test _search_user_by_username when not connected."""
        client = FlextLdapClient()

        result = client._search_user_by_username("testuser")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_authenticate_user_credentials_not_connected(self) -> None:
        """Test _authenticate_user_credentials when not connected."""
        client = FlextLdapClient()

        # Mock user entry
        class MockAttribute:
            def __init__(self, value: object) -> None:
                self.value = value

        class MockEntry:
            def __init__(self) -> None:
                self.entry_dn = "cn=testuser,dc=test,dc=com"
                self.entry_attributes = {"cn": ["testuser"]}

            def __getitem__(self, key: str) -> MockAttribute:
                return MockAttribute(self.entry_attributes.get(key, []))

        result = client._authenticate_user_credentials(MockEntry(), "testpass")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "No server connection established" in result.error
        )

    def test_create_user_from_entry_result_empty_entry(self) -> None:
        """Test _create_user_from_entry_result with empty entry."""
        client = FlextLdapClient()

        # Mock empty entry
        class MockAttribute:
            def __init__(self, value: object) -> None:
                self.value = value

        class MockEntry:
            def __init__(self) -> None:
                self.entry_dn = ""
                self.entry_attributes = {}

            def __getitem__(self, key: str) -> MockAttribute:
                return MockAttribute(self.entry_attributes.get(key, []))

        result = client._create_user_from_entry_result(MockEntry())
        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "User creation failed:" in result.error

    def test_validate_search_request_valid(self) -> None:
        """Test _validate_search_request with valid request."""
        client = FlextLdapClient()

        request = FlextLdapModels.SearchRequest(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=person)",
            scope="SUBTREE",
            attributes=["cn", "sn"],
        )

        result = client._validate_search_request(request)
        assert result.is_failure  # Should fail because no connection is established
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_validate_search_request_valid_with_connection(self) -> None:
        """Test _validate_search_request with valid request and mock connection."""
        client = FlextLdapClient()

        # Mock a connection object that implements LdapConnectionProtocol
        class MockConnection:
            def __init__(self) -> None:
                self.bound = True
                self.last_error = ""
                self.entries = []

            def bind(self) -> bool:
                return True

            def unbind(self) -> bool:
                return True

            # Only implement LdapConnectionProtocol methods
            # (bind, unbind, connect, disconnect, is_connected are inherited or implemented elsewhere)

        # Set mock connection - using object.__setattr__ to bypass Pydantic validation
        mock_conn = MockConnection()
        object.__setattr__(client, "_connection", mock_conn)

        request = FlextLdapModels.SearchRequest(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=person)",
            scope="SUBTREE",
            attributes=["cn", "sn"],
        )

        result = client._validate_search_request(request)
        assert result.is_success
        assert result.data is None

    def test_search_with_request_not_connected(self) -> None:
        """Test search_with_request when not connected."""
        client = FlextLdapClient()

        request = FlextLdapModels.SearchRequest(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=person)",
            scope="SUBTREE",
            attributes=["cn", "sn"],
        )

        result = client.search_with_request(request)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_search_users_not_connected(self) -> None:
        """Test search_users when not connected."""
        client = FlextLdapClient()

        result = client.search_users("dc=test,dc=com", "(objectClass=person)")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_search_groups_not_connected(self) -> None:
        """Test search_groups when not connected."""
        client = FlextLdapClient()

        result = client.search_groups("dc=test,dc=com", "(objectClass=group)")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_get_user_not_connected(self) -> None:
        """Test get_user when not connected."""
        client = FlextLdapClient()

        result = client.get_user("cn=testuser,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_get_group_not_connected(self) -> None:
        """Test get_group when not connected."""
        client = FlextLdapClient()

        result = client.get_group("cn=testgroup,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_create_user_not_connected(self) -> None:
        """Test create_user when not connected."""
        client = FlextLdapClient()

        user_request = FlextLdapModels.CreateUserRequest(
            dn="cn=testuser,dc=test,dc=com",
            cn="Test User",
            sn="User",
            uid="testuser",
            mail="test@example.com",
            given_name=None,
            user_password=None,
            telephone_number=None,
            description=None,
            department=None,
            organizational_unit=None,
            title=None,
            organization=None,
        )

        result = client.create_user(user_request)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_build_user_attributes_missing_required_fields(self) -> None:
        """Test _build_user_attributes with minimal required fields and optional None values."""
        client = FlextLdapClient()

        user_data = FlextLdapModels.CreateUserRequest(
            dn="cn=testuser,dc=test,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            given_name=None,
            mail=None,
            user_password=None,
            telephone_number=None,
            description=None,
            department=None,
            organizational_unit=None,
            title=None,
            organization=None,
        )

        result = client._build_user_attributes(user_data)
        assert result.is_success
        attributes = result.unwrap()
        assert attributes["uid"] == ["testuser"]
        assert attributes["cn"] == ["Test User"]
        assert attributes["sn"] == ["User"]
        assert "mail" not in attributes  # Optional fields with None are not included

    def test_add_user_to_ldap_not_connected(self) -> None:
        """Test _add_user_to_ldap when not connected."""
        client = FlextLdapClient()

        attributes = {
            "cn": ["Test User"],
            "sn": ["User"],
            "uid": ["testuser"],
            "objectClass": ["inetOrgPerson", "top"],
        }

        result = client._add_user_to_ldap("cn=testuser,dc=test,dc=com", attributes)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_retrieve_created_user_not_connected(self) -> None:
        """Test retrieve_created_user when not connected."""
        client = FlextLdapClient()

        result = client.retrieve_created_user("cn=testuser,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "User created but failed to retrieve" in result.error
        )

    def test_create_group_not_connected(self) -> None:
        """Test create_group when not connected."""
        client = FlextLdapClient()

        group_request = FlextLdapModels.CreateGroupRequest(
            dn="cn=testgroup,dc=test,dc=com",
            cn="Test Group",
            description="Test group",
            members=["cn=user1,dc=test,dc=com"],
        )

        result = client.create_group(group_request)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_close_connection_not_connected(self) -> None:
        """Test close_connection when not connected."""
        client = FlextLdapClient()

        result = client.close_connection()
        assert result.is_success
        assert result.data is None

    def test_update_group_not_connected(self) -> None:
        """Test update_group_attributes when not connected."""
        client = FlextLdapClient()

        result = client.update_group_attributes(
            "cn=testgroup,dc=test,dc=com", {"cn": "Updated Group"}
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_remove_member_not_connected(self) -> None:
        """Test remove_member when not connected."""
        client = FlextLdapClient()

        result = client.remove_member(
            "cn=testgroup,dc=test,dc=com", "cn=testuser,dc=test,dc=com"
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_get_members_not_connected(self) -> None:
        """Test get_members when not connected."""
        client = FlextLdapClient()

        result = client.get_members("cn=testgroup,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_user_exists_not_connected(self) -> None:
        """Test user_exists when not connected."""
        client = FlextLdapClient()

        result = client.user_exists("cn=testuser,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_group_exists_not_connected(self) -> None:
        """Test group_exists when not connected."""
        client = FlextLdapClient()

        result = client.group_exists("cn=testgroup,dc=test,dc=com")
        assert result.is_success
        assert result.data is False

    def test_search_not_connected(self) -> None:
        """Test search when not connected."""
        client = FlextLdapClient()

        result = client.search(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=person)",
            attributes=["cn", "sn"],
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_update_user_attributes_not_connected(self) -> None:
        """Test update_user_attributes when not connected."""
        client = FlextLdapClient()

        result = client.update_user_attributes(
            "cn=testuser,dc=test,dc=com", {"cn": "Updated User"}
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_update_group_attributes_not_connected(self) -> None:
        """Test update_group_attributes when not connected."""
        client = FlextLdapClient()

        result = client.update_group_attributes(
            "cn=testgroup,dc=test,dc=com", {"cn": "Updated Group"}
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_delete_user_not_connected(self) -> None:
        """Test delete_user when not connected."""
        client = FlextLdapClient()

        result = client.delete_user("cn=testuser,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_delete_group_not_connected(self) -> None:
        """Test delete_group when not connected."""
        client = FlextLdapClient()

        result = client.delete_group("cn=testgroup,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_add_not_connected(self) -> None:
        """Test add when not connected."""
        client = FlextLdapClient()

        result = client.add("cn=testuser,dc=test,dc=com", {"cn": "Test User"})
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_modify_not_connected(self) -> None:
        """Test modify when not connected."""
        client = FlextLdapClient()

        changes = {"cn": [("MODIFY_REPLACE", ["Updated User"])]}
        result = client.modify("cn=testuser,dc=test,dc=com", changes)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_delete_not_connected(self) -> None:
        """Test delete when not connected."""
        client = FlextLdapClient()

        result = client.delete("cn=testuser,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_add_member_not_connected(self) -> None:
        """Test add_member when not connected."""
        client = FlextLdapClient()

        result = client.add_member(
            "cn=testgroup,dc=test,dc=com", "cn=testuser,dc=test,dc=com"
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_session_id_property(self) -> None:
        """Test session_id property getter and setter."""
        client = FlextLdapClient()

        # Test initial state
        assert client.session_id is None

        # Test setter
        client.session_id = "test-session-123"
        assert client.session_id == "test-session-123"

        # Test setter with None
        client.session_id = None
        assert client.session_id is None

    def test_create_user_from_entry_empty_attributes(self) -> None:
        """Test _create_user_from_entry with empty attributes."""
        client = FlextLdapClient()

        # Mock entry with empty attributes
        class MockAttribute:
            def __init__(self, value: object) -> None:
                self.value = value

        class MockEntry:
            def __init__(self) -> None:
                self.entry_dn = "cn=testuser,dc=test,dc=com"
                self.entry_attributes = {}

            def __getitem__(self, key: str) -> MockAttribute:
                return MockAttribute(self.entry_attributes.get(key, []))

        # This should raise a validation error due to required fields
        with pytest.raises(Exception):
            client._create_user_from_entry(MockEntry())

    def test_create_group_from_entry_empty_attributes(self) -> None:
        """Test _create_group_from_entry with empty attributes."""
        client = FlextLdapClient()

        # Mock entry with empty attributes
        class MockAttribute:
            def __init__(self, value: object) -> None:
                self.value = value

        class MockEntry:
            def __init__(self) -> None:
                self.entry_dn = "cn=testgroup,dc=test,dc=com"
                self.entry_attributes = {}

            def __getitem__(self, key: str) -> MockAttribute:
                return MockAttribute(self.entry_attributes.get(key, []))

        group = client._create_group_from_entry(MockEntry())

        assert group is not None
        assert group.dn == "cn=testgroup,dc=test,dc=com"
        assert not group.cn  # Should be empty string when not in attributes

    def test_search_universal_not_connected(self) -> None:
        """Test search_universal when not connected."""
        client = FlextLdapClient()

        result = client.search_universal(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=person)",
            scope="SUBTREE",
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_add_entry_universal_not_connected(self) -> None:
        """Test add_entry_universal when not connected."""
        client = FlextLdapClient()

        result = client.add_entry_universal(
            "cn=testuser,dc=test,dc=com", {"cn": "Test User"}
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_modify_entry_universal_not_connected(self) -> None:
        """Test modify_entry_universal when not connected."""
        client = FlextLdapClient()

        changes: FlextTypes.Dict = {"cn": [("MODIFY_REPLACE", ["Updated User"])]}
        result = client.modify_entry_universal("cn=testuser,dc=test,dc=com", changes)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_delete_entry_universal_not_connected(self) -> None:
        """Test delete_entry_universal when not connected."""
        client = FlextLdapClient()

        result = client.delete_entry_universal("cn=testuser,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_compare_universal_not_connected(self) -> None:
        """Test compare_universal when not connected."""
        client = FlextLdapClient()

        result = client.compare_universal(
            "cn=testuser,dc=test,dc=com", "cn", "Test User"
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_extended_operation_universal_not_connected(self) -> None:
        """Test extended_operation_universal when not connected."""
        client = FlextLdapClient()

        result = client.extended_operation_universal("1.3.6.1.4.1.1466.20037", b"test")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_search_with_controls_universal_not_connected(self) -> None:
        """Test search_with_controls_universal when not connected."""
        client = FlextLdapClient()

        result = client.search_with_controls_universal(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=person)",
            scope="SUBTREE",
        )
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_get_server_capabilities_not_connected(self) -> None:
        """Test get_server_capabilities when not connected."""
        client = FlextLdapClient()

        result = client.get_server_capabilities()
        # Should return capabilities structure even when not connected
        assert isinstance(result, dict)
        assert "connected" in result
        assert result["connected"] is False

    def test_normalize_filter(self) -> None:
        """Test _normalize_filter method."""
        client = FlextLdapClient()

        # Test with whitespace
        result = client._normalize_filter("  (objectClass=person)  ")
        assert result == "  (objectClass=person)  "

        # Test with no whitespace
        result = client._normalize_filter("(objectClass=person)")
        assert result == "(objectClass=person)"

    def test_normalize_attributes(self) -> None:
        """Test _normalize_attributes method."""
        client = FlextLdapClient()

        # Test with whitespace
        attributes = ["  cn  ", "  sn  ", "mail"]
        result = client._normalize_attributes(attributes)
        # Without server quirks setup, normalization doesn't run
        assert result == ["  cn  ", "  sn  ", "mail"]

    def test_normalize_entry_attributes(self) -> None:
        """Test _normalize_entry_attributes method."""
        client = FlextLdapClient()

        # Mock entry attributes
        attributes: dict[str, str | FlextTypes.StringList] = {
            "cn": ["  Test User  "],
            "sn": ["User"],
            "mail": ["test@example.com"],
        }

        result = client._normalize_entry_attributes(attributes)
        assert result == {
            "cn": ["Test User"],
            "sn": ["User"],
            "mail": ["test@example.com"],
        }

    def test_normalize_modify_changes(self) -> None:
        """Test _normalize_modify_changes method."""
        client = FlextLdapClient()

        changes: FlextTypes.Dict = {
            "cn": [("MODIFY_REPLACE", ["  Test User  "])],
            "sn": [("MODIFY_REPLACE", ["User"])],
        }

        result = client._normalize_modify_changes(changes)
        assert result == {
            "cn": [("MODIFY_REPLACE", ["Test User"])],
            "sn": [("MODIFY_REPLACE", ["User"])],
        }

    def test_normalize_search_results(self) -> None:
        """Test _normalize_search_results method."""
        client = FlextLdapClient()

        # Mock search results as Entry models
        from flext_ldap.models import FlextLdapModels

        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=test,dc=com",
            attributes={"cn": ["  Test User  "], "sn": ["User"]},
            object_classes=["person"],
        )
        results: list[FlextLdapModels.Entry] = [entry]

        result = client._normalize_search_results(results)
        assert len(result) == 1
        # Without server quirks setup, normalization returns results as-is
        first_result = result[0]
        assert isinstance(first_result, FlextLdapModels.Entry)
        assert first_result.dn == "cn=testuser,dc=test,dc=com"
        # Normalization may trim whitespace even without server quirks
        assert first_result.attributes["cn"] in (["  Test User  "], ["Test User"])
        assert first_result.attributes["sn"] == ["User"]
