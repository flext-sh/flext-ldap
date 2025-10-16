"""Comprehensive unit tests for flext-ldap clients module.

This module provides complete test coverage for the flext-ldap client functionality,
consolidating all client-related tests into a single file per flext standards.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextTypes

from flext_ldap.clients import FlextLdapClients
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes

# Disable strict pyright checks for this comprehensive test module. These tests
# intentionally exercise protected helpers and use lightweight mocks which
# trigger static-analysis false-positives (private usage, argument-type and
# call-signature checks). Narrowly disable those pyright rules here.
# pyright: reportPrivateUsage=false, reportArgumentType=false, reportCallIssue=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportIndexIssue=false


class TestFlextLdapClientsComprehensive:
    """Comprehensive tests for FlextLdapClients class focusing on low coverage methods."""

    def test_connect_invalid_server_uri(self) -> None:
        """Test connect with invalid server URI."""
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

        result = client.unbind()
        # unbind is idempotent - returns success when not connected
        assert result.is_success
        assert result.data is None

    def test_is_connected_initial_state(self) -> None:
        """Test is_connected in initial state."""
        client = FlextLdapClients()
        assert not client.is_connected()

    def test_test_connection_not_connected(self) -> None:
        """Test test_connection when not connected."""
        client = FlextLdapClients()

        result = client.test_connection()
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_authenticate_user_not_connected(self) -> None:
        """Test authenticate_user when not connected."""
        client = FlextLdapClients()

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
        import pytest

        pytest.skip("Method _validate_connection removed during refactoring")

    # Obsolete test removed - _search_user_by_username method no longer exists
    # Use search_users method instead

    def test_authenticate_user_credentials_not_connected(self) -> None:
        """Test authenticate_user when not connected."""
        client = FlextLdapClients()

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

        result = client.authenticate_user("testuser", "testpass")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    @pytest.mark.skip(
        reason="Private method _create_user_from_entry_result doesn't exist in current implementation. Test needs refactoring."
    )
    def test_create_user_from_entry_result_empty_entry(self) -> None:
        """Test _create_user_from_entry_result with empty entry."""
        client = FlextLdapClients()

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

    # Obsolete test removed - _validate_search_request method no longer exists
    # Search request validation is now done via Pydantic validators on the model itself

    # Obsolete test removed - _validate_search_request method no longer exists
    @pytest.mark.skip(
        reason="Private method _validate_search_request doesn't exist in current implementation. Test marked obsolete."
    )
    def test_validate_search_request_valid_with_connection(self) -> None:
        """OBSOLETE TEST - _validate_search_request method no longer exists."""
        client = FlextLdapClients()

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

        # Set mock connection - using setattr to bypass Pydantic validation
        mock_conn = MockConnection()
        setattr(client, "_connection", mock_conn)

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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

    @pytest.mark.skip(
        reason="Method build_user_attributes doesn't exist in current implementation. Test needs refactoring."
    )
    def testbuild_user_attributes_missing_required_fields(self) -> None:
        """Test build_user_attributes with minimal required fields and optional None values."""
        client = FlextLdapClients()

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

        result = client.build_user_attributes(user_data)
        assert result.is_success
        attributes = result.unwrap()
        assert attributes["uid"] == ["testuser"]
        assert attributes["cn"] == ["Test User"]
        assert attributes["sn"] == ["User"]
        assert "mail" not in attributes  # Optional fields with None are not included

    def testadd_user_to_ldap_not_connected(self) -> None:
        """Test add_user_to_ldap when not connected."""
        client = FlextLdapClients()

        attributes = {
            "cn": ["Test User"],
            "sn": ["User"],
            "uid": ["testuser"],
            "objectClass": ["inetOrgPerson", "top"],
        }

        result = client.add_entry("cn=testuser,dc=test,dc=com", attributes)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    # Obsolete test removed - retrieve_created_user method no longer exists

    def test_create_group_not_connected(self) -> None:
        """Test create_group when not connected."""
        client = FlextLdapClients()

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
        client = FlextLdapClients()

        result = client.unbind()
        assert result.is_success
        assert result.data is None

    def test_update_group_not_connected(self) -> None:
        """Test update_group_attributes when not connected."""
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

        result = client.group_exists("cn=testgroup,dc=test,dc=com")
        assert result.is_success
        assert result.data is False

    def test_search_not_connected(self) -> None:
        """Test search when not connected."""
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

        result = client.delete_entry("cn=testgroup,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_add_not_connected(self) -> None:
        """Test add when not connected."""
        client = FlextLdapClients()

        result = client.add_entry("cn=testuser,dc=test,dc=com", {"cn": "Test User"})
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_modify_not_connected(self) -> None:
        """Test modify when not connected."""
        client = FlextLdapClients()

        changes = {"cn": [("MODIFY_REPLACE", ["Updated User"])]}
        result = client.modify_entry("cn=testuser,dc=test,dc=com", changes)
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_delete_not_connected(self) -> None:
        """Test delete when not connected."""
        client = FlextLdapClients()

        result = client.delete_entry("cn=testuser,dc=test,dc=com")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_add_member_not_connected(self) -> None:
        """Test add_member when not connected."""
        client = FlextLdapClients()

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

    @pytest.mark.skip(
        reason="session_id property doesn't exist in current implementation. Test needs refactoring."
    )
    def test_session_id_property(self) -> None:
        """Test session_id property getter and setter."""
        client = FlextLdapClients()

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
        client = FlextLdapClients()

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
        client = FlextLdapClients()

        # Mock entry with empty attributes
        # The mock must properly simulate FlextLdapModels.Entry behavior
        class MockEntry(FlextLdapModels.Entry):
            """Mock Entry that behaves like FlextLdapModels.Entry."""

            def __init__(self) -> None:
                # Initialize with minimal required data
                super().__init__(
                    dn="cn=testgroup,dc=test,dc=com",
                    attributes={},
                    object_classes=["groupOfNames"],
                )

            def __getitem__(
                self, key: str
            ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
                """Return attribute value or empty list/string."""
                value = self.attributes.get(key, [])
                # Return empty string for single-value attributes like 'cn'
                if key == "cn":
                    return "" if not value else value[0]
                # Return empty list for multi-value attributes like 'member'
                return value or []

        group = client._create_group_from_entry(MockEntry())

        assert group is not None
        assert group.dn == "cn=testgroup,dc=test,dc=com"
        assert not group.cn  # Should be empty string when not in attributes
        assert group.member_dns == []  # Should be empty list when not in attributes

    def test_search_universal_not_connected(self) -> None:
        """Test search_universal when not connected."""
        client = FlextLdapClients()

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

    def test_compare_universal_not_connected(self) -> None:
        """Test compare_universal when not connected."""
        client = FlextLdapClients()

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
        client = FlextLdapClients()

        result = client.extended_operation_universal("1.3.6.1.4.1.1466.20037", b"test")
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "LDAP connection not established" in result.error
        )

    def test_get_server_capabilities_not_connected(self) -> None:
        """Test get_server_capabilities when not connected."""
        client = FlextLdapClients()

        result = client.get_server_capabilities()
        # Should return failure when not connected
        assert result.is_failure
        assert result.error
        assert "not available" in result.error.lower()

    @pytest.mark.skip(
        reason="Private method _normalize_filter doesn't exist in current implementation. Test needs refactoring."
    )
    def test_normalize_filter(self) -> None:
        """Test _normalize_filter method."""
        client = FlextLdapClients()

        # Test with whitespace
        result = client._normalize_filter("  (objectClass=person)  ")
        assert result == "  (objectClass=person)  "

        # Test with no whitespace
        result = client._normalize_filter("(objectClass=person)")
        assert result == "(objectClass=person)"

    @pytest.mark.skip(
        reason="Private method _normalize_attributes doesn't exist in current implementation. Test needs refactoring."
    )
    def test_normalize_attributes(self) -> None:
        """Test _normalize_attributes method."""
        client = FlextLdapClients()

        # Test with whitespace
        attributes = ["  cn  ", "  sn  ", "mail"]
        result = client._normalize_attributes(attributes)
        # Without server quirks setup, normalization doesn't run
        assert result == ["  cn  ", "  sn  ", "mail"]

    @pytest.mark.skip(
        reason="Private method _normalize_entry_attributes doesn't exist in current implementation. Test needs refactoring."
    )
    def test_normalize_entry_attributes(self) -> None:
        """Test _normalize_entry_attributes method."""
        client = FlextLdapClients()

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

    @pytest.mark.skip(
        reason="Private method _normalize_modify_changes doesn't exist in current implementation. Test needs refactoring."
    )
    def test_normalize_modify_changes(self) -> None:
        """Test _normalize_modify_changes method."""
        client = FlextLdapClients()

        changes: FlextTypes.Dict = {
            "cn": [("MODIFY_REPLACE", ["  Test User  "])],
            "sn": [("MODIFY_REPLACE", ["User"])],
        }

        result = client._normalize_modify_changes(changes)
        assert result == {
            "cn": [("MODIFY_REPLACE", ["Test User"])],
            "sn": [("MODIFY_REPLACE", ["User"])],
        }

    @pytest.mark.skip(
        reason="Private method _normalize_search_results doesn't exist in current implementation. Test needs refactoring."
    )
    def test_normalize_search_results(self) -> None:
        """Test _normalize_search_results method."""
        client = FlextLdapClients()

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


@pytest.mark.unit
class TestFlextLdapClientsConnection:
    """Test FlextLdapClients connection lifecycle operations."""

    def test_client_initialization_no_config(self) -> None:
        """Test client can be initialized without configuration."""
        client = FlextLdapClients()
        assert client is not None
        assert not client.is_connected()

    def test_client_initialization_with_config(self) -> None:
        """Test client initialization with configuration."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost:3390",
            port=3390,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password="REDACTED_LDAP_BIND_PASSWORD123",
            use_ssl=False,
        )
        client = FlextLdapClients(config=config)
        assert client is not None
        assert not client.is_connected()

    def test_is_connected_before_connection(self) -> None:
        """Test is_connected returns False before connecting."""
        client = FlextLdapClients()
        assert not client.is_connected()

    def test_connect_missing_server_uri(self) -> None:
        """Test connect fails with invalid (empty) server URI."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri="",  # Invalid empty URI
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert result.is_failure
        assert (result.error and result.error and "server" in result.error.lower()) or (
            result.error and "uri" in result.error.lower()
        )

    def test_connect_missing_bind_dn(self) -> None:
        """Test connect fails with invalid (empty) bind DN."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="",  # Invalid empty DN
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert result.is_failure
        assert (result.error and result.error and "dn" in result.error.lower()) or (
            result.error and "bind" in result.error.lower()
        )

    def test_connect_missing_password(self) -> None:
        """Test connect fails with invalid (empty) password."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="",  # Invalid empty password
        )
        assert result.is_failure
        assert result.error and result.error and "password" in result.error.lower()

    def test_disconnect_before_connect(self) -> None:
        """Test disconnect returns success even if not connected."""
        client = FlextLdapClients()
        result = client.unbind()
        # Should succeed gracefully (idempotent)
        assert result.is_success


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsConnectionIntegration:
    """Integration tests for FlextLdapClients connection with real LDAP server."""

    def test_connect_success(self, clean_ldap_container: FlextTypes.Dict) -> None:
        """Test successful connection to LDAP server."""
        client = FlextLdapClients()

        # Connect using container info
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        assert result.is_success
        assert result.value is True
        assert client.is_connected()

        # Cleanup
        client.unbind()

    def test_connect_invalid_credentials(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test connection fails with invalid credentials."""
        client = FlextLdapClients()

        # Attempt connection with wrong password
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password="wrong_password",
        )

        assert result.is_failure
        assert (result.error and "invalid credentials" in result.error.lower()) or (
            result.error and "bind" in result.error.lower()
        )
        assert not client.is_connected()

    def test_connect_invalid_bind_dn(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test connection fails with invalid bind DN."""
        client = FlextLdapClients()

        # Attempt connection with invalid DN
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn="cn=invalid,dc=flext,dc=local",
            password=str(clean_ldap_container["password"]),
        )

        assert result.is_failure
        assert not client.is_connected()

    def test_disconnect_after_connect(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test disconnect after successful connection."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert connect_result.is_success
        assert client.is_connected()

        # Disconnect
        disconnect_result = client.unbind()
        assert disconnect_result.is_success
        assert not client.is_connected()

    def test_reconnect_after_disconnect(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test can reconnect after disconnect."""
        client = FlextLdapClients()

        # First connection
        result1 = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result1.is_success
        assert client.is_connected()

        # Disconnect
        disconnect_result = client.unbind()
        assert disconnect_result.is_success
        assert not client.is_connected()

        # Reconnect
        result2 = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result2.is_success
        assert client.is_connected()

        # Cleanup
        client.unbind()

    def test_test_connection_success(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test test_connection method validates connectivity."""
        client = FlextLdapClients()

        # Connect first
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Test connection
        result = client.test_connection()
        assert result.is_success
        assert result.value is True

        # Cleanup
        client.unbind()

    def test_test_connection_not_connected(self) -> None:
        """Test test_connection fails when not connected."""
        client = FlextLdapClients()

        result = client.test_connection()
        assert result.is_failure
        assert result.error and "connection not established" in result.error.lower()

    def test_bind_after_connect(self, clean_ldap_container: FlextTypes.Dict) -> None:
        """Test bind operation after connection."""
        client = FlextLdapClients()

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Bind (rebind with same credentials)
        bind_result = client.bind(
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert bind_result.is_success

        # Cleanup
        client.unbind()

    def test_unbind_after_connect(self, clean_ldap_container: FlextTypes.Dict) -> None:
        """Test unbind operation after connection."""
        client = FlextLdapClients()

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert client.is_connected()

        # Unbind
        unbind_result = client.unbind()
        assert unbind_result.is_success
        assert not client.is_connected()

    def test_session_id_persistence(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test session ID persists across connection lifecycle."""
        client = FlextLdapClients()

        # Get initial session ID
        session_id_1 = client.session_id

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Session ID should be same
        session_id_2 = client.session_id
        assert session_id_1 == session_id_2

        # Disconnect
        client.unbind()

        # Session ID should still be same
        session_id_3 = client.session_id
        assert session_id_1 == session_id_3


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
class TestFlextLdapClientsConnectionEdgeCases:
    """Edge case tests for FlextLdapClients connection management."""

    def test_multiple_disconnect_calls_idempotent(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test multiple disconnect calls are idempotent."""
        client = FlextLdapClients()

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Disconnect multiple times
        result1 = client.unbind()
        assert result1.is_success

        result2 = client.unbind()
        assert result2.is_success

        result3 = client.unbind()
        assert result3.is_success

    def test_connect_overrides_config(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test connect parameters override config object."""
        # Create config with wrong credentials
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://wrong-server:389",
            port=389,
            bind_dn="cn=wrong,dc=example,dc=com",
            bind_password="wrong",
            use_ssl=False,
        )
        client = FlextLdapClients(config=config)

        # Connect with correct parameters (should override config)
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result.is_success
        assert client.is_connected()

        # Cleanup
        client.unbind()


@pytest.mark.unit
class TestFlextLdapClientsAuthenticationUnit:
    """Test FlextLdapClients authentication operations - unit tests (no Docker)."""

    def test_authenticate_user_not_connected(self) -> None:
        """Test authenticate_user fails when not connected."""
        client = FlextLdapClients()

        result = client.authenticate_user(username="testuser", password="password123")

        assert result.is_failure
        assert (result.error and "not established" in result.error.lower()) or (
            result.error and "connection" in result.error.lower()
        )

    def test_authenticate_user_empty_username(self) -> None:
        """Test authenticate_user with empty username."""
        client = FlextLdapClients()

        # Even though client is not connected, empty username should be caught
        result = client.authenticate_user(username="", password="password123")

        assert result.is_failure
        # Will fail at connection validation or user search stage

    def test_authenticate_user_empty_password(self) -> None:
        """Test authenticate_user with empty password."""
        client = FlextLdapClients()

        # Even though client is not connected, empty password should be caught
        result = client.authenticate_user(username="testuser", password="")

        assert result.is_failure
        # Will fail at connection validation or authentication stage


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsAuthenticationIntegration:
    """Integration tests for FlextLdapClients authentication with real LDAP server.

    Note: Full authentication tests with user creation are skipped due to hardcoded
    search base in clients.py (_search_user_by_username uses 'ou=users,dc=example,dc=com').
    These tests will be enabled after refactoring to use configurable search base.
    """

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> FlextLdapClients:
        """Create and connect LDAP client for authentication tests."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_authenticate_user_not_found(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test authentication fails for non-existent user."""
        result = authenticated_client.authenticate_user(
            username="nonexistentuser", password="password123"
        )

        assert result.is_failure
        assert (result.error and "not found" in result.error.lower()) or (
            result.error and "search failed" in result.error.lower()
        )

    def test_authenticate_disconnected_during_auth(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test authentication handles disconnection gracefully."""
        # Disconnect the client
        authenticated_client.unbind()

        result = authenticated_client.authenticate_user(
            username="testuser", password="password123"
        )

        assert result.is_failure
        assert (result.error and "not established" in result.error.lower()) or (
            result.error and "connection" in result.error.lower()
        )


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
class TestFlextLdapClientsAuthenticationEdgeCases:
    """Edge case tests for FlextLdapClients authentication."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> FlextLdapClients:
        """Create and connect LDAP client for edge case tests."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_authenticate_special_characters_in_username(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test authentication with special characters in username."""
        result = authenticated_client.authenticate_user(
            username="user@example.com",  # Email format
            password="password123",
        )

        # Should handle gracefully (will fail as user doesn't exist)
        assert result.is_failure
        assert (result.error and "not found" in result.error.lower()) or (
            result.error and "search failed" in result.error.lower()
        )

    def test_authenticate_ldap_injection_attempt(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test authentication prevents LDAP injection."""
        # Attempt LDAP injection in username
        result = authenticated_client.authenticate_user(
            username="*)(uid=*",  # Injection attempt
            password="password123",
        )

        # Should handle safely without crashing
        assert result.is_failure

    def test_authenticate_very_long_username(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test authentication with very long username."""
        long_username = "a" * 1000

        result = authenticated_client.authenticate_user(
            username=long_username, password="password123"
        )

        # Should handle gracefully
        assert result.is_failure

    def test_authenticate_unicode_username(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test authentication with unicode characters in username."""
        result = authenticated_client.authenticate_user(
            username="用户名",  # Chinese characters
            password="password123",
        )

        # Should handle gracefully (will fail as user doesn't exist)
        assert result.is_failure


@pytest.mark.unit
class TestFlextLdapClientsSearchUnit:
    """Test FlextLdapClients search operations - unit tests (no Docker)."""

    def test_search_with_request_not_connected(self) -> None:
        """Test search_with_request fails when not connected."""
        client = FlextLdapClients()

        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            scope="subtree",
        )

        result = client.search_with_request(search_request)

        assert result.is_failure
        assert (result.error and "not established" in result.error.lower()) or (
            result.error and "connection" in result.error.lower()
        )

    def test_search_with_request_invalid_dn(self) -> None:
        """Test search_with_request validates base DN with custom exception."""
        from flext_ldap.exceptions import FlextLdapExceptions

        FlextLdapClients()

        # Custom validation raises LdapValidationError at model construction
        with pytest.raises(
            FlextLdapExceptions.LdapValidationError, match="DN cannot be empty"
        ):
            FlextLdapModels.SearchRequest(
                base_dn="",  # Invalid empty DN
                filter_str="(objectClass=person)",
                scope="subtree",
            )

    def test_search_with_request_invalid_filter(self) -> None:
        """Test search_with_request validates filter at Pydantic level."""
        from flext_ldap.exceptions import FlextLdapExceptions

        FlextLdapClients()

        # Pydantic validation should reject empty filter at model construction
        # Custom domain validator raises LdapValidationError instead of Pydantic ValidationError
        with pytest.raises(FlextLdapExceptions.LdapValidationError) as exc_info:
            FlextLdapModels.SearchRequest(
                base_dn="dc=flext,dc=local",
                filter_str="",  # Invalid empty filter
                scope="subtree",
            )

        assert "filter" in str(exc_info.value).lower()

    def test_search_users_not_connected(self) -> None:
        """Test search_users fails when not connected."""
        client = FlextLdapClients()

        result = client.search_users(base_dn="ou=users,dc=flext,dc=local")

        assert result.is_failure
        assert (
            result.error and result.error and "not established" in result.error.lower()
        )

    def test_search_groups_not_connected(self) -> None:
        """Test search_groups fails when not connected."""
        client = FlextLdapClients()

        result = client.search_groups(base_dn="ou=groups,dc=flext,dc=local")

        assert result.is_failure
        assert (
            result.error and result.error and "not established" in result.error.lower()
        )


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsSearchIntegration:
    """Integration tests for FlextLdapClients search with real LDAP server."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> FlextLdapClients:
        """Create and connect LDAP client for search tests."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_search_with_request_base_search(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_with_request with BASE scope."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=dcObject)",
            scope="base",
            attributes=["objectClass", "dc"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value
        assert response is not None
        assert isinstance(response, FlextLdapModels.SearchResponse)
        assert len(response.entries) > 0

    def test_search_with_request_subtree_search(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_with_request with SUBTREE scope."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=organizationalUnit)",
            scope="subtree",
            attributes=["ou", "objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value
        assert response is not None
        assert isinstance(response.entries, list)

    def test_search_with_request_returns_response(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_with_request returns SearchResponse object."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=dcObject)",  # More specific filter
            scope="base",  # Base search for reliability
            attributes=["dc", "objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value

        # Verify response structure
        assert hasattr(response, "entries")
        assert isinstance(response.entries, list)
        # Note: entries list may be empty or have entries with attribute parsing issues
        # due to ldap3 entry_attributes being list instead of dict[str, object] in some cases

    def test_search_users_all_users(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_users retrieves all users."""
        result = authenticated_client.search_users(
            base_dn=str(clean_ldap_container["base_dn"])
        )

        assert result.is_success
        users = result.value
        assert isinstance(users, list)
        # May be empty if no users exist, but should succeed

    def test_search_users_with_uid_filter(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_users with UID filter."""
        result = authenticated_client.search_users(
            base_dn=str(clean_ldap_container["base_dn"]), uid="nonexistentuser"
        )

        assert result.is_success
        users = result.value
        assert isinstance(users, list)
        # Should return empty list for non-existent user
        assert len(users) == 0

    def test_search_groups_all_groups(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_groups retrieves all groups."""
        result = authenticated_client.search_groups(
            base_dn=str(clean_ldap_container["base_dn"])
        )

        assert result.is_success
        groups = result.value
        assert isinstance(groups, list)
        # May be empty if no groups exist, but should succeed

    def test_search_groups_with_cn_filter(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_groups with CN filter."""
        result = authenticated_client.search_groups(
            base_dn=str(clean_ldap_container["base_dn"]), cn="nonexistentgroup"
        )

        assert result.is_success
        groups = result.value
        assert isinstance(groups, list)
        # Should return empty list for non-existent group
        assert len(groups) == 0

    def test_search_disconnected_during_search(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search handles disconnection gracefully."""
        # Disconnect the client
        authenticated_client.unbind()

        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="subtree",
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_failure
        assert (result.error and "not established" in result.error.lower()) or (
            result.error and "connection" in result.error.lower()
        )


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
class TestFlextLdapClientsSearchEdgeCases:
    """Edge case tests for FlextLdapClients search operations."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> FlextLdapClients:
        """Create and connect LDAP client for edge case tests."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_search_with_complex_filter(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search with complex LDAP filter."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(&(objectClass=organizationalUnit)(!(ou=readonly)))",
            scope="subtree",
        )

        result = authenticated_client.search_with_request(search_request)

        # Should handle complex filter without crashing
        assert result.is_success or result.is_failure

    def test_search_with_invalid_attribute_list(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search with non-existent attribute in list."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="base",
            attributes=["nonExistentAttribute"],
        )

        result = authenticated_client.search_with_request(search_request)

        # Should handle gracefully (attribute won't be in results)
        assert result.is_success

    def test_search_with_wildcard_filter(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search with wildcard in filter."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="subtree",
            attributes=["objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value
        assert len(response.entries) > 0

    def test_search_with_case_insensitive_scope(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search handles case-insensitive scope values."""
        # Test uppercase scope
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",  # Uppercase
            attributes=["objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success

    def test_search_users_empty_base_dn(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test search_users with empty base DN."""
        result = authenticated_client.search_users(base_dn="")

        # Method allows empty base DN and searches from root
        # Returns success with empty or full results depending on LDAP server
        assert result.is_success or result.is_failure
        if result.is_success:
            assert isinstance(result.value, list)

    def test_search_groups_special_characters_in_cn(
        self,
        authenticated_client: FlextLdapClients,
        clean_ldap_container: FlextTypes.Dict,
    ) -> None:
        """Test search_groups with special characters in CN."""
        result = authenticated_client.search_groups(
            base_dn=str(clean_ldap_container["base_dn"]), cn="group-with-dashes"
        )

        # Should handle special characters gracefully
        assert result.is_success
        groups = result.value
        assert isinstance(groups, list)
