"""Tests for LDAP client infrastructure module.

# Constants
EXPECTED_BULK_SIZE = 2

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from ldap3.core.exceptions import LDAPException
from ldap3.core.exceptions import LDAPException
from ldap3.core.exceptions import LDAPException
from ldap3.core.exceptions import LDAPException
from ldap3.core.exceptions import LDAPException
from ldap3.core.exceptions import LDAPException
import asyncio


from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from flext_ldap.infrastructure.ldap_client import FlextLdapInfrastructureClient


class TestFlextLdapInfrastructureClient:
    """Test suite for LDAP infrastructure client."""

    def test_init(self) -> None:
        """Test client initialization."""
        adapter = FlextLdapInfrastructureClient()
        if adapter._connections != {}:
            raise AssertionError(f"Expected {{}}, got {adapter._connections}")

    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Test successful LDAP connection."""
        adapter = FlextLdapInfrastructureClient()

        # Mock ldap3 Connection
        mock_connection = MagicMock()

        with (
            patch("ldap3.Connection", return_value=mock_connection),
            patch("ldap3.Server"),
        ):
            result = await adapter.connect("ldap://test.com", "cn=REDACTED_LDAP_BIND_PASSWORD", "password")

            assert result.is_success
            if result.data != "ldap://test.com:cn=REDACTED_LDAP_BIND_PASSWORD":
                raise AssertionError(f"Expected {"ldap://test.com:cn=REDACTED_LDAP_BIND_PASSWORD"}, got {result.data}")
            if "ldap://test.com:cn=REDACTED_LDAP_BIND_PASSWORD" not in adapter._connections:
                raise AssertionError(f"Expected {"ldap://test.com:cn=REDACTED_LDAP_BIND_PASSWORD"} in {adapter._connections}")

    @pytest.mark.asyncio
    async def test_connect_anonymous(self) -> None:
        """Test anonymous LDAP connection."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()

        with (
            patch("ldap3.Connection", return_value=mock_connection),
            patch("ldap3.Server"),
        ):
            result = await adapter.connect("ldap://test.com")

            assert result.is_success
            if result.data != "ldap://test.com:anonymous":
                raise AssertionError(f"Expected {"ldap://test.com:anonymous"}, got {result.data}")

    @pytest.mark.asyncio
    async def test_connect_with_ssl(self) -> None:
        """Test LDAP connection with SSL."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()

        with (
            patch("ldap3.Connection", return_value=mock_connection),
            patch("ldap3.Server") as mock_server,
        ):
            result = await adapter.connect(
                "ldaps://test.com",
                "cn=REDACTED_LDAP_BIND_PASSWORD",
                "password",
                use_ssl=True,
            )

            assert result.is_success
            if result.data != "ldaps://test.com:cn=REDACTED_LDAP_BIND_PASSWORD":
                raise AssertionError(f"Expected {"ldaps://test.com:cn=REDACTED_LDAP_BIND_PASSWORD"}, got {result.data}")

            # Verify SSL was enabled on server
            mock_server.assert_called_once()
            server_call_args = mock_server.call_args
            if not (server_call_args[1]["use_ssl"]):
                raise AssertionError(f"Expected True, got {server_call_args[1]["use_ssl"]}")

    @pytest.mark.asyncio
    async def test_connect_ldap_exception(self) -> None:
        """Test LDAP connection exception."""
        adapter = FlextLdapInfrastructureClient()

        # Mock LDAPException


        with (
            patch("ldap3.Connection", side_effect=LDAPException("LDAP error")),
            patch("ldap3.Server"),
        ):
            result = await adapter.connect("ldap://test.com", "cn=REDACTED_LDAP_BIND_PASSWORD", "password")

            assert not result.is_success
            if "LDAP connection failed" not in (result.error or ""):
                raise AssertionError(f"Expected {"LDAP connection failed"} in {(result.error or "")}")

    @pytest.mark.asyncio
    async def test_connect_unexpected_exception(self) -> None:
        """Test unexpected connection exception."""
        adapter = FlextLdapInfrastructureClient()

        with (
            patch("ldap3.Connection", side_effect=ValueError("Unexpected error")),
            patch("ldap3.Server"),
        ):
            result = await adapter.connect("ldap://test.com", "cn=REDACTED_LDAP_BIND_PASSWORD", "password")

            assert not result.is_success
            assert result.error is not None
            if "Unexpected connection error" not in result.error:
                raise AssertionError(f"Expected {"Unexpected connection error"} in {result.error}")

    @pytest.mark.asyncio
    async def test_disconnect_success(self) -> None:
        """Test successful disconnection."""
        adapter = FlextLdapInfrastructureClient()

        # Setup mock connection
        mock_connection = MagicMock()
        adapter._connections["test_conn"] = mock_connection

        result = await adapter.disconnect("test_conn")

        assert result.is_success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")
        if "test_conn" not in adapter._connections:
            raise AssertionError(f"Expected {"test_conn" not in {adapter._connections}")
        mock_connection.unbind.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_not_found(self) -> None:
        """Test disconnection with non-existent connection."""
        adapter = FlextLdapInfrastructureClient()

        result = await adapter.disconnect("nonexistent")

        assert not result.is_success
        if "Connection not found" not in (result.error or ""):
            raise AssertionError(f"Expected {"Connection not found"} in {(result.error or "")}")

    @pytest.mark.asyncio
    async def test_disconnect_ldap_exception(self) -> None:
        """Test disconnection with LDAP exception."""
        adapter = FlextLdapInfrastructureClient()

        # Mock LDAPException


        mock_connection = MagicMock()
        mock_connection.unbind.side_effect = LDAPException("Unbind error")
        adapter._connections["test_conn"] = mock_connection

        result = await adapter.disconnect("test_conn")

        assert not result.is_success
        if "LDAP disconnect failed" not in (result.error or ""):
            raise AssertionError(f"Expected {"LDAP disconnect failed"} in {(result.error or "")}")

    @pytest.mark.asyncio
    async def test_disconnect_unexpected_exception(self) -> None:
        """Test disconnection with unexpected exception."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.unbind.side_effect = ValueError("Unexpected error")
        adapter._connections["test_conn"] = mock_connection

        result = await adapter.disconnect("test_conn")

        assert not result.is_success
        assert result.error is not None
        if "Unexpected disconnect error" not in result.error:
            raise AssertionError(f"Expected {"Unexpected disconnect error"} in {result.error}")

    @pytest.mark.asyncio
    async def test_search_success(self) -> None:
        """Test successful LDAP search."""
        adapter = FlextLdapInfrastructureClient()

        # Mock connection and search results
        mock_connection = MagicMock()
        mock_connection.search.return_value = True

        # Create mock entries with proper structure
        mock_entry1 = MagicMock()
        mock_entry1.entry_dn = "cn=user1,dc=test"
        mock_entry1.entry_attributes_as_dict = {
            "cn": ["user1"],
            "mail": ["user1@test.com"],
        }

        mock_entry2 = MagicMock()
        mock_entry2.entry_dn = "cn=user2,dc=test"
        mock_entry2.entry_attributes_as_dict = {
            "cn": ["user2"],
            "mail": ["user2@test.com"],
        }

        mock_connection.entries = [mock_entry1, mock_entry2]

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.search("test_conn", "dc=test", "(objectClass=person)")

        assert result.is_success
        assert result.data is not None
        if len(result.data) != EXPECTED_BULK_SIZE:
            raise AssertionError(f"Expected {2}, got {len(result.data)}")
        assert result.data[0]["dn"] == "cn=user1,dc=test"
        if result.data[0]["attributes"]["cn"] != ["user1"]:
            raise AssertionError(f"Expected {["user1"]}, got {result.data[0]["attributes"]["cn"]}")

        mock_connection.search.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_with_attributes(self) -> None:
        """Test LDAP search with specific attributes."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.search.return_value = True
        mock_connection.entries = []

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.search(
            "test_conn",
            "dc=test",
            "(objectClass=person)",
            attributes=["cn", "mail"],
            scope="onelevel",
        )

        assert result.is_success
        mock_connection.search.assert_called_once()
        call_args = mock_connection.search.call_args
        if call_args[1]["attributes"] != ["cn", "mail"]:
            raise AssertionError(f"Expected {["cn", "mail"]}, got {call_args[1]["attributes"]}")

    @pytest.mark.asyncio
    async def test_search_with_base_scope(self) -> None:
        """Test LDAP search with base scope."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.search.return_value = True
        mock_connection.entries = []

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.search(
            "test_conn",
            "dc=test",
            "(objectClass=person)",
            scope="base",
        )

        assert result.is_success
        mock_connection.search.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_connection_not_found(self) -> None:
        """Test search with non-existent connection."""
        adapter = FlextLdapInfrastructureClient()

        result = await adapter.search("nonexistent", "dc=test", "(objectClass=person)")

        assert not result.is_success
        if "Connection not found" not in (result.error or ""):
            raise AssertionError(f"Expected {"Connection not found"} in {(result.error or "")}")

    @pytest.mark.asyncio
    async def test_search_failed(self) -> None:
        """Test failed LDAP search."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.search.return_value = False
        mock_connection.result = {"description": "Search failed"}

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.search("test_conn", "dc=test", "(objectClass=person)")

        assert not result.is_success
        assert result.error is not None
        if "Search failed" not in result.error:
            raise AssertionError(f"Expected {"Search failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_search_ldap_exception(self) -> None:
        """Test search with LDAP exception."""
        adapter = FlextLdapInfrastructureClient()

        # Mock LDAPException


        mock_connection = MagicMock()
        mock_connection.search.side_effect = LDAPException("Search error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.search("test_conn", "dc=test", "(objectClass=person)")

        assert not result.is_success
        assert result.error is not None
        if "LDAP search failed" not in result.error:
            raise AssertionError(f"Expected {"LDAP search failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_search_unexpected_exception(self) -> None:
        """Test search with unexpected exception."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.search.side_effect = ValueError("Unexpected error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.search("test_conn", "dc=test", "(objectClass=person)")

        assert not result.is_success
        assert result.error is not None
        if "Unexpected search error" not in result.error:
            raise AssertionError(f"Expected {"Unexpected search error"} in {result.error}")

    @pytest.mark.asyncio
    async def test_add_entry_success(self) -> None:
        """Test successful LDAP add entry operation."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.add.return_value = True

        adapter._connections["test_conn"] = mock_connection

        attributes = {
            "cn": ["testuser"],
            "mail": ["test@example.com"],
            "objectClass": ["person"],
        }
        result = await adapter.add_entry("test_conn", "cn=testuser,dc=test", attributes)

        assert result.is_success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

        mock_connection.add.assert_called_once_with(
            "cn=testuser,dc=test",
            attributes=attributes,
        )

    @pytest.mark.asyncio
    async def test_add_entry_connection_not_found(self) -> None:
        """Test add entry with non-existent connection."""
        adapter = FlextLdapInfrastructureClient()

        result = await adapter.add_entry("nonexistent", "cn=test,dc=test", {})

        assert not result.is_success
        if "Connection not found" not in (result.error or ""):
            raise AssertionError(f"Expected {"Connection not found"} in {(result.error or "")}")

    @pytest.mark.asyncio
    async def test_add_entry_failed(self) -> None:
        """Test failed LDAP add entry operation."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.add.return_value = False
        mock_connection.result = {"description": "Add failed"}

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.add_entry("test_conn", "cn=test,dc=test", {})

        assert not result.is_success
        assert result.error is not None
        if "Add failed" not in result.error:
            raise AssertionError(f"Expected {"Add failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_add_ldap_exception(self) -> None:
        """Test add with LDAP exception."""
        adapter = FlextLdapInfrastructureClient()

        # Mock LDAPException


        mock_connection = MagicMock()
        mock_connection.add.side_effect = LDAPException("Add error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.add_entry("test_conn", "cn=test,dc=test", {})

        assert not result.is_success
        assert result.error is not None
        if "LDAP add failed" not in result.error:
            raise AssertionError(f"Expected {"LDAP add failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_add_unexpected_exception(self) -> None:
        """Test add with unexpected exception."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.add.side_effect = ValueError("Unexpected error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.add_entry("test_conn", "cn=test,dc=test", {})

        assert not result.is_success
        assert result.error is not None
        if "Unexpected add error" not in result.error:
            raise AssertionError(f"Expected {"Unexpected add error"} in {result.error}")

    @pytest.mark.asyncio
    async def test_modify_success(self) -> None:
        """Test successful LDAP modify operation."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.modify.return_value = True

        adapter._connections["test_conn"] = mock_connection

        changes = {"mail": [("MODIFY_REPLACE", ["new@example.com"])]}
        result = await adapter.modify_entry("test_conn", "cn=test,dc=test", changes)

        assert result.is_success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

        mock_connection.modify.assert_called_once_with("cn=test,dc=test", changes)

    @pytest.mark.asyncio
    async def test_modify_connection_not_found(self) -> None:
        """Test modify with non-existent connection."""
        adapter = FlextLdapInfrastructureClient()

        result = await adapter.modify_entry("nonexistent", "cn=test,dc=test", {})

        assert not result.is_success
        if "Connection not found" not in (result.error or ""):
            raise AssertionError(f"Expected {"Connection not found"} in {(result.error or "")}")

    @pytest.mark.asyncio
    async def test_modify_failed(self) -> None:
        """Test failed LDAP modify operation."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.modify.return_value = False
        mock_connection.result = {"description": "Modify failed"}

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.modify_entry("test_conn", "cn=test,dc=test", {})

        assert not result.is_success
        assert result.error is not None
        if "Modify failed" not in result.error:
            raise AssertionError(f"Expected {"Modify failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_modify_ldap_exception(self) -> None:
        """Test modify with LDAP exception."""
        adapter = FlextLdapInfrastructureClient()

        # Mock LDAPException


        mock_connection = MagicMock()
        mock_connection.modify.side_effect = LDAPException("Modify error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.modify_entry("test_conn", "cn=test,dc=test", {})

        assert not result.is_success
        assert result.error is not None
        if "LDAP modify failed" not in result.error:
            raise AssertionError(f"Expected {"LDAP modify failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_modify_unexpected_exception(self) -> None:
        """Test modify with unexpected exception."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.modify.side_effect = ValueError("Unexpected error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.modify_entry("test_conn", "cn=test,dc=test", {})

        assert not result.is_success
        assert result.error is not None
        if "Unexpected modify error" not in result.error:
            raise AssertionError(f"Expected {"Unexpected modify error"} in {result.error}")

    @pytest.mark.asyncio
    async def test_delete_success(self) -> None:
        """Test successful LDAP delete operation."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.delete.return_value = True

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.delete_entry("test_conn", "cn=test,dc=test")

        assert result.is_success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

        mock_connection.delete.assert_called_once_with("cn=test,dc=test")

    @pytest.mark.asyncio
    async def test_delete_connection_not_found(self) -> None:
        """Test delete with non-existent connection."""
        adapter = FlextLdapInfrastructureClient()

        result = await adapter.delete_entry("nonexistent", "cn=test,dc=test")

        assert not result.is_success
        if "Connection not found" not in (result.error or ""):
            raise AssertionError(f"Expected {"Connection not found"} in {(result.error or "")}")

    @pytest.mark.asyncio
    async def test_delete_failed(self) -> None:
        """Test failed LDAP delete operation."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.delete.return_value = False
        mock_connection.result = {"description": "Delete failed"}

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.delete_entry("test_conn", "cn=test,dc=test")

        assert not result.is_success
        assert result.error is not None
        if "Delete failed" not in result.error:
            raise AssertionError(f"Expected {"Delete failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_delete_ldap_exception(self) -> None:
        """Test delete with LDAP exception."""
        adapter = FlextLdapInfrastructureClient()

        # Mock LDAPException


        mock_connection = MagicMock()
        mock_connection.delete.side_effect = LDAPException("Delete error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.delete_entry("test_conn", "cn=test,dc=test")

        assert not result.is_success
        assert result.error is not None
        if "LDAP delete failed" not in result.error:
            raise AssertionError(f"Expected {"LDAP delete failed"} in {result.error}")

    @pytest.mark.asyncio
    async def test_delete_unexpected_exception(self) -> None:
        """Test delete with unexpected exception."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.delete.side_effect = ValueError("Unexpected error")

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.delete_entry("test_conn", "cn=test,dc=test")

        assert not result.is_success
        assert result.error is not None
        if "Unexpected delete error" not in result.error:
            raise AssertionError(f"Expected {"Unexpected delete error"} in {result.error}")

    def test_get_connection_info_success(self) -> None:
        """Test successful connection info retrieval."""
        adapter = FlextLdapInfrastructureClient()

        # Setup mock connection with all required attributes
        mock_connection = MagicMock()
        mock_connection.server = MagicMock()
        mock_connection.server.__str__ = lambda x: "ldap://test.com:389"
        mock_connection.bound = True
        mock_connection.user = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test"
        mock_connection.strategy = MagicMock()
        mock_connection.strategy.__str__ = lambda x: "SYNC"

        # Mock server info
        mock_server_info = MagicMock()
        mock_server_info.to_dict.return_value = {"version": "3", "vendor": "OpenLDAP"}
        mock_connection.server.info = mock_server_info

        adapter._connections["test_conn"] = mock_connection

        result = adapter.get_connection_info("test_conn")

        assert result.is_success
        assert result.data is not None
        info = result.data
        if info["server"] != "ldap://test.com:389":
            raise AssertionError(f"Expected {"ldap://test.com:389"}, got {info["server"]}")
        if not (info["bound"]):
            raise AssertionError(f"Expected True, got {info["bound"]}")
        if info["user"] != "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test":
            raise AssertionError(f"Expected {"cn=REDACTED_LDAP_BIND_PASSWORD,dc=test"}, got {info["user"]}")
        assert info["strategy"] == "SYNC"
        if info["server_info"]["version"] != "3":
            raise AssertionError(f"Expected {"3"}, got {info["server_info"]["version"]}")

    def test_get_connection_info_not_found(self) -> None:
        """Test connection info for non-existent connection."""
        adapter = FlextLdapInfrastructureClient()

        result = adapter.get_connection_info("nonexistent")

        assert not result.is_success
        if "Connection not found" not in (result.error or ""):
            raise AssertionError(f"Expected {"Connection not found"} in {(result.error or "")}")

    def test_get_connection_info_no_server_info(self) -> None:
        """Test connection info when server info is None."""
        adapter = FlextLdapInfrastructureClient()

        # Setup mock connection without server info
        mock_connection = MagicMock()
        mock_connection.server = MagicMock()
        mock_connection.server.__str__ = lambda x: "ldap://test.com:389"
        mock_connection.bound = False
        mock_connection.user = None
        mock_connection.strategy = MagicMock()
        mock_connection.strategy.__str__ = lambda x: "SYNC"
        mock_connection.server.info = None

        adapter._connections["test_conn"] = mock_connection

        result = adapter.get_connection_info("test_conn")

        assert result.is_success
        assert result.data is not None
        info = result.data
        assert info["server_info"] is None

    def test_get_connection_info_unexpected_exception(self) -> None:
        """Test connection info with unexpected exception."""
        adapter = FlextLdapInfrastructureClient()

        # Setup mock connection that raises exception when accessed
        mock_connection = MagicMock()
        # Configure __str__ to raise an exception when converting server to string
        mock_connection.server.__str__ = MagicMock(
            side_effect=ValueError("Server error"),
        )

        adapter._connections["test_conn"] = mock_connection

        result = adapter.get_connection_info("test_conn")

        assert not result.is_success
        assert result.error is not None
        if "Unexpected error getting connection info" not in result.error:
            raise AssertionError(f"Expected {"Unexpected error getting connection info"} in {result.error}")

    def test_search_scope_mapping(self) -> None:
        """Test search scope string to ldap3 constant mapping."""
        adapter = FlextLdapInfrastructureClient()

        # Test through the actual search method
        mock_connection = MagicMock()
        mock_connection.search.return_value = True
        mock_connection.entries = []
        adapter._connections["test_conn"] = mock_connection

        # Test each scope mapping


        # Test subtree scope (default)
        asyncio.run(
            adapter.search("test_conn", "dc=test", "(objectClass=*)", scope="subtree"),
        )
        # Test onelevel scope
        asyncio.run(
            adapter.search("test_conn", "dc=test", "(objectClass=*)", scope="onelevel"),
        )
        # Test base scope
        asyncio.run(
            adapter.search("test_conn", "dc=test", "(objectClass=*)", scope="base"),
        )
        # Test invalid scope (should default to subtree)
        asyncio.run(
            adapter.search("test_conn", "dc=test", "(objectClass=*)", scope="invalid"),
        )

        # All calls should succeed
        if mock_connection.search.call_count != 4:
            raise AssertionError(f"Expected {4}, got {mock_connection.search.call_count}")

    @pytest.mark.asyncio
    async def test_search_with_default_attributes(self) -> None:
        """Test search with default attributes (*)."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.search.return_value = True
        mock_connection.entries = []

        adapter._connections["test_conn"] = mock_connection

        result = await adapter.search("test_conn", "dc=test", "(objectClass=person)")

        assert result.is_success
        # Verify default attributes are used
        call_args = mock_connection.search.call_args
        if call_args[1]["attributes"] != ["*"]:
            raise AssertionError(f"Expected {["*"]}, got {call_args[1]["attributes"]}")

    @pytest.mark.asyncio
    async def test_add_entry_with_complex_attributes(self) -> None:
        """Test add entry with complex attribute structure."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.add.return_value = True

        adapter._connections["test_conn"] = mock_connection

        # Complex attributes with multiple values
        attributes = {
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "givenName": ["John"],
            "mail": ["john.doe@example.com", "jdoe@example.com"],
            "telephoneNumber": ["+1-555-123-4567", "+1-555-987-6543"],
        }

        result = await adapter.add_entry(
            "test_conn",
            "cn=John Doe,ou=people,dc=example,dc=com",
            attributes,
        )

        assert result.is_success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

        mock_connection.add.assert_called_once_with(
            "cn=John Doe,ou=people,dc=example,dc=com",
            attributes=attributes,
        )

    @pytest.mark.asyncio
    async def test_modify_entry_with_complex_changes(self) -> None:
        """Test modify entry with complex change operations."""
        adapter = FlextLdapInfrastructureClient()

        mock_connection = MagicMock()
        mock_connection.modify.return_value = True

        adapter._connections["test_conn"] = mock_connection

        # Complex changes with different operations
        changes = {
            "mail": [("MODIFY_REPLACE", ["newemail@example.com"])],
            "telephoneNumber": [("MODIFY_ADD", ["+1-555-111-2222"])],
            "description": [("MODIFY_DELETE", [])],
            "title": [("MODIFY_REPLACE", ["Senior Developer"])],
        }

        result = await adapter.modify_entry(
            "test_conn",
            "cn=John Doe,ou=people,dc=example,dc=com",
            changes,
        )

        assert result.is_success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

        mock_connection.modify.assert_called_once_with(
            "cn=John Doe,ou=people,dc=example,dc=com",
            changes,
        )
