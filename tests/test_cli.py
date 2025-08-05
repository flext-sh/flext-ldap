"""Tests for modern CLI interface using flext-cli patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from click.testing import CliRunner
from flext_core import FlextResult

from flext_ldap.cli import (
    LDAPConnectionHandler,
    LDAPConnectionTestParams,
    LDAPSearchHandler,
    LDAPUserHandler,
    cli,
)


# FBT smell elimination constants for tests - SOLID DRY Principle
class TestConnectionResult:
    """Test connection result constants - eliminates FBT003 positional booleans."""

    SUCCESS = True
    FAILURE = False


class TestOperationResult:
    """Test operation result constants - eliminates FBT003 positional booleans."""

    SUCCESS = True
    FAILURE = False


class TestCLI:
    """Test suite for modern CLI functionality with flext-cli patterns."""

    def test_cli_version_option(self) -> None:
        """Test CLI version option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "0.9.0" in result.output

    def test_cli_help_option(self) -> None:
        """Test CLI help option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "FLEXT LDAP - Enterprise LDAP Operations" in result.output
        assert "test" in result.output
        assert "search" in result.output
        assert "user-info" in result.output
        assert "create-user" in result.output
        assert "list-users" in result.output

    def test_version_command(self) -> None:
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])

        assert result.exit_code == 0
        assert "FLEXT LDAP v0.9.0" in result.output

    def test_main_function_success(self) -> None:
        """Test main function calls cli."""
        with patch("flext_ldap.cli.cli") as mock_cli:
            from flext_ldap.cli import main

            main()
            mock_cli.assert_called_once()

    def test_missing_arguments(self) -> None:
        """Test commands with missing arguments."""
        runner = CliRunner()

        # Test command needs server argument
        result = runner.invoke(cli, ["test"])
        assert result.exit_code == 2
        assert "Missing argument" in result.output

        # Search command needs server and base_dn arguments
        result = runner.invoke(cli, ["search"])
        assert result.exit_code == 2
        assert "Missing argument" in result.output


class TestLDAPConnectionHandler:
    """Test suite for LDAP connection handler."""

    def test_test_connection_success(self) -> None:
        """Test successful connection test."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS methods
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.is_connected.return_value = TestConnectionResult.SUCCESS

            params = LDAPConnectionTestParams(server="ldap.example.com", port=389)
            result = LDAPConnectionHandler.test_connection(params)

            assert result.success
            assert (
                "Successfully connected to ldap://ldap.example.com:389" in result.data
            )

    def test_test_connection_failure(self) -> None:
        """Test connection test failure."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect is SYNCHRONOUS method
            mock_client.connect.return_value = FlextResult.fail("Connection refused")

            params = LDAPConnectionTestParams(server="invalid.example.com", port=389)
            result = LDAPConnectionHandler.test_connection(params)

            assert result.is_failure
            assert "Connection failed" in result.error


class TestLDAPSearchHandler:
    """Test suite for LDAP search handler."""

    def test_search_entries_success(self) -> None:
        """Test successful search entries."""
        mock_entries = [
            {
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {"cn": ["user1"], "objectClass": ["person"]},
            }
        ]

        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(return_value=FlextResult.ok(mock_entries))
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            from flext_ldap.cli import LDAPSearchParams

            params = LDAPSearchParams(
                server="ldap.example.com", base_dn="dc=example,dc=com"
            )
            result = LDAPSearchHandler.search_entries(params)

            assert result.success
            assert len(result.data) == 1
            assert result.data[0].dn == "cn=user1,dc=example,dc=com"

    def test_search_entries_connection_failure(self) -> None:
        """Test search entries with connection failure."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect is SYNCHRONOUS method
            mock_client.connect.return_value = FlextResult.fail("Connection failed")

            from flext_ldap.cli import LDAPSearchParams

            params = LDAPSearchParams(
                server="invalid.example.com", base_dn="dc=example,dc=com"
            )
            result = LDAPSearchHandler.search_entries(params)

            assert result.is_failure
            assert "Connection failed" in result.error


class TestLDAPUserHandler:
    """Test suite for LDAP user handler."""

    def test_get_user_info_success(self) -> None:
        """Test successful user info retrieval."""
        mock_user_data = {
            "dn": "cn=john,dc=example,dc=com",
            "attributes": {"uid": ["john"], "cn": ["John Doe"], "sn": ["Doe"]},
        }

        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(
                return_value=FlextResult.ok([mock_user_data])
            )
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            result = LDAPUserHandler.get_user_info("john")

            assert result.success
            assert result.data["attributes"]["uid"] == ["john"]

    def test_get_user_info_not_found(self) -> None:
        """Test user info when user not found."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(
                return_value=FlextResult.ok([])
            )  # Empty results
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            result = LDAPUserHandler.get_user_info("nonexistent")

            assert result.is_failure
            assert "User nonexistent not found" in result.error

    def test_create_user_success(self) -> None:
        """Test successful user creation."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, add is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.add = AsyncMock(
                return_value=FlextResult.ok(TestOperationResult.SUCCESS)
            )
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            from flext_ldap.cli import LDAPUserParams

            params = LDAPUserParams(uid="john", cn="John Doe", sn="Doe")
            result = LDAPUserHandler.create_user(params)

            assert result.success
            assert result.data["uid"] == "john"
            assert result.data["cn"] == "John Doe"

    def test_list_users_success(self) -> None:
        """Test successful user listing."""
        mock_users = [
            {
                "dn": "cn=john,dc=example,dc=com",
                "attributes": {"uid": ["john"], "cn": ["John Doe"], "sn": ["Doe"]},
            },
            {
                "dn": "cn=jane,dc=example,dc=com",
                "attributes": {"uid": ["jane"], "cn": ["Jane Smith"], "sn": ["Smith"]},
            },
        ]

        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(return_value=FlextResult.ok(mock_users))
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            result = LDAPUserHandler.list_users()

            assert result.success
            assert len(result.data) == 2
