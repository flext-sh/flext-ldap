"""Tests for modern CLI interface using flext-cli patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from flext_core import FlextResult
from flext_ldap.cli import (
    LDAPConnectionHandler,
    LDAPSearchHandler,
    LDAPUserHandler,
    cli,
)
from flext_ldap.values import ExtendedLDAPEntry


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

    @patch("flext_ldap.cli.setup_cli")
    def test_main_function_success(self, mock_setup_cli: MagicMock) -> None:
        """Test main function with successful setup."""
        mock_setup_cli.return_value = FlextResult.ok(True)

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

    @pytest.mark.asyncio
    async def test_test_connection_success(self) -> None:
        """Test successful connection test."""
        with patch("flext_ldap.cli.FlextLdapClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            mock_client.connect = AsyncMock(return_value=FlextResult.ok(True))
            mock_client.disconnect = AsyncMock(return_value=FlextResult.ok(True))

            result = await LDAPConnectionHandler.test_connection("ldap.example.com", 389)

            assert result.is_success
            assert "Successfully connected to ldap://ldap.example.com:389" in result.data

    @pytest.mark.asyncio
    async def test_test_connection_failure(self) -> None:
        """Test connection test failure."""
        with patch("flext_ldap.cli.FlextLdapClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            mock_client.connect = AsyncMock(return_value=FlextResult.fail("Connection refused"))

            result = await LDAPConnectionHandler.test_connection("invalid.example.com", 389)

            assert result.is_failure
            assert "Connection failed" in result.error


class TestLDAPSearchHandler:
    """Test suite for LDAP search handler."""

    @pytest.mark.asyncio
    async def test_search_entries_success(self) -> None:
        """Test successful search entries."""
        mock_entries = [
            ExtendedLDAPEntry(
                dn="cn=user1,dc=example,dc=com",
                attributes={"cn": ["user1"], "objectClass": ["person"]}
            )
        ]

        with patch("flext_ldap.cli.FlextLdapClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            mock_client.connect = AsyncMock(return_value=FlextResult.ok(True))
            mock_client.search = AsyncMock(return_value=FlextResult.ok(mock_entries))
            mock_client.disconnect = AsyncMock(return_value=FlextResult.ok(True))

            from flext_ldap.cli import LDAPSearchParams
            params = LDAPSearchParams(
                server="ldap.example.com",
                base_dn="dc=example,dc=com"
            )
            result = await LDAPSearchHandler.search_entries(params)

            assert result.is_success
            assert len(result.data) == 1
            assert result.data[0].dn == "cn=user1,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_search_entries_connection_failure(self) -> None:
        """Test search entries with connection failure."""
        with patch("flext_ldap.cli.FlextLdapClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            mock_client.connect = AsyncMock(return_value=FlextResult.fail("Connection failed"))

            from flext_ldap.cli import LDAPSearchParams
            params = LDAPSearchParams(
                server="invalid.example.com",
                base_dn="dc=example,dc=com"
            )
            result = await LDAPSearchHandler.search_entries(params)

            assert result.is_failure
            assert "Connection failed" in result.error


class TestLDAPUserHandler:
    """Test suite for LDAP user handler."""

    @pytest.mark.asyncio
    async def test_get_user_info_success(self) -> None:
        """Test successful user info retrieval."""
        from flext_ldap.entities import FlextLdapUser

        mock_user = FlextLdapUser(
            id="123",
            dn="cn=john,dc=example,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe"
        )

        with patch("flext_ldap.cli.FlextLdapService") as mock_service_class:
            mock_service = mock_service_class.return_value
            mock_service.find_user_by_uid = AsyncMock(return_value=FlextResult.ok(mock_user))

            result = await LDAPUserHandler.get_user_info("john")

            assert result.is_success
            assert result.data.uid == "john"
            assert result.data.cn == "John Doe"

    @pytest.mark.asyncio
    async def test_get_user_info_not_found(self) -> None:
        """Test user info when user not found."""
        with patch("flext_ldap.cli.FlextLdapService") as mock_service_class:
            mock_service = mock_service_class.return_value
            mock_service.find_user_by_uid = AsyncMock(return_value=FlextResult.fail("User not found"))

            result = await LDAPUserHandler.get_user_info("nonexistent")

            assert result.is_failure
            assert "User not found: nonexistent" in result.error

    @pytest.mark.asyncio
    async def test_create_user_success(self) -> None:
        """Test successful user creation."""
        from flext_ldap.entities import FlextLdapUser

        mock_user = FlextLdapUser(
            id="123",
            dn="cn=john,ou=users,dc=example,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe"
        )

        with patch("flext_ldap.cli.FlextLdapService") as mock_service_class:
            mock_service = mock_service_class.return_value
            mock_service.create_user = AsyncMock(return_value=FlextResult.ok(mock_user))

            from flext_ldap.cli import LDAPUserParams
            params = LDAPUserParams(
                uid="john",
                cn="John Doe",
                sn="Doe"
            )
            result = await LDAPUserHandler.create_user(params)

            assert result.is_success
            assert result.data.uid == "john"
            assert result.data.cn == "John Doe"

    @pytest.mark.asyncio
    async def test_list_users_success(self) -> None:
        """Test successful user listing."""
        from flext_ldap.entities import FlextLdapUser

        mock_users = [
            FlextLdapUser(id="1", dn="cn=john,dc=example,dc=com", uid="john", cn="John Doe", sn="Doe"),
            FlextLdapUser(id="2", dn="cn=jane,dc=example,dc=com", uid="jane", cn="Jane Smith", sn="Smith")
        ]

        with patch("flext_ldap.cli.FlextLdapService") as mock_service_class:
            mock_service = mock_service_class.return_value
            mock_service.list_users = AsyncMock(return_value=FlextResult.ok(mock_users))

            result = await LDAPUserHandler.list_users()

            assert result.is_success
            assert len(result.data) == 2
            assert result.data[0].uid == "john"
            assert result.data[1].uid == "jane"
