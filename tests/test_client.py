"""Test LDAP client functionality."""

from flext_ldap.client import FlextLdapClient
from flext_ldap.client import FlextLdapClient
from flext_ldap.client import FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextConnectionError, FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextLdapClient
from flext_ldap.client import FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextLdapClient
from flext_ldap.client import FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextLdapClient
from flext_ldap.client import FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextLdapClient
from unittest.mock import AsyncMock, MagicMock, patch
from flext_ldap.client import FlextLdapClient
from unittest.mock import MagicMock, patch
from flext_ldap.client import FlextLdapClient


from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from flext_ldap.config import FlextLdapSettings


class TestLDAPClient:
    """Test LDAPClient functionality."""

    @pytest.mark.unit
    def test_client_import(self) -> None:
        """Test that LDAPClient can be imported."""


        assert FlextLdapClient is not None

    @pytest.mark.unit
    def test_client_instantiation_with_settings(
        self,
        ldap_settings: FlextLdapSettings,
    ) -> None:
        """Test that LDAPClient can be instantiated with settings."""
        from flext_ldap.client import FlextLdapClient

        # ldap_settings fixture returns FlextLDAPSettings instance
        client = FlextLdapClient(ldap_settings)
        assert client is not None
        assert not client.is_connected()

    @pytest.mark.unit
    def test_client_instantiation_without_config(self) -> None:
        """Test that LDAPClient can be instantiated without config."""


        client = FlextLdapClient()
        assert client is not None
        assert not client.is_connected()

    @pytest.mark.unit
    def test_get_server_info_disconnected(self) -> None:
        """Test get_server_info when disconnected."""


        client = FlextLdapClient()
        info = client.get_server_info()
        if info != {"status": "disconnected"}:
            raise AssertionError(f"Expected {{"status": "disconnected"}}, got {info}")

    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Test successful connection."""




        # Mock the infrastructure client
        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            await client.connect()

            if not (client.is_connected()):

                raise AssertionError(f"Expected True, got {client.is_connected()}")
            mock_instance.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_failure(self) -> None:
        """Test connection failure."""




        # Mock the infrastructure client to return failure
        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=False,
                error="Connection failed",
            )
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()

            with pytest.raises(FlextConnectionError, match="Connection failed"):
                await client.connect()

            if client.is_connected():

                raise AssertionError(f"Expected False, got {client.is_connected()}")

    @pytest.mark.asyncio
    async def test_disconnect_success(self) -> None:
        """Test successful disconnection."""




        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_instance.disconnect.return_value = MagicMock(success=True, data=True)
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            await client.connect()
            await client.disconnect()

            if client.is_connected():

                raise AssertionError(f"Expected False, got {client.is_connected()}")
            mock_instance.disconnect.assert_called_once_with("conn_123")

    @pytest.mark.asyncio
    async def test_ping_connected(self) -> None:
        """Test ping when connected."""




        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_instance.search.return_value = MagicMock(success=True, data=[])
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            await client.connect()
            result = await client.ping()

            if not (result):

                raise AssertionError(f"Expected True, got {result}")

    @pytest.mark.asyncio
    async def test_ping_disconnected(self) -> None:
        """Test ping when disconnected."""


        client = FlextLdapClient()
        result = await client.ping()

        if result:

            raise AssertionError(f"Expected False, got {result}")

    @pytest.mark.asyncio
    async def test_search_success(self) -> None:
        """Test successful search operation."""




        # Mock search results
        search_results = [
            {
                "dn": "uid=test,ou=users,dc=example,dc=org",
                "attributes": {
                    "uid": ["test"],
                    "cn": ["Test User"],
                    "objectClass": ["inetOrgPerson"],
                },
            },
        ]

        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_instance.search.return_value = MagicMock(
                success=True,
                data=search_results,
            )
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            await client.connect()

            result = await client.search(
                base_dn="ou=users,dc=example,dc=org",
                search_filter="(uid=test)",
                attributes=["uid", "cn"],
            )

            if not (result.is_success):

                raise AssertionError(f"Expected True, got {result.is_success}")
            assert result.data is not None
            if len(result.data) != 1:
                raise AssertionError(f"Expected {1}, got {len(result.data)}")
            assert result.data[0].dn == "uid=test,ou=users,dc=example,dc=org"
            if result.data[0].attributes["uid"] != ["test"]:
                raise AssertionError(f"Expected {["test"]}, got {result.data[0].attributes["uid"]}")

    @pytest.mark.asyncio
    async def test_search_not_connected(self) -> None:
        """Test search when not connected."""


        client = FlextLdapClient()

        result = await client.search(
            base_dn="ou=users,dc=example,dc=org",
            search_filter="(uid=test)",
        )

        if result.is_success:

            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Not connected" not in result.error:
            raise AssertionError(f"Expected {"Not connected"} in {result.error}")

    @pytest.mark.asyncio
    async def test_modify_success(self) -> None:
        """Test successful modify operation."""




        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_instance.modify_entry.return_value = MagicMock(success=True, data=True)
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            await client.connect()

            result = await client.modify(
                dn="uid=test,ou=users,dc=example,dc=org",
                changes={"mail": "test@example.org"},
            )

            if not (result.is_success):

                raise AssertionError(f"Expected True, got {result.is_success}")
            mock_instance.modify_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_modify_not_connected(self) -> None:
        """Test modify when not connected."""


        client = FlextLdapClient()

        result = await client.modify(
            dn="uid=test,ou=users,dc=example,dc=org",
            changes={"mail": "test@example.org"},
        )

        if result.is_success:

            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Not connected" not in result.error:
            raise AssertionError(f"Expected {"Not connected"} in {result.error}")

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Test async context manager functionality."""




        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_instance.disconnect.return_value = MagicMock(success=True, data=True)
            mock_infra_client.return_value = mock_instance

            async with FlextLdapClient() as client:
                if not (client.is_connected()):
                    raise AssertionError(f"Expected True, got {client.is_connected()}")

            # After exiting context, should be disconnected
            if client.is_connected():
                raise AssertionError(f"Expected False, got {client.is_connected()}")

    @pytest.mark.asyncio
    async def test_transaction_context_manager(self) -> None:
        """Test transaction context manager."""




        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            await client.connect()

            async with client.transaction() as tx_client:
                assert tx_client is client
                if not (client.is_connected()):
                    raise AssertionError(f"Expected True, got {client.is_connected()}")

    def test_get_server_info_connected(self) -> None:
        """Test get_server_info when connected."""




        with patch(
            "flext_ldap.client.FlextLdapInfrastructureClient",
        ) as mock_infra_client:
            mock_instance = MagicMock()
            mock_instance.get_connection_info.return_value = MagicMock(
                success=True,
                data={
                    "server": "ldap://localhost:389",
                    "bound": True,
                    "user": "cn=REDACTED_LDAP_BIND_PASSWORD",
                },
            )
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            client._connection_id = "conn_123"  # Simulate connected state
            client._connected = True  # Also need to set connected flag

            info = client.get_server_info()

            if info["server"] != "ldap://localhost:389":

                raise AssertionError(f"Expected {"ldap://localhost:389"}, got {info["server"]}")
            assert info["bound"] == "True"  # Note: values are converted to strings
            if info["user"] != "cn=REDACTED_LDAP_BIND_PASSWORD":
                raise AssertionError(f"Expected {"cn=REDACTED_LDAP_BIND_PASSWORD"}, got {info["user"]}")
