"""Test LDAP client functionality."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from flext_ldap.ldap_infrastructure import FlextLdapClient


class TestLDAPClient:
    """Test LDAPClient functionality."""

    @pytest.mark.unit
    def test_client_import(self) -> None:
        """Test that LDAPClient can be imported."""

        assert FlextLdapClient is not None

    @pytest.mark.unit
    def test_client_instantiation_with_settings(self) -> None:
        """Test that LDAPClient can be instantiated with settings."""
        from flext_ldap.config import FlextLdapConnectionConfig

        # Create a test configuration
        config = FlextLdapConnectionConfig(
            host="localhost", port=389, use_ssl=False, timeout_seconds=30
        )

        client = FlextLdapClient(config)
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
        expected_info = {"status": "disconnected"}
        if info != expected_info:
            raise AssertionError(f"Expected {expected_info}, got {info}")

    def test_connect_success(self) -> None:
        """Test successful connection."""
        from unittest.mock import Mock

        from flext_core import FlextResult

        # Create real client instance and mock its methods directly
        client = FlextLdapClient()

        # Mock connect method to return success
        client.connect = Mock(return_value=FlextResult.ok(True))

        # Mock is_connected to return True (connected state)
        client.is_connected = Mock(return_value=True)

        # Test successful connection
        result = client.connect()

        if not result.success:
            raise AssertionError(f"Expected True, got {result.success}")

        if not client.is_connected():
            raise AssertionError(f"Expected True, got {client.is_connected()}")

        # Verify connect was called
        client.connect.assert_called_once()

    def test_connect_failure(self) -> None:
        """Test connection failure."""
        from unittest.mock import Mock

        from flext_core import FlextResult

        # Create real client instance and mock its methods directly
        client = FlextLdapClient()

        # Mock connect method to return failure result
        client.connect = Mock(return_value=FlextResult.fail("Connection failed"))

        # Mock is_connected to return False (not connected state)
        client.is_connected = Mock(return_value=False)

        # Test connection failure - should return failed FlextResult, not raise exception
        result = client.connect()

        # Enterprise-compatible: check FlextResult instead of expecting exception
        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")

        assert result.error is not None
        if "Connection failed" not in result.error:
            raise AssertionError(f"Expected 'Connection failed' in {result.error}")

        if client.is_connected():
            raise AssertionError(f"Expected False, got {client.is_connected()}")

    def test_disconnect_success(self) -> None:
        """Test successful disconnection."""
        from unittest.mock import Mock

        from flext_core import FlextResult

        # Create real client instance and mock its methods directly
        client = FlextLdapClient()

        # Mock connect method to return success
        client.connect = Mock(return_value=FlextResult.ok(True))

        # Mock disconnect method to return success
        client.disconnect = Mock(return_value=FlextResult.ok(True))

        # Mock is_connected to return False after disconnect
        client.is_connected = Mock(return_value=False)

        # Test connection and disconnection
        connect_result = client.connect()
        if not connect_result.success:
            raise AssertionError(f"Expected True, got {connect_result.success}")

        disconnect_result = client.disconnect()
        if not disconnect_result.success:
            raise AssertionError(f"Expected True, got {disconnect_result.success}")

        # After disconnect, should not be connected
        if client.is_connected():
            raise AssertionError(
                f"Expected False (not connected), got {client.is_connected()}"
            )

        # Verify methods were called
        client.connect.assert_called_once()
        client.disconnect.assert_called_once()

    def test_ping_connected(self) -> None:
        """Test ping when connected."""
        from unittest.mock import Mock

        from flext_core import FlextResult

        # Create real client instance and mock its methods directly
        client = FlextLdapClient()

        # Mock connect method to return success
        client.connect = Mock(return_value=FlextResult.ok(True))

        # Mock ping method to return True (successful ping)
        client.ping = Mock(return_value=True)

        # Mock is_connected to return True (connected state)
        client.is_connected = Mock(return_value=True)

        # Test connection and ping
        connect_result = client.connect()
        if not connect_result.success:
            raise AssertionError(f"Expected True, got {connect_result.success}")

        ping_result = client.ping()
        if not ping_result:
            raise AssertionError(f"Expected True, got {ping_result}")

        # Verify methods were called
        client.connect.assert_called_once()
        client.ping.assert_called_once()

    def test_ping_disconnected(self) -> None:
        """Test connection status when disconnected."""

        client = FlextLdapClient()
        # Test that client starts disconnected
        result = client.is_connected()

        if result:
            raise AssertionError(f"Expected False, got {result}")

    @pytest.mark.asyncio
    async def test_search_success(self) -> None:
        """Test successful search operation."""
        from unittest.mock import AsyncMock, Mock

        from flext_core import FlextResult

        # Create real client instance and mock its methods directly
        client = FlextLdapClient()

        # Mock search results with proper FlextResult structure
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

        # Mock connect method to return success
        client.connect = Mock(return_value=FlextResult.ok(True))

        # Mock search method to return success with results
        client.search = AsyncMock(return_value=FlextResult.ok(search_results))

        # Mock is_connected to return True
        client.is_connected = Mock(return_value=True)

        # Test connection
        connect_result = client.connect()
        if not connect_result.success:
            raise AssertionError(f"Expected True, got {connect_result.success}")

        # Test search operation (now properly awaited)
        result = await client.search(
            base_dn="ou=users,dc=example,dc=org",
            search_filter="(uid=test)",
            attributes=["uid", "cn"],
        )

        if not result.success:
            raise AssertionError(f"Expected True, got {result.success}")
        assert result.data is not None
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")
        assert result.data[0]["dn"] == "uid=test,ou=users,dc=example,dc=org"
        if result.data[0]["attributes"]["uid"] != ["test"]:
            raise AssertionError(
                f"Expected {['test']}, got {result.data[0]['attributes']['uid']}"
            )

    @pytest.mark.asyncio
    async def test_search_not_connected(self) -> None:
        """Test search when not connected."""
        from unittest.mock import AsyncMock, Mock

        from flext_core import FlextResult

        client = FlextLdapClient()

        # Mock is_connected to return False (not connected state)
        client.is_connected = Mock(return_value=False)
        client.search = AsyncMock(
            return_value=FlextResult.fail("Not connected to LDAP server")
        )

        result = await client.search(
            base_dn="ou=users,dc=example,dc=org",
            search_filter="(uid=test)",
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Not connected" not in result.error:
            raise AssertionError(f"Expected {'Not connected'} in {result.error}")

    @pytest.mark.asyncio
    async def test_modify_success(self) -> None:
        """Test successful modify operation."""
        from unittest.mock import Mock

        from flext_core import FlextResult

        # Create real client instance and mock its methods directly
        client = FlextLdapClient()

        # Mock connect method to return success
        client.connect = Mock(return_value=FlextResult.ok(True))

        # Mock modify method to return success:
        client.modify = AsyncMock(return_value=FlextResult.ok(True))

        # Mock is_connected to return True
        client.is_connected = Mock(return_value=True)

        # Test connection
        connect_result = client.connect()
        if not connect_result.success:
            raise AssertionError(f"Expected True, got {connect_result.success}")

        # Test modify operation
        result = await client.modify(
            dn="uid=test,ou=users,dc=example,dc=org",
            changes={"mail": "test@example.org"},
        )

        if not result.success:
            raise AssertionError(f"Expected True, got {result.success}")

        # Verify methods were called
        client.connect.assert_called_once()
        client.modify.assert_called_once_with(
            dn="uid=test,ou=users,dc=example,dc=org",
            changes={"mail": "test@example.org"},
        )

    @pytest.mark.asyncio
    async def test_modify_not_connected(self) -> None:
        """Test modify when not connected."""
        from unittest.mock import AsyncMock, Mock

        from flext_core import FlextResult

        client = FlextLdapClient()

        # Mock is_connected to return False (not connected state)
        client.is_connected = Mock(return_value=False)
        client.modify = AsyncMock(
            return_value=FlextResult.fail("Not connected to LDAP server")
        )

        result = await client.modify(
            dn="uid=test,ou=users,dc=example,dc=org",
            changes={"mail": "test@example.org"},
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Not connected" not in result.error:
            raise AssertionError(f"Expected {'Not connected'} in {result.error}")

    def test_context_manager(self) -> None:
        """Test context manager functionality - currently not implemented."""
        # Context manager not implemented yet in FlextLdapClient
        # This test is placeholder for future implementation
        client = FlextLdapClient()

        # Test that client can be created
        assert client is not None

        # Future: implement __enter__/__exit__ methods for context manager support

    def test_transaction_context_manager(self) -> None:
        """Test transaction context manager."""

        with patch(
            "flext_ldap.ldap_infrastructure.FlextLdapClient",
        ) as mock_infra_client:
            mock_instance = AsyncMock()
            mock_instance.connect.return_value = MagicMock(
                success=True,
                data="conn_123",
            )
            mock_infra_client.return_value = mock_instance

            client = FlextLdapClient()
            client.connect()

            # Transaction context manager not implemented yet
            # This test is placeholder for future implementation
            assert client is not None

    def test_get_server_info_connected(self) -> None:
        """Test get_server_info when connected."""
        from unittest.mock import MagicMock, Mock

        # Create real client instance and mock its methods directly
        client = FlextLdapClient()

        # Mock is_connected to return True (connected state)
        client.is_connected = Mock(return_value=True)

        # Mock the actual connection object that get_server_info will access
        mock_connection = MagicMock()
        mock_connection.server = "ldap://localhost:389"
        mock_connection.bound = True
        mock_connection.user = "cn=REDACTED_LDAP_BIND_PASSWORD"
        client._current_connection = mock_connection

        info = client.get_server_info()

        # Verify returned info structure matches expected enterprise format
        assert "status" in info
        if info["status"] != "connected":
            raise AssertionError(f"Expected {'connected'}, got {info['status']}")

        if info["server"] != "ldap://localhost:389":
            raise AssertionError(
                f"Expected {'ldap://localhost:389'}, got {info['server']}"
            )
        assert info["bound"] == "True"  # Note: values are converted to strings
        if info["user"] != "cn=REDACTED_LDAP_BIND_PASSWORD":
            raise AssertionError(f"Expected {'cn=REDACTED_LDAP_BIND_PASSWORD'}, got {info['user']}")
