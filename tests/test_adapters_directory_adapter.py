"""Tests for LDAP directory adapter in FLEXT-LDAP."""

from typing import cast
from unittest.mock import AsyncMock, patch

import pytest
from flext_core import FlextResult

# Constants
EXPECTED_DATA_COUNT = 3


# FBT smell elimination constants - SOLID DRY Principle
class TestOperationResult:
    """Test operation result constants - eliminates FBT003 positional booleans."""
    SUCCESS = True
    FAILURE = False


from flext_ldap.adapters.directory_adapter import (
    FlextLdapDirectoryAdapter,
    FlextLdapDirectoryAdapterInterface,
    FlextLdapDirectoryConnectionProtocol,
    FlextLdapDirectoryEntryProtocol,
    FlextLdapDirectoryService,
    FlextLdapDirectoryServiceInterface,
)


class TestFlextLdapDirectoryConnectionProtocol:
    """Test directory connection protocol."""

    def test_protocol_attributes(self) -> None:
        """Test protocol has required attributes."""

        # Create a simple class that implements the protocol
        class TestConnection:
            def __init__(self) -> None:
                self.host = "localhost"
                self.port = 389

        connection = TestConnection()

        # Test protocol compliance
        protocol_connection = cast("FlextLdapDirectoryConnectionProtocol", connection)
        if protocol_connection.host != "localhost":
            raise AssertionError(
                f"Expected {'localhost'}, got {protocol_connection.host}"
            )
        assert protocol_connection.port == 389


class TestFlextLdapDirectoryEntryProtocol:
    """Test directory entry protocol."""

    def test_protocol_attributes(self) -> None:
        """Test protocol has required attributes."""

        # Create a simple class that implements the protocol
        class TestEntry:
            def __init__(self) -> None:
                self.dn = "cn=test,dc=example,dc=org"
                self.attributes = {"uid": ["test"], "cn": ["Test User"]}

        entry = TestEntry()

        # Test protocol compliance
        protocol_entry = cast("FlextLdapDirectoryEntryProtocol", entry)
        if protocol_entry.dn != "cn=test,dc=example,dc=org":
            raise AssertionError(
                f"Expected {'cn=test,dc=example,dc=org'}, got {protocol_entry.dn}"
            )
        assert protocol_entry.attributes == {"uid": ["test"], "cn": ["Test User"]}


class TestFlextLdapDirectoryServiceInterface:
    """Test directory service interface."""

    def test_is_abstract(self) -> None:
        """Test that directory service interface is abstract."""
        with pytest.raises(TypeError):
            FlextLdapDirectoryServiceInterface()


class TestFlextLdapDirectoryAdapterInterface:
    """Test directory adapter interface."""

    def test_is_abstract(self) -> None:
        """Test that directory adapter interface is abstract."""
        with pytest.raises(TypeError):
            FlextLdapDirectoryAdapterInterface()


class TestFlextLdapDirectoryService:
    """Test FlextLdapDirectoryService."""

    @pytest.fixture
    def directory_service(self) -> FlextLdapDirectoryService:
        """Create directory service instance."""
        return FlextLdapDirectoryService()

    def test_initialization(self, directory_service: FlextLdapDirectoryService) -> None:
        """Test directory service initialization."""
        assert directory_service._ldap_client is not None
        assert hasattr(directory_service._ldap_client, "connect")

    async def test_connect_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful connection."""
        result = await directory_service.connect()

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is True

    async def test_connect_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test connection with exception."""
        # Force an exception by mocking the FlextResult.ok method
        with patch("flext_ldap.adapters.directory_adapter.FlextResult.ok") as mock_ok:
            mock_ok.side_effect = Exception("Connection failed")

            result = await directory_service.connect()

            if result.is_success:
                raise AssertionError(f"Expected False, got {result.is_success}")
            assert result.error is not None
            if "Connection error" not in result.error:
                raise AssertionError(f"Expected {'Connection error'} in {result.error}")

    async def test_search_users_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful user search."""
        filter_criteria = {"uid": "testuser"}

        result = await directory_service.search_users(filter_criteria)

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is not None
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")
        assert result.data[0].dn == "cn=user,dc=example,dc=com"
        expected_attrs = {"uid": "user"}
        if result.data[0].attributes != expected_attrs:
            raise AssertionError(
                f"Expected {expected_attrs}, got {result.data[0].attributes}"
            )

    async def test_search_users_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test user search with exception."""
        # Force an exception by mocking the FlextResult.ok method
        with patch("flext_ldap.adapters.directory_adapter.FlextResult.ok") as mock_ok:
            mock_ok.side_effect = Exception("Search failed")

            result = await directory_service.search_users({"uid": "test"})

            if result.is_success:
                raise AssertionError(f"Expected False, got {result.is_success}")
            assert result.error is not None
            if "Search error" not in result.error:
                raise AssertionError(f"Expected {'Search error'} in {result.error}")

    async def test_disconnect_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful disconnection."""
        connection_id = "test_connection"

        # Mock the ldap_client.disconnect method
        directory_service._ldap_client.disconnect = AsyncMock(
            return_value=FlextResult.ok(TestOperationResult.SUCCESS),
        )

        result = await directory_service.disconnect(connection_id)

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is True
        directory_service._ldap_client.disconnect.assert_called_once_with(connection_id)

    async def test_disconnect_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test disconnection with exception."""
        connection_id = "test_connection"

        # Mock the ldap_client.disconnect method to raise exception
        directory_service._ldap_client.disconnect = AsyncMock(
            side_effect=Exception("Disconnect failed"),
        )

        result = await directory_service.disconnect(connection_id)

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Disconnect error" not in result.error:
            raise AssertionError(f"Expected {'Disconnect error'} in {result.error}")

    async def test_search_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful search."""
        connection_id = "test_connection"
        base_dn = "ou=users,dc=example,dc=org"
        search_filter = "(objectClass=inetOrgPerson)"
        attributes = ["uid", "cn", "mail"]

        # Mock search result
        mock_search_data = [
            {
                "dn": "uid=user1,ou=users,dc=example,dc=org",
                "attributes": {
                    "uid": ["user1"],
                    "cn": ["User One"],
                    "mail": ["user1@example.org"],
                    "objectClass": ["inetOrgPerson"],
                },
            },
        ]

        directory_service._ldap_client.search = AsyncMock(
            return_value=FlextResult.ok(mock_search_data),
        )

        result = await directory_service.search(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
            attributes=attributes,
        )

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is not None
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")
        assert result.data[0].dn == "uid=user1,ou=users,dc=example,dc=org"
        if result.data[0].attributes["uid"] != ["user1"]:
            raise AssertionError(
                f"Expected {['user1']}, got {result.data[0].attributes['uid']}"
            )

        directory_service._ldap_client.search.assert_called_once_with(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
            attributes=attributes,
            scope="sub",
        )

    async def test_search_with_default_attributes(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test search with default attributes."""
        connection_id = "test_connection"
        base_dn = "ou=users,dc=example,dc=org"
        search_filter = "(objectClass=inetOrgPerson)"

        # Mock search result
        mock_search_data = [
            {
                "dn": "uid=user1,ou=users,dc=example,dc=org",
                "attributes": {"uid": ["user1"], "objectClass": ["inetOrgPerson"]},
            },
        ]

        directory_service._ldap_client.search = AsyncMock(
            return_value=FlextResult.ok(mock_search_data),
        )

        result = await directory_service.search(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
        )

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        directory_service._ldap_client.search.assert_called_once_with(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
            attributes=["*"],
            scope="sub",
        )

    async def test_search_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test search failure."""
        connection_id = "test_connection"
        base_dn = "ou=users,dc=example,dc=org"
        search_filter = "(objectClass=inetOrgPerson)"

        # Mock search failure
        directory_service._ldap_client.search = AsyncMock(
            return_value=FlextResult.fail("Search operation failed"),
        )

        result = await directory_service.search(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Search failed" not in result.error:
            raise AssertionError(f"Expected {'Search failed'} in {result.error}")

    async def test_search_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test search with exception."""
        connection_id = "test_connection"
        base_dn = "ou=users,dc=example,dc=org"
        search_filter = "(objectClass=inetOrgPerson)"

        # Mock search exception
        directory_service._ldap_client.search = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = await directory_service.search(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Search error" not in result.error:
            raise AssertionError(f"Expected {'Search error'} in {result.error}")

    async def test_add_entry_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful entry addition."""
        connection_id = "test_connection"
        dn = "uid=newuser,ou=users,dc=example,dc=org"
        attributes = {
            "objectClass": ["inetOrgPerson"],
            "uid": ["newuser"],
            "cn": ["New User"],
            "sn": ["User"],
        }

        # Mock successful add
        directory_service._ldap_client.add_entry = AsyncMock(
            return_value=FlextResult.ok(TestOperationResult.SUCCESS),
        )

        result = await directory_service.add_entry(
            connection_id=connection_id,
            dn=dn,
            attributes=attributes,
        )

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is True

        directory_service._ldap_client.add_entry.assert_called_once_with(
            connection_id=connection_id,
            dn=dn,
            attributes=attributes,
        )

    async def test_add_entry_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry addition failure."""
        connection_id = "test_connection"
        dn = "uid=newuser,ou=users,dc=example,dc=org"
        attributes = {"objectClass": ["inetOrgPerson"]}

        # Mock add failure
        directory_service._ldap_client.add_entry = AsyncMock(
            return_value=FlextResult.fail("Entry already exists"),
        )

        result = await directory_service.add_entry(
            connection_id=connection_id,
            dn=dn,
            attributes=attributes,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Add entry failed" not in result.error:
            raise AssertionError(f"Expected {'Add entry failed'} in {result.error}")

    async def test_add_entry_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry addition with exception."""
        connection_id = "test_connection"
        dn = "uid=newuser,ou=users,dc=example,dc=org"
        attributes = {"objectClass": ["inetOrgPerson"]}

        # Mock add exception
        directory_service._ldap_client.add_entry = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = await directory_service.add_entry(
            connection_id=connection_id,
            dn=dn,
            attributes=attributes,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Add entry error" not in result.error:
            raise AssertionError(f"Expected {'Add entry error'} in {result.error}")

    async def test_modify_entry_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful entry modification."""
        connection_id = "test_connection"
        dn = "uid=user1,ou=users,dc=example,dc=org"
        changes = {"mail": "newemail@example.org", "telephoneNumber": "+1234567890"}

        # Mock successful modify
        directory_service._ldap_client.modify_entry = AsyncMock(
            return_value=FlextResult.ok(TestOperationResult.SUCCESS),
        )

        result = await directory_service.modify_entry(
            connection_id=connection_id,
            dn=dn,
            changes=changes,
        )

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is True

        directory_service._ldap_client.modify_entry.assert_called_once_with(
            connection_id=connection_id,
            dn=dn,
            changes=changes,
        )

    async def test_modify_entry_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry modification failure."""
        connection_id = "test_connection"
        dn = "uid=user1,ou=users,dc=example,dc=org"
        changes = {"mail": "newemail@example.org"}

        # Mock modify failure
        directory_service._ldap_client.modify_entry = AsyncMock(
            return_value=FlextResult.fail("Entry not found"),
        )

        result = await directory_service.modify_entry(
            connection_id=connection_id,
            dn=dn,
            changes=changes,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Modify entry failed" not in result.error:
            raise AssertionError(f"Expected {'Modify entry failed'} in {result.error}")

    async def test_modify_entry_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry modification with exception."""
        connection_id = "test_connection"
        dn = "uid=user1,ou=users,dc=example,dc=org"
        changes = {"mail": "newemail@example.org"}

        # Mock modify exception
        directory_service._ldap_client.modify_entry = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = await directory_service.modify_entry(
            connection_id=connection_id,
            dn=dn,
            changes=changes,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Modify entry error" not in result.error:
            raise AssertionError(f"Expected {'Modify entry error'} in {result.error}")

    async def test_delete_entry_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful entry deletion."""
        connection_id = "test_connection"
        dn = "uid=user1,ou=users,dc=example,dc=org"

        # Mock successful delete
        directory_service._ldap_client.delete_entry = AsyncMock(
            return_value=FlextResult.ok(TestOperationResult.SUCCESS),
        )

        result = await directory_service.delete_entry(
            connection_id=connection_id,
            dn=dn,
        )

        if not (result.is_success):
            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is True

        directory_service._ldap_client.delete_entry.assert_called_once_with(
            connection_id=connection_id,
            dn=dn,
        )

    async def test_delete_entry_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry deletion failure."""
        connection_id = "test_connection"
        dn = "uid=user1,ou=users,dc=example,dc=org"

        # Mock delete failure
        directory_service._ldap_client.delete_entry = AsyncMock(
            return_value=FlextResult.fail("Entry not found"),
        )

        result = await directory_service.delete_entry(
            connection_id=connection_id,
            dn=dn,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Delete entry failed" not in result.error:
            raise AssertionError(f"Expected {'Delete entry failed'} in {result.error}")

    async def test_delete_entry_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry deletion with exception."""
        connection_id = "test_connection"
        dn = "uid=user1,ou=users,dc=example,dc=org"

        # Mock delete exception
        directory_service._ldap_client.delete_entry = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = await directory_service.delete_entry(
            connection_id=connection_id,
            dn=dn,
        )

        if result.is_success:
            raise AssertionError(f"Expected False, got {result.is_success}")
        assert result.error is not None
        if "Delete entry error" not in result.error:
            raise AssertionError(f"Expected {'Delete entry error'} in {result.error}")


class TestFlextLdapDirectoryAdapter:
    """Test FlextLdapDirectoryAdapter."""

    @pytest.fixture
    def directory_adapter(self) -> FlextLdapDirectoryAdapter:
        """Create directory adapter instance."""
        return FlextLdapDirectoryAdapter()

    def test_get_directory_service(
        self,
        directory_adapter: FlextLdapDirectoryAdapter,
    ) -> None:
        """Test getting directory service."""
        service = directory_adapter.get_directory_service()

        assert isinstance(service, FlextLdapDirectoryService)
        assert isinstance(service, FlextLdapDirectoryServiceInterface)


class TestBackwardCompatibilityAliases:
    """Test backward compatibility aliases."""

    def test_aliases_exist(self) -> None:
        """Test that backward compatibility aliases exist."""
        from flext_ldap.adapters.directory_adapter import (
            DirectoryAdapterInterface,
            DirectoryConnectionProtocol,
            DirectoryEntryProtocol,
            DirectoryServiceInterface,
        )

        # Test that aliases point to the correct classes
        assert DirectoryConnectionProtocol is FlextLdapDirectoryConnectionProtocol
        assert DirectoryEntryProtocol is FlextLdapDirectoryEntryProtocol
        assert DirectoryServiceInterface is FlextLdapDirectoryServiceInterface
        assert DirectoryAdapterInterface is FlextLdapDirectoryAdapterInterface
