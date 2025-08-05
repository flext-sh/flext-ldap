"""Tests for LDAP directory adapter in FLEXT-LDAP."""

from typing import cast
from unittest.mock import AsyncMock, patch

import pytest
from flext_core import FlextResult

from flext_ldap.adapters.directory_adapter import (
    FlextLdapDirectoryAdapter,
    FlextLdapDirectoryAdapterInterface,
    FlextLdapDirectoryConnectionProtocol,
    FlextLdapDirectoryEntryProtocol,
    FlextLdapDirectoryService,
    FlextLdapDirectoryServiceInterface,
)

# Constants
EXPECTED_DATA_COUNT = 3


# FBT smell elimination constants - SOLID DRY Principle
class TestOperationResult:
    """Test operation result constants - eliminates FBT003 positional booleans."""

    SUCCESS = True
    FAILURE = False


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

    def test_connect_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful connection."""
        result = directory_service.connect(server_url="ldap://test.example.com:389")

        if not (result.success):
            raise AssertionError(f"Expected True, got {result.success}")
        assert result.data is True

    def test_connect_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test connection with exception."""
        # Force an exception by mocking the FlextResult.ok method
        with patch("flext_ldap.adapters.directory_adapter.FlextResult.ok") as mock_ok:
            mock_ok.side_effect = Exception("Connection failed")

            result = directory_service.connect(server_url="ldap://test.example.com:389")

            if result.success:
                raise AssertionError(f"Expected False, got {result.success}")
            assert result.error is not None
            if "Connection" not in result.error:
                raise AssertionError(f"Expected {'Connection'} in {result.error}")

    def test_search_users_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful user search."""
        search_filter = "(uid=testuser)"

        # Mock the search method with proper result structure
        mock_search_results = [
            {"dn": "cn=user,dc=example,dc=com", "attributes": {"uid": ["user"]}}
        ]
        directory_service._ldap_client.search = AsyncMock(
            return_value=FlextResult.ok(mock_search_results)
        )

        result = directory_service.search_users(search_filter)

        if not (result.success):
            raise AssertionError(f"Expected True, got {result.success}")
        assert result.data is not None
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")

        # Check if result.data[0] is dict (from search conversion) or protocol object
        entry = result.data[0]
        if isinstance(entry, dict):
            assert entry["dn"] == "cn=user,dc=example,dc=com"
            expected_attrs = {"uid": ["user"]}
            if entry["attributes"] != expected_attrs:
                raise AssertionError(
                    f"Expected {expected_attrs}, got {entry['attributes']}"
                )
        else:
            assert entry.dn == "cn=user,dc=example,dc=com"
            expected_attrs = {"uid": ["user"]}
            if entry.attributes != expected_attrs:
                raise AssertionError(
                    f"Expected {expected_attrs}, got {entry.attributes}"
                )

    def test_search_users_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test user search with exception."""
        search_filter = "(uid=test)"

        # Mock the search method to raise exception
        directory_service._ldap_client.search = AsyncMock(
            side_effect=Exception("Search failed")
        )

        result = directory_service.search_users(search_filter)

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
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

        if not (result.success):
            raise AssertionError(f"Expected True, got {result.success}")
        assert result.data is True
        directory_service._ldap_client.disconnect.assert_called_once()

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

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Disconnect error" not in result.error:
            raise AssertionError(f"Expected {'Disconnect error'} in {result.error}")

    def test_search_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful search."""
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

        result = directory_service.search(
            base_dn=base_dn,
            search_filter=search_filter,
            attributes=attributes,
        )

        if not (result.success):
            raise AssertionError(f"Expected True, got {result.success}")
        assert result.data is not None
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")
        assert result.data[0].dn == "uid=user1,ou=users,dc=example,dc=org"
        if result.data[0].attributes["uid"] != ["user1"]:
            raise AssertionError(
                f"Expected {['user1']}, got {result.data[0].attributes['uid']}"
            )

        directory_service._ldap_client.search.assert_called_once_with(
            base_dn, search_filter, attributes
        )

    async def test_search_with_default_attributes(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test search with default attributes."""
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

        result = directory_service.search(
            base_dn=base_dn,
            search_filter=search_filter,
        )

        if not (result.success):
            raise AssertionError(f"Expected True, got {result.success}")
        directory_service._ldap_client.search.assert_called_once_with(
            base_dn, search_filter, ["*"]
        )

    def test_search_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test search failure."""
        base_dn = "ou=users,dc=example,dc=org"
        search_filter = "(objectClass=inetOrgPerson)"

        # Mock search failure
        directory_service._ldap_client.search = AsyncMock(
            return_value=FlextResult.fail("Search operation failed"),
        )

        result = directory_service.search(
            base_dn=base_dn,
            search_filter=search_filter,
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Search failed" not in result.error:
            raise AssertionError(f"Expected {'Search failed'} in {result.error}")

    async def test_search_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test search with exception."""
        base_dn = "ou=users,dc=example,dc=org"
        search_filter = "(objectClass=inetOrgPerson)"

        # Mock search exception
        directory_service._ldap_client.search = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = directory_service.search(
            base_dn=base_dn,
            search_filter=search_filter,
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Search error" not in result.error:
            raise AssertionError(f"Expected {'Search error'} in {result.error}")

    async def test_add_entry_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful entry addition."""
        dn = "uid=newuser,ou=users,dc=example,dc=org"
        attributes = {
            "objectClass": ["inetOrgPerson"],
            "uid": ["newuser"],
            "cn": ["New User"],
            "sn": ["User"],
        }

        # Mock successful add
        directory_service._ldap_client.add = AsyncMock(
            return_value=FlextResult.ok(TestOperationResult.SUCCESS),
        )

        result = directory_service.add_entry(
            dn=dn,
            attributes=attributes,
        )

        if not (result.success):
            raise AssertionError(f"Expected True, got {result.success}")
        assert result.data is True

        directory_service._ldap_client.add.assert_called_once()

    async def test_add_entry_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry addition failure."""
        dn = "uid=newuser,ou=users,dc=example,dc=org"
        attributes = {"objectClass": ["inetOrgPerson"]}

        # Mock add failure
        directory_service._ldap_client.add = AsyncMock(
            return_value=FlextResult.fail("Entry already exists"),
        )

        result = directory_service.add_entry(
            dn=dn,
            attributes=attributes,
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Add entry failed" not in result.error:
            raise AssertionError(f"Expected {'Add entry failed'} in {result.error}")

    async def test_add_entry_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry addition with exception."""
        dn = "uid=newuser,ou=users,dc=example,dc=org"
        attributes = {"objectClass": ["inetOrgPerson"]}

        # Mock add exception
        directory_service._ldap_client.add = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = directory_service.add_entry(
            dn=dn,
            attributes=attributes,
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Add entry error" not in result.error:
            raise AssertionError(f"Expected {'Add entry error'} in {result.error}")

    async def test_modify_entry_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful entry modification."""
        dn = "uid=user1,ou=users,dc=example,dc=org"
        changes = {"mail": "newemail@example.org", "telephoneNumber": "+1234567890"}

        # Mock successful modify with AsyncMock since modify is async
        directory_service._ldap_client.modify = AsyncMock(
            return_value=FlextResult.ok(TestOperationResult.SUCCESS),
        )

        result = directory_service.modify_entry(
            dn=dn,
            changes=changes,
        )

        if not (result.success):
            raise AssertionError(
                f"Expected True, got {result.success}. Error: {result.error}"
            )
        assert result.data is True

        directory_service._ldap_client.modify.assert_called_once_with(
            dn,
            changes,
        )

    async def test_modify_entry_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry modification failure."""
        dn = "uid=user1,ou=users,dc=example,dc=org"
        changes = {"mail": "newemail@example.org"}

        # Mock modify failure
        directory_service._ldap_client.modify = AsyncMock(
            return_value=FlextResult.fail("Entry not found"),
        )

        result = directory_service.modify_entry(
            dn=dn,
            changes=changes,
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Modify entry failed" not in result.error:
            raise AssertionError(f"Expected {'Modify entry failed'} in {result.error}")

    async def test_modify_entry_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry modification with exception."""
        dn = "uid=user1,ou=users,dc=example,dc=org"
        changes = {"mail": "newemail@example.org"}

        # Mock modify exception
        directory_service._ldap_client.modify = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = directory_service.modify_entry(
            dn=dn,
            changes=changes,
        )

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Modify entry" not in result.error:
            raise AssertionError(f"Expected {'Modify entry'} in {result.error}")

    def test_delete_entry_success(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test successful entry deletion."""
        dn = "uid=user1,ou=users,dc=example,dc=org"

        # Mock successful delete - correct method name
        directory_service._ldap_client.delete = AsyncMock(
            return_value=FlextResult.ok(TestOperationResult.SUCCESS),
        )

        result = directory_service.delete_entry(dn=dn)

        if not (result.success):
            raise AssertionError(f"Expected True, got {result.success}")
        assert result.data is True

        directory_service._ldap_client.delete.assert_called_once_with(dn)

    def test_delete_entry_failure(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry deletion failure."""
        dn = "uid=user1,ou=users,dc=example,dc=org"

        # Mock delete failure
        directory_service._ldap_client.delete = AsyncMock(
            return_value=FlextResult.fail("Entry not found"),
        )

        result = directory_service.delete_entry(dn=dn)

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Delete entry failed" not in result.error:
            raise AssertionError(f"Expected {'Delete entry failed'} in {result.error}")

    def test_delete_entry_exception(
        self,
        directory_service: FlextLdapDirectoryService,
    ) -> None:
        """Test entry deletion with exception."""
        dn = "uid=user1,ou=users,dc=example,dc=org"

        # Mock delete exception
        directory_service._ldap_client.delete = AsyncMock(
            side_effect=Exception("Connection error"),
        )

        result = directory_service.delete_entry(dn=dn)

        if result.success:
            raise AssertionError(f"Expected False, got {result.success}")
        assert result.error is not None
        if "Delete entry failed" not in result.error:
            raise AssertionError(f"Expected {'Delete entry failed'} in {result.error}")


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
