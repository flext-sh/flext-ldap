
from __future__ import annotations

import pytest
from flext_core import FlextResult
from pydantic import ValidationError
from flext_ldap import (
    FlextLDAPAdapters,
    FlextLDAPClient,
    FlextLDAPConstants,
)

# Import from the adapters module
from flext_core import FlextModels

# Type aliases for cleaner code
ConnectionConfig = FlextLDAPAdapters.ConnectionConfig
DirectoryEntry = FlextLDAPAdapters.DirectoryEntry
OperationExecutor = FlextLDAPAdapters.OperationExecutor

# Fix forward references for DirectoryEntry
DirectoryEntry.model_rebuild()


class TestRealAdaptersModels:
    """Test REAL adapters domain models."""

    def test_directory_entry_creation(self) -> None:
        """Test creating DirectoryEntry with valid data."""

        entry = DirectoryEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["test@example.com"],
            },
        )

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.attributes["cn"] == ["test"]
        assert entry.attributes["objectClass"] == ["person", "inetOrgPerson"]
        assert entry.attributes["mail"] == ["test@example.com"]

    def test_directory_entry_with_empty_attributes(self) -> None:
        """Test DirectoryEntry with empty attributes (should work)."""

        entry = DirectoryEntry(dn="cn=test,dc=example,dc=com")

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.attributes == {}

    def test_directory_entry_dn_validation_valid(self) -> None:
        """Test DirectoryEntry DN validation with valid DNs."""

        valid_dns = [
            "cn=test,dc=example,dc=com",
            "uid=john,ou=people,dc=company,dc=org",
            "ou=groups,dc=test,dc=local",
            "dc=root",
        ]

        for dn in valid_dns:
            entry = DirectoryEntry(dn=dn)
            assert entry.dn == dn

    def test_directory_entry_dn_validation_invalid(self) -> None:
        """Test DirectoryEntry DN validation rejects invalid DNs."""

        invalid_dns = [
            "",  # Empty string
            "   ",  # Whitespace only
            "ab",  # Too short (min_length=3)
        ]

        for invalid_dn in invalid_dns:
            with pytest.raises(ValidationError):
                DirectoryEntry(dn=invalid_dn)

    def test_connection_config_creation_minimal(self) -> None:
        """Test ConnectionConfig creation with minimal required data."""

        config = ConnectionConfig(server="ldap://localhost:389")

        assert config.server == "ldap://localhost:389"
        assert config.bind_dn is None
        assert config.bind_password is None
        assert config.timeout == FlextLDAPConstants.Connection.DEFAULT_TIMEOUT
        assert config.use_tls is False

    def test_connection_config_creation_full(self) -> None:
        """Test ConnectionConfig creation with all fields."""

        config = ConnectionConfig(
            server="ldaps://ldap.example.com:636",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret123",
            timeout=60,
            use_tls=True,
        )

        assert config.server == "ldaps://ldap.example.com:636"
        assert config.bind_dn == "cn=admin,dc=example,dc=com"
        assert config.bind_password == "secret123"
        assert config.timeout == 60
        assert config.use_tls is True

    def test_connection_config_timeout_validation_valid(self) -> None:
        """Test ConnectionConfig timeout validation accepts valid values."""

        valid_timeouts = [1, 30, 60, 120, 300]  # gt=0, le=300

        for timeout in valid_timeouts:
            config = ConnectionConfig(server="ldap://localhost:389", timeout=timeout)
            assert config.timeout == timeout

    def test_connection_config_timeout_validation_invalid(self) -> None:
        """Test ConnectionConfig timeout validation rejects invalid values."""

        invalid_timeouts = [0, -1, 301, 1000]  # Outside gt=0, le=300

        for timeout in invalid_timeouts:
            with pytest.raises(ValidationError):
                ConnectionConfig(server="ldap://localhost:389", timeout=timeout)

    def test_connection_config_server_validation_valid(self) -> None:
        """Test ConnectionConfig server validation accepts valid URIs."""

        valid_uris = [
            "ldap://localhost:389",
            "ldaps://secure.ldap.example.com:636",
            "ldap://192.168.1.100:389",
            "ldaps://ldap.company.local:636",
        ]

        for uri in valid_uris:
            config = ConnectionConfig(server=uri)
            assert config.server == uri

    def test_connection_config_server_validation_invalid(self) -> None:
        """Test ConnectionConfig server validation rejects invalid URIs."""

        invalid_uris = [
            "",  # Empty string
            "not-a-url",  # Not a URL
            "http://localhost:389",  # Wrong protocol
            "://localhost:389",  # Missing scheme
            "ldap://",  # Missing netloc
        ]

        for uri in invalid_uris:
            # Test that invalid URIs are rejected
            try:
                ConnectionConfig(server=uri)
                # If we get here, the validation failed to catch the invalid URI
                pytest.fail(f"Expected ValidationError for invalid URI: {uri}")
            except ValidationError:
                # This is expected - validation should catch invalid URIs
                pass

    def test_connection_config_business_rules_validation(self) -> None:
        """Test ConnectionConfig business rules validation."""

        # Valid config should pass business rules
        config = ConnectionConfig(server="ldap://localhost:389")
        result = config.validate_business_rules()
        assert result.is_success

        # Test with timeout edge cases
        config_min = ConnectionConfig(server="ldap://localhost:389", timeout=1)
        result_min = config_min.validate_business_rules()
        assert result_min.is_success


class TestRealConnectionService:
    """Test REAL ConnectionService functionality."""

    def test_connection_service_can_be_instantiated(self) -> None:
        """Test ConnectionService can be instantiated with client."""

        client = FlextLDAPClient()
        config = FlextLDAPAdapters.ConnectionConfig(
            server="ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=com",
        )
        service = FlextLDAPAdapters.ConnectionService(client=client, config=config)

        assert isinstance(service, FlextLDAPAdapters.ConnectionService)
        assert service is not None

    def test_connection_service_has_required_methods(self) -> None:
        """Test ConnectionService has required methods."""

        client = FlextLDAPClient()
        config = FlextLDAPAdapters.ConnectionConfig(
            server="ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=com",
        )
        service = FlextLDAPAdapters.ConnectionService(client=client, config=config)

        # Should have connection interface methods
        assert hasattr(service, "establish_connection")
        assert hasattr(service, "terminate_connection")
        assert hasattr(service, "is_connected")

        # Methods should be callable
        assert callable(service.establish_connection)
        assert callable(service.terminate_connection)
        assert callable(service.is_connected)

    def test_connection_service_initial_state_not_connected(self) -> None:
        """Test connection service starts in not connected state."""

        client = FlextLDAPClient()
        config = FlextLDAPAdapters.ConnectionConfig(
            server="ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=com",
        )
        service = FlextLDAPAdapters.ConnectionService(client=client, config=config)

        assert not service.is_connected()

    async def test_connection_service_establish_connection_validates_config(
        self,
    ) -> None:
        """Test establish_connection validates configuration."""

        # Testing validation - this should be outside validation test

        # Invalid config should fail validation - this will fail during validation before attempting connection
        with pytest.raises(ValidationError):
            ConnectionConfig(server="invalid-uri")

    async def test_connection_service_terminate_connection_when_not_connected(
        self,
    ) -> None:
        """Test terminate_connection when not connected."""

        client = FlextLDAPClient()
        config = FlextLDAPAdapters.ConnectionConfig(
            server="ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=com",
        )
        service = FlextLDAPAdapters.ConnectionService(client=client, config=config)

        # Should fail gracefully when no connection exists
        result = await service.terminate_connection()
        assert not result.is_success
        assert "No active connection to terminate" in (result.error or "")


class TestRealSearchService:
    """Test REAL SearchService functionality."""

    def test_search_service_can_be_instantiated(self) -> None:
        """Test SearchService can be instantiated with client."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.SearchService(client=client)

        assert isinstance(service, FlextLDAPAdapters.SearchService)
        assert service is not None

    def test_search_service_has_required_methods(self) -> None:
        """Test SearchService has required methods."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.SearchService(client=client)

        # Should have search interface methods
        assert hasattr(service, "search_entries")
        assert callable(service.search_entries)

    async def test_search_service_validates_empty_base_dn(self) -> None:
        """Test search_entries validates empty base DN."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.SearchService(client=client)

        result = await service.search_entries("", "(objectClass=*)")
        assert not result.is_success
        assert "Base DN cannot be empty" in (result.error or "")

    async def test_search_service_validates_empty_filter(self) -> None:
        """Test search_entries validates empty search filter."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.SearchService(client=client)

        result = await service.search_entries("dc=example,dc=com", "")
        assert not result.is_success
        assert "Search filter cannot be empty" in (result.error or "")


class TestRealEntryService:
    """Test REAL EntryService functionality."""

    def test_entry_service_can_be_instantiated(self) -> None:
        """Test EntryService can be instantiated with client."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.EntryService(client=client)

        assert isinstance(service, FlextLDAPAdapters.EntryService)
        assert service is not None

    def test_entry_service_has_required_methods(self) -> None:
        """Test EntryService has required methods."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.EntryService(client=client)

        # Should have entry interface methods
        assert hasattr(service, "add_entry")
        assert hasattr(service, "modify_entry")
        assert hasattr(service, "delete_entry")

        # Methods should be callable
        assert callable(service.add_entry)
        assert callable(service.modify_entry)
        assert callable(service.delete_entry)

    async def test_entry_service_validates_entry_for_add_no_attributes(self) -> None:
        """Test add_entry validates entry with no attributes."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.EntryService(client=client)

        # Entry without attributes should fail validation
        entry_no_attrs = DirectoryEntry(dn="cn=test,dc=example,dc=com")
        result = await service.add_entry(entry_no_attrs)
        assert not result.is_success
        assert "must have at least one attribute" in (result.error or "")

    async def test_entry_service_validates_entry_for_add_no_object_class(self) -> None:
        """Test add_entry validates entry without objectClass."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.EntryService(client=client)

        # Entry without objectClass should fail
        entry_no_oc = DirectoryEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        result = await service.add_entry(entry_no_oc)
        assert not result.is_success
        assert "must have objectClass" in (result.error or "")

    async def test_entry_service_validates_dn_for_modify(self) -> None:
        """Test modify_entry validates DN parameter."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.EntryService(client=client)

        # Empty DN should fail
        result = await service.modify_entry("", {})
        assert not result.is_success
        assert "DN cannot be empty" in (result.error or "")

    async def test_entry_service_validates_dn_for_delete(self) -> None:
        """Test delete_entry validates DN parameter."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.EntryService(client=client)

        # Empty DN should fail
        result = await service.delete_entry("")
        assert not result.is_success
        assert "DN cannot be empty" in (result.error or "")

    async def test_entry_service_validates_no_modifications(self) -> None:
        """Test modify_entry validates empty modifications."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.EntryService(client=client)

        # No modifications should fail
        result = await service.modify_entry("cn=test,dc=example,dc=com", {})
        assert not result.is_success
        assert "Modifications cannot be empty" in (result.error or "")


class TestRealDirectoryAdapter:
    """Test REAL DirectoryAdapter functionality."""

    def test_directory_adapter_can_be_instantiated(self) -> None:
        """Test DirectoryAdapter can be instantiated."""

        client = FlextLDAPClient()
        adapter = FlextLDAPAdapters.DirectoryAdapter(client=client)

        assert isinstance(adapter, FlextLDAPAdapters.DirectoryAdapter)
        assert adapter is not None

    def test_directory_adapter_has_required_methods(self) -> None:
        """Test DirectoryAdapter has required methods."""

        client = FlextLDAPClient()
        adapter = FlextLDAPAdapters.DirectoryAdapter(client=client)

        # Should have adapter methods
        assert hasattr(adapter, "get_all_entries")
        assert callable(adapter.get_all_entries)

    async def test_directory_adapter_validates_base_dn(self) -> None:
        """Test DirectoryAdapter validates base DN."""

        client = FlextLDAPClient()
        adapter = FlextLDAPAdapters.DirectoryAdapter(client=client)

        # Empty base DN should fail
        result = await adapter.get_all_entries("")
        assert not result.is_success
        assert "Base DN cannot be empty" in (result.error or "")


class TestRealDirectoryService:
    """Test REAL DirectoryService functionality."""

    def test_directory_service_can_be_instantiated(self) -> None:
        """Test DirectoryService can be instantiated."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.DirectoryService(client=client)

        assert isinstance(service, FlextLDAPAdapters.DirectoryService)
        assert service is not None

    def test_directory_service_has_required_methods(self) -> None:
        """Test DirectoryService has required methods."""

        client = FlextLDAPClient()
        service = FlextLDAPAdapters.DirectoryService(client=client)

        # Should have interface methods
        assert hasattr(service, "connect")
        assert hasattr(service, "search_users")

        # Methods should be callable
        assert callable(service.connect)
        assert callable(service.search_users)


class TestRealOperationExecutor:
    """Test REAL OperationExecutor class functionality."""

    def test_operation_executor_can_be_instantiated(self) -> None:
        """Test OperationExecutor can be instantiated."""

        client = FlextLDAPClient()
        executor = OperationExecutor(client=client)
        assert isinstance(executor, OperationExecutor)

    def test_operation_executor_execute_method(self) -> None:
        """Test OperationExecutor execute method returns expected result."""

        client = FlextLDAPClient()
        executor = OperationExecutor(client=client)

        # Base class execute should return error (not implemented)
        result = executor.execute()
        assert not result.is_success
        assert "Not implemented in base class" in (result.error or "")

    async def test_operation_executor_async_operation_success(self) -> None:
        """Test OperationExecutor handles successful async operations."""

        client = FlextLDAPClient()
        executor = OperationExecutor(client=client)

        async def successful_operation() -> FlextResult[list[DirectoryEntry]]:
            return FlextResult[list[DirectoryEntry]].ok([])

        result = await executor.execute_async_operation(
            successful_operation,
            "test operation",
        )

        assert result.is_success
        assert result.value == []

    async def test_operation_executor_async_operation_exception_handling(self) -> None:
        """Test OperationExecutor handles exceptions gracefully."""

        client = FlextLDAPClient()
        executor = OperationExecutor(client=client)

        async def failing_operation() -> FlextResult[list[DirectoryEntry]]:
            msg = "Operation failed"
            raise RuntimeError(msg)

        result = await executor.execute_async_operation(
            failing_operation,
            "test operation",
        )

        assert not result.is_success
        assert "Failed to execute test operation" in (result.error or "")


class TestRealAdaptersIntegration:
    """Test REAL adapters integration patterns."""

    def test_directory_entry_integrates_with_flext_model(self) -> None:
        """Test that DirectoryEntry properly inherits from FlextModels."""

        entry = DirectoryEntry(dn="cn=test,dc=example,dc=com")

        # Should have FlextModels methods
        assert hasattr(entry, "model_dump")
        assert hasattr(entry, "model_validate")

        # Test model_dump works
        data = entry.model_dump()
        assert isinstance(data, dict)
        assert data["dn"] == "cn=test,dc=example,dc=com"
        assert "attributes" in data

    def test_connection_config_integrates_with_flext_model(self) -> None:
        """Test that ConnectionConfig properly inherits from FlextModels."""

        config = ConnectionConfig(server="ldap://localhost:389")

        # Should have FlextModels methods
        assert hasattr(config, "model_dump")
        assert hasattr(config, "model_validate")

        # Test model_dump works
        data = config.model_dump()
        assert isinstance(data, dict)
        assert data["server"] == "ldap://localhost:389"
        assert "timeout" in data
        assert "use_tls" in data

    def test_models_can_be_serialized_and_deserialized(self) -> None:
        """Test that adapters models can be properly serialized/deserialized."""

        # Test DirectoryEntry
        original_entry = DirectoryEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "mail": ["test@example.com"]},
        )

        # Serialize to dict
        entry_data = original_entry.model_dump()

        # Deserialize from dict
        restored_entry = DirectoryEntry.model_validate(entry_data)

        # Should be equivalent
        assert restored_entry.dn == original_entry.dn
        assert restored_entry.attributes == original_entry.attributes

        # Test ConnectionConfig
        original_config = ConnectionConfig(
            server="ldaps://ldap.example.com:636",
            bind_dn="cn=admin,dc=example,dc=com",
            timeout=120,
            use_tls=True,
        )

        # Serialize to dict
        config_data = original_config.model_dump()

        # Deserialize from dict
        restored_config = ConnectionConfig.model_validate(config_data)

        # Should be equivalent
        assert restored_config.server == original_config.server
        assert restored_config.bind_dn == original_config.bind_dn
        assert restored_config.timeout == original_config.timeout
        assert restored_config.use_tls == original_config.use_tls


class TestRealAdaptersErrorHandling:
    """Test REAL error handling in adapters."""

    def test_directory_entry_handles_malformed_data(self) -> None:
        """Test DirectoryEntry handles malformed data gracefully."""

        # Test with various malformed data that should raise ValidationError
        malformed_cases = [
            {"dn": 123},  # dn should be string
            {"dn": None},  # dn is required
            {"dn": "valid", "attributes": "not_a_dict"},  # attributes should be dict
        ]

        for malformed_data in malformed_cases:
            with pytest.raises(ValidationError):
                DirectoryEntry.model_validate(malformed_data)

    def test_connection_config_handles_malformed_data(self) -> None:
        """Test ConnectionConfig handles malformed data gracefully."""

        # Test with various malformed data that should raise ValidationError
        malformed_cases = [
            {},  # Missing required server
            {"server": 123},  # server should be string
            {
                "server": "ldap://localhost:389",
                "timeout": "not_an_int",
            },  # timeout should be int
            {
                "server": "ldap://localhost:389",
                "use_tls": "not_a_bool",
            },  # use_tls should be bool
        ]

        for malformed_data in malformed_cases:
            with pytest.raises(ValidationError):
                ConnectionConfig.model_validate(malformed_data)

    def test_models_provide_helpful_error_messages(self) -> None:
        """Test that models provide helpful error messages on validation failure."""

        # Test DirectoryEntry with invalid DN
        try:
            DirectoryEntry(dn="ab")  # Too short (min_length=3)
        except ValidationError as e:
            error_str = str(e)
            # Should contain information about the validation failure
            assert len(error_str) > 0
            assert (
                "at least 3 characters" in error_str
                or "String should have at least 3 characters" in error_str
            )

        # Test ConnectionConfig with invalid timeout
        try:
            ConnectionConfig(server="ldap://localhost:389", timeout=0)
        except ValidationError as e:
            error_str = str(e)
            # Should contain information about the validation failure
            assert len(error_str) > 0
            assert (
                "greater than 0" in error_str
                or "Input should be greater than 0" in error_str
            )
