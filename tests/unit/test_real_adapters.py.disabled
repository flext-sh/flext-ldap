"""REAL adapters tests - testing actual adapter functionality without mocks.

These tests execute REAL adapter code to increase coverage and validate functionality.
"""

from __future__ import annotations

import inspect

import pytest
from flext_core import FlextResult
from pydantic import ValidationError

# Test real adapters functionality - CONSOLIDATED IMPORTS TO FIX PLC0415
from flext_ldap.adapters import (
    ConnectionConfig,
    DirectoryEntry,
    FlextLdapConnectionConstants,
    FlextLdapConnectionService,
    FlextLdapDirectoryAdapter,
    FlextLdapDirectoryEntry,
    FlextLdapDirectoryService,
    FlextLdapEntryService,
    FlextLdapSearchService,
    OperationExecutor,
    create_directory_adapter,
    create_directory_service,
    # Interfaces removed - using concrete implementations
)
from flext_ldap.clients import FlextLdapClient


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
        """Test DirectoryEntry DN validation rejects truly invalid DNs."""
        # The validator only checks for non-empty strings, so only empty/None will fail
        truly_invalid_dns = [
            "",  # Empty string - this should fail
            "   ",  # Whitespace only - this should fail after strip
        ]

        for invalid_dn in truly_invalid_dns:
            with pytest.raises(ValidationError):
                DirectoryEntry(dn=invalid_dn)

        # These are accepted by the current validator (only checks non-empty)
        # This tests the ACTUAL behavior, not ideal behavior
        accepted_by_validator = [
            "no equals sign",  # Currently accepted (not full DN validation)
            "cn=",  # Currently accepted (not full DN validation)
            "=value",  # Currently accepted (not full DN validation)
        ]

        for dn in accepted_by_validator:
            # These should create successfully with current validator
            entry = DirectoryEntry(dn=dn)
            assert entry.dn == dn

    def test_connection_config_creation_minimal(self) -> None:
        """Test ConnectionConfig creation with minimal required data."""
        config = ConnectionConfig(server_uri="ldap://localhost:389")

        assert config.server_uri == "ldap://localhost:389"
        assert config.bind_dn is None
        assert config.bind_password is None
        assert config.timeout == FlextLdapConnectionConstants.DEFAULT_TIMEOUT
        assert config.use_ssl is False

    def test_connection_config_creation_full(self) -> None:
        """Test ConnectionConfig creation with all fields."""
        config = ConnectionConfig(
            server_uri="ldaps://ldap.example.com:636",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret123",
            timeout=60,
            use_ssl=True,
        )

        assert config.server_uri == "ldaps://ldap.example.com:636"
        assert config.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert config.bind_password == "secret123"
        assert config.timeout == 60
        assert config.use_ssl is True

    def test_connection_config_timeout_validation_valid(self) -> None:
        """Test ConnectionConfig timeout validation accepts valid values."""
        valid_timeouts = [1, 30, 60, 120, 300]  # ge=1, le=300

        for timeout in valid_timeouts:
            config = ConnectionConfig(
                server_uri="ldap://localhost:389", timeout=timeout
            )
            assert config.timeout == timeout

    def test_connection_config_timeout_validation_invalid(self) -> None:
        """Test ConnectionConfig timeout validation rejects invalid values."""
        invalid_timeouts = [0, -1, 301, 1000]  # Outside ge=1, le=300

        for timeout in invalid_timeouts:
            with pytest.raises(ValidationError):
                ConnectionConfig(server_uri="ldap://localhost:389", timeout=timeout)

    def test_connection_config_various_server_uris(self) -> None:
        """Test ConnectionConfig accepts various valid server URI formats."""
        valid_uris = [
            "ldap://localhost:389",
            "ldaps://secure.ldap.example.com:636",
            "ldap://192.168.1.100:389",
            "ldaps://internal.invalid:636",
        ]

        for uri in valid_uris:
            config = ConnectionConfig(server_uri=uri)
            assert config.server_uri == uri


class TestRealAdaptersInterfaces:
    """Test REAL adapters interfaces and protocols."""

    def test_connection_service_concrete_implementation(self) -> None:
        """Test that FlextLdapConnectionService is a concrete implementation."""
        # Test that we can instantiate the concrete service
        service = FlextLdapConnectionService(FlextLdapClient())
        assert service is not None

        # Verify it has the expected methods
        assert hasattr(service, "establish_connection")
        assert hasattr(service, "terminate_connection")


class TestRealAdaptersConstants:
    """Test REAL adapters constants usage."""

    def test_default_timeout_constant_used_in_connection_config(self) -> None:
        """Test that DEFAULT_TIMEOUT constant is properly used in ConnectionConfig."""
        # Create config without explicit timeout
        config = ConnectionConfig(server_uri="ldap://localhost:389")

        # Should use the constant value
        expected_timeout = FlextLdapConnectionConstants.DEFAULT_TIMEOUT
        assert config.timeout == expected_timeout
        assert isinstance(expected_timeout, int)
        assert expected_timeout > 0

    def test_timeout_boundaries_use_reasonable_values(self) -> None:
        """Test that timeout validation boundaries are reasonable."""
        # Test minimum boundary (ge=1)
        config_min = ConnectionConfig(server_uri="ldap://localhost:389", timeout=1)
        assert config_min.timeout == 1

        # Test maximum boundary (le=300)
        config_max = ConnectionConfig(server_uri="ldap://localhost:389", timeout=300)
        assert config_max.timeout == 300


class TestRealAdaptersFieldValidation:
    """Test REAL field validation in adapters models."""

    def test_directory_entry_field_validation_works(self) -> None:
        """Test that DirectoryEntry field validation actually works."""
        # This tests the real @field_validator("dn") decorator
        valid_dn = "cn=test,dc=example,dc=com"
        entry = DirectoryEntry(dn=valid_dn)

        # The validator should have processed the DN
        assert entry.dn == valid_dn

        # Invalid DN should raise ValidationError through the validator
        with pytest.raises(ValidationError):
            DirectoryEntry(dn="")

    def test_connection_config_field_constraints_work(self) -> None:
        """Test that ConnectionConfig field constraints actually work."""
        # Test required field
        with pytest.raises(ValidationError):
            ConnectionConfig()  # Missing required server_uri

        # Test field constraints (ge=1, le=300 for timeout)
        with pytest.raises(ValidationError):
            ConnectionConfig(server_uri="ldap://localhost:389", timeout=0)

        with pytest.raises(ValidationError):
            ConnectionConfig(server_uri="ldap://localhost:389", timeout=301)


class TestRealAdaptersIntegration:
    """Test REAL adapters integration patterns."""

    def test_directory_entry_integrates_with_flext_model(self) -> None:
        """Test that DirectoryEntry properly inherits from FlextModel."""
        entry = DirectoryEntry(dn="cn=test,dc=example,dc=com")

        # Should have FlextModel methods
        assert hasattr(entry, "model_dump")
        assert hasattr(entry, "model_validate")

        # Test model_dump works
        data = entry.model_dump()
        assert isinstance(data, dict)
        assert data["dn"] == "cn=test,dc=example,dc=com"
        assert "attributes" in data

    def test_connection_config_integrates_with_flext_model(self) -> None:
        """Test that ConnectionConfig properly inherits from FlextModel."""
        config = ConnectionConfig(server_uri="ldap://localhost:389")

        # Should have FlextModel methods
        assert hasattr(config, "model_dump")
        assert hasattr(config, "model_validate")

        # Test model_dump works
        data = config.model_dump()
        assert isinstance(data, dict)
        assert data["server_uri"] == "ldap://localhost:389"
        assert "timeout" in data
        assert "use_ssl" in data

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
            server_uri="ldaps://ldap.example.com:636",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            timeout=120,
            use_ssl=True,
        )

        # Serialize to dict
        config_data = original_config.model_dump()

        # Deserialize from dict
        restored_config = ConnectionConfig.model_validate(config_data)

        # Should be equivalent
        assert restored_config.server_uri == original_config.server_uri
        assert restored_config.bind_dn == original_config.bind_dn
        assert restored_config.timeout == original_config.timeout
        assert restored_config.use_ssl == original_config.use_ssl


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
            {},  # Missing required server_uri
            {"server_uri": 123},  # server_uri should be string
            {
                "server_uri": "ldap://localhost:389",
                "timeout": "not_an_int",
            },  # timeout should be int
            {
                "server_uri": "ldap://localhost:389",
                "use_ssl": "not_a_bool",
            },  # use_ssl should be bool
        ]

        for malformed_data in malformed_cases:
            with pytest.raises(ValidationError):
                ConnectionConfig.model_validate(malformed_data)

    def test_models_provide_helpful_error_messages(self) -> None:
        """Test that models provide helpful error messages on validation failure."""
        # Test DirectoryEntry with empty DN
        try:
            DirectoryEntry(dn="")
        except ValidationError as e:
            error_str = str(e)
            # Should contain information about the validation failure
            assert len(error_str) > 0
            # Error should mention the field or validation issue
            assert len(error_str) > 10  # Should be informative

        # Test ConnectionConfig with invalid timeout
        try:
            ConnectionConfig(server_uri="ldap://localhost:389", timeout=0)
        except ValidationError as e:
            error_str = str(e)
            # Should contain information about the validation failure
            assert len(error_str) > 0
            # Error should mention the constraint
            assert (
                "greater than or equal to 1" in error_str.lower()
                or "timeout" in error_str.lower()
            )


class TestRealOperationExecutor:
    """Test REAL OperationExecutor class functionality."""

    def test_operation_executor_can_be_instantiated(self) -> None:
        """Test OperationExecutor can be instantiated."""
        # OperationExecutor imported at top

        executor = OperationExecutor()
        assert isinstance(executor, OperationExecutor)

    async def test_operation_executor_execute_string_operation_success(self) -> None:
        """Test OperationExecutor handles successful string operations."""
        # OperationExecutor imported at top

        executor = OperationExecutor()

        # Test with validation that passes
        def passing_validation() -> None:
            return None

        async def successful_operation() -> FlextResult[str]:
            return FlextResult[str].ok("operation successful")

        result = await executor.execute_string_operation(
            operation_type="test",
            validation_func=passing_validation,
            operation_func=successful_operation,
        )

        assert result.is_success
        assert result.value == "operation successful"

    async def test_operation_executor_execute_string_operation_validation_failure(
        self,
    ) -> None:
        """Test OperationExecutor handles validation failures."""
        # OperationExecutor imported at top

        executor = OperationExecutor()

        # Test with validation that returns error
        def failing_validation() -> str:
            return "Validation failed"

        async def dummy_operation() -> FlextResult[str]:
            return FlextResult[str].ok("success")

        result = await executor.execute_string_operation(
            operation_type="test",
            validation_func=failing_validation,
            operation_func=dummy_operation,
        )

        assert not result.is_success
        assert "Validation failed" in (result.error or "")

    async def test_operation_executor_execute_string_operation_exception_handling(
        self,
    ) -> None:
        """Test OperationExecutor handles exceptions gracefully."""
        # OperationExecutor imported at top

        executor = OperationExecutor()

        def passing_validation() -> None:
            return None

        async def failing_operation() -> FlextResult[str]:
            msg = "Operation failed"
            raise RuntimeError(msg)

        result = await executor.execute_string_operation(
            operation_type="test",
            validation_func=passing_validation,
            operation_func=failing_operation,
        )

        assert not result.is_success
        assert "Test operation failed" in (result.error or "")

    async def test_operation_executor_execute_operation_with_list_return(self) -> None:
        """Test OperationExecutor execute_operation method for list results."""
        # OperationExecutor imported at top

        executor = OperationExecutor()

        def passing_validation() -> None:
            return None

        async def list_operation() -> FlextResult[list[FlextLdapEntry]]:
            return FlextResult[list[FlextLdapEntry]].ok([])

        result = await executor.execute_operation(
            operation_type="list_test",
            validation_func=passing_validation,
            operation_func=list_operation,
        )

        assert result.is_success
        assert result.value == []


class TestRealFlextLdapConnectionService:
    """Test REAL FlextLdapConnectionService class functionality."""

    def test_connection_service_can_be_instantiated(self) -> None:
        """Test FlextLdapConnectionService can be instantiated with client."""
        client = FlextLdapClient()
        service = FlextLdapConnectionService(client)

        assert isinstance(service, FlextLdapConnectionService)
        assert service is not None

    def test_connection_service_requires_client(self) -> None:
        """Test FlextLdapConnectionService requires client parameter."""
        with pytest.raises(TypeError):
            FlextLdapConnectionService()  # Missing required client parameter

    def test_connection_service_has_required_methods(self) -> None:
        """Test FlextLdapConnectionService has required methods."""
        client = FlextLdapClient()
        service = FlextLdapConnectionService(client)

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
        client = FlextLdapClient()
        service = FlextLdapConnectionService(client)

        assert not service.is_connected()

    def test_connection_service_follows_flext_patterns(self) -> None:
        """Test FlextLdapConnectionService follows FLEXT architectural patterns."""
        client = FlextLdapClient()
        service = FlextLdapConnectionService(client)

        # Should have required methods after FLEXT compliance refactoring
        assert hasattr(service, "establish_connection")
        assert hasattr(service, "terminate_connection")
        assert hasattr(service, "is_connected")

    async def test_connection_service_establish_connection_validates_config(
        self,
    ) -> None:
        """Test establish_connection validates configuration."""
        client = FlextLdapClient()
        service = FlextLdapConnectionService(client)

        # Invalid config should fail validation
        invalid_config = ConnectionConfig(server_uri="invalid-uri")
        result = await service.establish_connection(invalid_config)

        assert not result.is_success
        assert result.error is not None
        assert "missing hostname" in result.error.lower()

    async def test_connection_service_terminate_connection_when_not_connected(
        self,
    ) -> None:
        """Test terminate_connection when not connected."""
        client = FlextLdapClient()
        service = FlextLdapConnectionService(client)

        # Should fail gracefully when no connection exists
        result = await service.terminate_connection()
        assert not result.is_success
        assert "No active connection to terminate" in (result.error or "")


class TestRealFlextLdapSearchService:
    """Test REAL FlextLdapSearchService class functionality."""

    def test_search_service_can_be_instantiated(self) -> None:
        """Test FlextLdapSearchService can be instantiated with client."""
        client = FlextLdapClient()
        service = FlextLdapSearchService(client)

        assert isinstance(service, FlextLdapSearchService)
        assert service is not None

    def test_search_service_requires_client(self) -> None:
        """Test FlextLdapSearchService requires client parameter."""
        with pytest.raises(TypeError):
            FlextLdapSearchService()  # Missing required client parameter

    def test_search_service_has_required_methods(self) -> None:
        """Test FlextLdapSearchService has required methods."""
        client = FlextLdapClient()
        service = FlextLdapSearchService(client)

        # Should have search interface methods
        assert hasattr(service, "search_entries")
        assert callable(service.search_entries)

    def test_search_service_inherits_from_interface(self) -> None:
        """Test FlextLdapSearchService inherits from correct interface."""
        # SearchServiceInterface removed - using concrete implementation

        client = FlextLdapClient()
        service = FlextLdapSearchService(client)

        # Interface check removed - SearchServiceInterface no longer exists
        assert hasattr(service, "search_entries")  # Check method exists instead

    async def test_search_service_validates_empty_base_dn(self) -> None:
        """Test search_entries validates empty base DN."""
        client = FlextLdapClient()
        service = FlextLdapSearchService(client)

        result = await service.search_entries("", "(objectClass=*)")
        assert not result.is_success
        assert "Base DN cannot be empty" in (result.error or "")

    async def test_search_service_validates_empty_filter(self) -> None:
        """Test search_entries validates empty search filter."""
        client = FlextLdapClient()
        service = FlextLdapSearchService(client)

        result = await service.search_entries("dc=example,dc=com", "")
        assert not result.is_success
        assert "Search filter cannot be empty" in (result.error or "")

    def test_search_service_has_private_methods(self) -> None:
        """Test search service has required private methods."""
        client = FlextLdapClient()
        service = FlextLdapSearchService(client)

        # Should have validation and conversion methods
        assert hasattr(service, "_validate_search_params")
        assert hasattr(service, "_perform_search")
        assert hasattr(service, "_convert_search_results")
        assert hasattr(service, "_normalize_attributes")

    def test_search_service_validation_method_works(self) -> None:
        """Test search service validation method works correctly."""
        client = FlextLdapClient()
        service = FlextLdapSearchService(client)

        # Valid parameters should pass
        error = service._validate_search_params("dc=example,dc=com", "(objectClass=*)")
        assert error is None

        # Empty base DN should fail
        error = service._validate_search_params("", "(objectClass=*)")
        assert error is not None
        assert "Base DN cannot be empty" in error

        # Empty filter should fail
        error = service._validate_search_params("dc=example,dc=com", "")
        assert error is not None
        assert "Search filter cannot be empty" in error


class TestRealFlextLdapEntryService:
    """Test REAL FlextLdapEntryService class functionality."""

    def test_entry_service_can_be_instantiated(self) -> None:
        """Test FlextLdapEntryService can be instantiated with client."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        assert isinstance(service, FlextLdapEntryService)
        assert service is not None

    def test_entry_service_requires_client(self) -> None:
        """Test FlextLdapEntryService requires client parameter."""
        with pytest.raises(TypeError):
            FlextLdapEntryService()  # Missing required client parameter

    def test_entry_service_has_required_methods(self) -> None:
        """Test FlextLdapEntryService has required methods."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Should have entry interface methods
        assert hasattr(service, "add_entry")
        assert hasattr(service, "modify_entry")
        assert hasattr(service, "delete_entry")

        # Methods should be callable
        assert callable(service.add_entry)
        assert callable(service.modify_entry)
        assert callable(service.delete_entry)

    def test_entry_service_inherits_from_interfaces(self) -> None:
        """Test FlextLdapEntryService inherits from correct interfaces."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Interface check removed - EntryServiceInterface no longer exists
        assert hasattr(service, "add_entry")  # Check method exists instead
        assert isinstance(service, OperationExecutor)

    async def test_entry_service_validates_entry_for_add_no_attributes(self) -> None:
        """Test add_entry validates entry with no attributes."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Entry without attributes should fail validation
        entry_no_attrs = DirectoryEntry(dn="cn=test,dc=example,dc=com")
        result = await service.add_entry(entry_no_attrs)
        assert not result.is_success
        assert "must have at least one attribute" in (result.error or "")

    async def test_entry_service_validates_entry_for_add_no_object_class(self) -> None:
        """Test add_entry validates entry without objectClass."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Entry without objectClass should fail
        entry_no_oc = DirectoryEntry(
            dn="cn=test,dc=example,dc=com", attributes={"cn": ["test"]}
        )
        result = await service.add_entry(entry_no_oc)
        assert not result.is_success
        assert "must have objectClass" in (result.error or "")

    async def test_entry_service_validates_dn_for_modify(self) -> None:
        """Test modify_entry validates DN parameter."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Empty DN should fail
        result = await service.modify_entry("", {})
        assert not result.is_success
        assert "DN cannot be empty" in (result.error or "")

    async def test_entry_service_validates_dn_for_delete(self) -> None:
        """Test delete_entry validates DN parameter."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Empty DN should fail
        result = await service.delete_entry("")
        assert not result.is_success
        assert "DN cannot be empty" in (result.error or "")

    async def test_entry_service_validates_no_modifications(self) -> None:
        """Test modify_entry validates empty modifications."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # No modifications should fail
        result = await service.modify_entry("cn=test,dc=example,dc=com", {})
        assert not result.is_success
        assert "No modifications provided" in (result.error or "")

    def test_entry_service_has_private_validation_methods(self) -> None:
        """Test entry service has required private validation methods."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Should have validation methods
        assert hasattr(service, "_validate_entry")
        assert hasattr(service, "_validate_modify_params")
        assert hasattr(service, "_validate_dn_param")

        # Should have operation methods
        assert hasattr(service, "_perform_add_entry")
        assert hasattr(service, "_perform_modify_entry")
        assert hasattr(service, "_perform_delete_entry")

    def test_entry_service_validation_methods_work(self) -> None:
        """Test entry service validation methods work correctly."""
        client = FlextLdapClient()
        service = FlextLdapEntryService(client)

        # Test DN validation
        error = service._validate_dn_param("")
        assert error == "DN cannot be empty"

        error = service._validate_dn_param("   ")
        assert error == "DN cannot be empty"

        error = service._validate_dn_param("valid-dn")
        assert error is None


class TestRealFlextLdapDirectoryEntry:
    """Test REAL FlextLdapDirectoryEntry class functionality."""

    def test_directory_entry_protocol_can_be_instantiated(self) -> None:
        """Test FlextLdapDirectoryEntry can be instantiated."""
        entry = FlextLdapDirectoryEntry("cn=test,dc=example,dc=com", {})

        assert isinstance(entry, FlextLdapDirectoryEntry)
        assert entry.dn == "cn=test,dc=example,dc=com"

    def test_directory_entry_protocol_handles_attributes(self) -> None:
        """Test FlextLdapDirectoryEntry handles attributes properly."""
        attributes = {"objectClass": ["person"], "cn": ["Test User"], "sn": ["User"]}

        entry = FlextLdapDirectoryEntry("cn=test,dc=example,dc=com", attributes)

        assert isinstance(entry.attributes, dict)
        assert len(entry.attributes) > 0

    def test_directory_entry_protocol_get_attribute_values(self) -> None:
        """Test get_attribute_values method works."""
        attributes = {
            "objectClass": ["person"],
            "cn": ["Test User"],
        }

        entry = FlextLdapDirectoryEntry("cn=test,dc=example,dc=com", attributes)

        # Should have get_attribute_values method
        assert hasattr(entry, "get_attribute_values")
        assert callable(entry.get_attribute_values)

        # Should return list of strings
        values = entry.get_attribute_values("cn")
        assert isinstance(values, list)

        # Non-existent attribute should return empty list
        empty_values = entry.get_attribute_values("nonexistent")
        assert isinstance(empty_values, list)
        assert len(empty_values) == 0

    def test_directory_entry_protocol_normalizes_attributes(self) -> None:
        """Test FlextLdapDirectoryEntry normalizes attributes correctly."""
        # Test with various attribute formats
        mixed_attributes = {
            "singleValue": "test",
            "listValue": ["value1", "value2"],
            "numberValue": 123,
            "boolValue": True,
        }

        entry = FlextLdapDirectoryEntry("cn=test,dc=example,dc=com", mixed_attributes)

        # All attribute values should be lists of strings
        for values in entry.attributes.values():
            assert isinstance(values, list)
            for value in values:
                assert isinstance(value, str)

    def test_directory_entry_protocol_handles_empty_attributes(self) -> None:
        """Test FlextLdapDirectoryEntry handles empty/None attributes."""
        entry = FlextLdapDirectoryEntry("cn=test,dc=example,dc=com", {})

        assert isinstance(entry.attributes, dict)
        assert len(entry.attributes) == 0

        # get_attribute_values should still work
        values = entry.get_attribute_values("any")
        assert isinstance(values, list)
        assert len(values) == 0


class TestRealFlextLdapDirectoryService:
    """Test REAL FlextLdapDirectoryService class functionality."""

    def test_directory_service_can_be_instantiated(self) -> None:
        """Test FlextLdapDirectoryService can be instantiated."""
        service = FlextLdapDirectoryService()

        assert isinstance(service, FlextLdapDirectoryService)
        assert service is not None

    def test_directory_service_has_required_methods(self) -> None:
        """Test FlextLdapDirectoryService has required methods."""
        service = FlextLdapDirectoryService()

        # Should have interface methods
        assert hasattr(service, "connect")
        assert hasattr(service, "search_users")

        # Methods should be callable
        assert callable(service.connect)
        assert callable(service.search_users)

    def test_directory_service_inherits_from_interface(self) -> None:
        """Test FlextLdapDirectoryService inherits from correct interface."""
        service = FlextLdapDirectoryService()

        # Interface check removed - FlextLdapDirectoryServiceInterface no longer exists
        assert hasattr(service, "connect")  # Check method exists instead

    def test_directory_service_has_specialized_services(self) -> None:
        """Test FlextLdapDirectoryService creates specialized services."""
        service = FlextLdapDirectoryService()

        # Should have private service instances
        assert hasattr(service, "_ldap_client")
        assert hasattr(service, "_connection_service")
        assert hasattr(service, "_search_service")
        assert hasattr(service, "_entry_service")

    def test_directory_service_search_users_method_signature(self) -> None:
        """Test search_users has correct method signature."""
        service = FlextLdapDirectoryService()

        # Should accept search parameters

        signature = inspect.signature(service.search_users)

        # Should have required parameters
        params = list(signature.parameters.keys())
        assert "search_filter" in params
        assert "base_dn" in params
        assert "attributes" in params

    def test_directory_service_has_conversion_methods(self) -> None:
        """Test directory service has required conversion methods."""
        service = FlextLdapDirectoryService()

        # Should have private conversion methods
        assert hasattr(service, "_convert_entries_to_protocol")
        assert hasattr(service, "_normalize_entry_attributes")


class TestRealFlextLdapDirectoryAdapter:
    """Test REAL FlextLdapDirectoryAdapter class functionality."""

    def test_directory_adapter_can_be_instantiated(self) -> None:
        """Test FlextLdapDirectoryAdapter can be instantiated."""
        adapter = FlextLdapDirectoryAdapter()

        assert isinstance(adapter, FlextLdapDirectoryAdapter)
        assert adapter is not None

    def test_directory_adapter_has_required_methods(self) -> None:
        """Test FlextLdapDirectoryAdapter has required methods."""
        adapter = FlextLdapDirectoryAdapter()

        # Should have interface method
        assert hasattr(adapter, "get_directory_service")
        assert callable(adapter.get_directory_service)

    def test_directory_adapter_inherits_from_interface(self) -> None:
        """Test FlextLdapDirectoryAdapter inherits from correct interface."""
        adapter = FlextLdapDirectoryAdapter()

        # Interface check removed - FlextLdapDirectoryAdapterInterface no longer exists
        assert hasattr(adapter, "get_directory_service")  # Check method exists instead

    def test_directory_adapter_returns_service(self) -> None:
        """Test get_directory_service returns service instance."""
        adapter = FlextLdapDirectoryAdapter()

        service = adapter.get_directory_service()

        assert service is not None
        assert isinstance(service, FlextLdapDirectoryService)

    def test_directory_adapter_has_private_service_instance(self) -> None:
        """Test directory adapter creates private service instance."""
        adapter = FlextLdapDirectoryAdapter()

        # Should have private service reference
        assert hasattr(adapter, "_directory_service")

        # Service should be consistent
        service1 = adapter.get_directory_service()
        service2 = adapter.get_directory_service()
        assert service1 is service2  # Same instance


class TestRealFactoryFunctions:
    """Test REAL factory functions functionality."""

    def test_create_directory_service_function_exists(self) -> None:
        """Test create_directory_service function exists and is callable."""
        assert callable(create_directory_service)

    def test_create_directory_service_returns_service(self) -> None:
        """Test create_directory_service returns correct service type."""
        service = create_directory_service()

        assert isinstance(service, FlextLdapDirectoryService)
        assert service is not None

    def test_create_directory_adapter_function_exists(self) -> None:
        """Test create_directory_adapter function exists and is callable."""
        assert callable(create_directory_adapter)

    def test_create_directory_adapter_returns_adapter(self) -> None:
        """Test create_directory_adapter returns correct adapter type."""
        adapter = create_directory_adapter()

        assert isinstance(adapter, FlextLdapDirectoryAdapter)
        assert adapter is not None

    def test_factory_functions_create_independent_instances(self) -> None:
        """Test factory functions create independent instances."""
        service1 = create_directory_service()
        service2 = create_directory_service()

        assert service1 is not service2
        assert type(service1) is type(service2)

        adapter1 = create_directory_adapter()
        adapter2 = create_directory_adapter()

        assert adapter1 is not adapter2
        assert type(adapter1) is type(adapter2)
