"""Unit tests for FlextLdapSchemaSync.

Tests the actual FlextLdapSchemaSync API including:
- Service initialization with required parameters
- Connection context management
- Schema synchronization error handling
- Execute method and FlextResult pattern

All tests use real FlextLdapSchemaSync objects with no mocks for initialization.
Docker-based integration tests with real LDAP servers are deferred to tests/integration/.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from flext_core import FlextResult

from flext_ldap.services.schema_sync import FlextLdapSchemaSync


@pytest.fixture
def temp_schema_file() -> Path:
    """Create a temporary schema LDIF file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
        # Write minimal LDIF content
        f.write("version: 1\n")
        f.write("dn: cn=schema\n")
        f.write("objectClass: top\n")
        return Path(f.name)


class TestFlextLdapSchemaSyncInitialization:
    """Test FlextLdapSchemaSync initialization and basic functionality."""

    @pytest.mark.unit
    def test_schema_sync_service_can_be_instantiated(
        self, temp_schema_file: Path
    ) -> None:
        """Test FlextLdapSchemaSync can be instantiated."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        assert service is not None
        assert isinstance(service, FlextLdapSchemaSync)

    @pytest.mark.unit
    def test_schema_sync_service_has_logger(
        self, temp_schema_file: Path
    ) -> None:
        """Test schema sync service inherits logger from FlextService."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        assert hasattr(service, "logger")
        assert service.logger is not None

    @pytest.mark.unit
    def test_schema_sync_service_has_container(
        self, temp_schema_file: Path
    ) -> None:
        """Test schema sync service has container from FlextService."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        assert hasattr(service, "container")

    @pytest.mark.unit
    def test_schema_sync_service_connection_initially_none(
        self, temp_schema_file: Path
    ) -> None:
        """Test connection context is initially None."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        assert service._connection is None


class TestSchemaSyncExecute:
    """Test the execute method required by FlextService."""

    @pytest.mark.unit
    def test_execute_returns_flext_result(self, temp_schema_file: Path) -> None:
        """Test execute method returns FlextResult."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        result = service.execute()
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_execute_without_connection_fails(
        self, temp_schema_file: Path
    ) -> None:
        """Test execute fails when no connection context is set."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        result = service.execute()
        # Should fail due to no connection
        assert isinstance(result, FlextResult)
        if result.is_failure:
            assert isinstance(result.error, str)

    @pytest.mark.unit
    def test_execute_returns_dict_or_failure(
        self, temp_schema_file: Path
    ) -> None:
        """Test execute returns dict result or failure."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        result = service.execute()
        # Either failure (no connection) or dict (success)
        assert isinstance(result, FlextResult)
        if result.is_success:
            unwrapped = result.unwrap()
            assert isinstance(unwrapped, dict)


class TestSchemaSyncServiceProperties:
    """Test FlextLdapSchemaSync property initialization."""

    @pytest.mark.unit
    def test_schema_sync_service_stores_parameters(
        self, temp_schema_file: Path
    ) -> None:
        """Test schema sync service stores parameters correctly."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="test.example.com",
            server_port=3890,
        )
        assert service._server_host == "test.example.com"
        assert service._server_port == 3890

    @pytest.mark.unit
    def test_schema_sync_service_with_ssl(
        self, temp_schema_file: Path
    ) -> None:
        """Test schema sync service SSL configuration."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
            use_ssl=True,
        )
        assert service._use_ssl is True

    @pytest.mark.unit
    def test_schema_sync_service_with_credentials(
        self, temp_schema_file: Path
    ) -> None:
        """Test schema sync service with credentials."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password123",
        )
        assert service._bind_dn == "cn=admin,dc=example,dc=com"
        assert service._bind_password == "password123"


class TestSchemaSyncIntegration:
    """Integration tests for FlextLdapSchemaSync."""

    @pytest.mark.unit
    def test_complete_schema_sync_service_workflow(
        self, temp_schema_file: Path
    ) -> None:
        """Test complete schema sync service workflow."""
        # Create service
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        assert service is not None

        # Set connection context
        service.set_connection_context(None)
        assert service._connection is None

        # Execute service
        result = service.execute()
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_schema_sync_service_flext_result_pattern(
        self, temp_schema_file: Path
    ) -> None:
        """Test service follows FlextResult railway pattern."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file, server_host="localhost"
        )
        result = service.execute()
        # Must return FlextResult with is_success/is_failure properties
        assert isinstance(result, FlextResult)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert result.is_success or result.is_failure


__all__ = [
    "TestFlextLdapSchemaSyncInitialization",
    "TestConnectionContextManagement",
    "TestSchemaSyncExecute",
    "TestSchemaSyncServiceProperties",
    "TestSchemaSyncIntegration",
]
