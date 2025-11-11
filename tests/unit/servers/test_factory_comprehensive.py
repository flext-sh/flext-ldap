"""Comprehensive real Docker LDAP tests for FlextLdapServersFactory.

This module contains comprehensive tests for FlextLdapServersFactory using real Docker
LDAP containers. All tests use actual LDAP operations without any mocks, stubs,
or wrappers.

Test Categories:
- @pytest.mark.docker - Requires Docker LDAP container
- @pytest.mark.unit - Unit tests with real LDAP operations

Container Requirements:
    Docker container must be running on port 3390
    Base DN: dc=flext,dc=local
    Admin DN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
    Admin password: REDACTED_LDAP_BIND_PASSWORD123
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClients, FlextLdapModels
from flext_ldap.servers.factory import FlextLdapServersFactory

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapServersFactoryCreation:
    """Test factory creation methods with real LDAP operations."""

    @pytest.fixture(autouse=True)
    def factory(self) -> FlextLdapServersFactory:
        """Provide a factory instance."""
        return FlextLdapServersFactory()

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        request = FlextLdapModels.ConnectionRequest(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        client.connect(request)
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_server_type_openldap2(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test creating operations from explicit OpenLDAP2 server type."""
        result = factory.create_from_server_type("openldap2")

        assert result.is_success is True
        operations = result.unwrap()
        assert operations is not None
        assert operations.server_type == "openldap2"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_server_type_generic(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test creating operations from generic server type."""
        result = factory.create_from_server_type("generic")

        assert result.is_success is True
        operations = result.unwrap()
        assert operations is not None
        assert operations.server_type == "generic"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_server_type_case_insensitive(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test server type matching is case insensitive."""
        result = factory.create_from_server_type("OPENLDAP2")

        assert result.is_success is True
        operations = result.unwrap()
        assert operations is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_server_type_empty_fails(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test creating from empty server type fails."""
        result = factory.create_from_server_type("")

        assert result.is_failure is True
        assert result.error and "empty" in result.error.lower()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_server_type_unknown_defaults_to_generic(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test unknown server type defaults to generic operations."""
        result = factory.create_from_server_type("unknown-server-xyz")

        assert result.is_success is True
        operations = result.unwrap()
        assert operations is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_connection_success(
        self, factory: FlextLdapServersFactory, connected_client: FlextLdapClients
    ) -> None:
        """Test creating operations from real LDAP connection."""
        result = factory.create_from_connection(connected_client.connection)

        assert result.is_success is True
        operations = result.unwrap()
        assert operations is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_connection_none_fails(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test creating from None connection fails."""
        result = factory.create_from_connection(None)

        assert result.is_failure is True
        assert result.error and "connection" in result.error.lower()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_detect_server_type_from_root_dse(
        self, factory: FlextLdapServersFactory, connected_client: FlextLdapClients
    ) -> None:
        """Test detecting server type from root DSE."""
        result = factory.detect_server_type_from_root_dse(connected_client.connection)

        assert result.is_success is True
        server_type = result.unwrap()
        assert isinstance(server_type, str)
        assert len(server_type) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_detect_server_type_from_none_connection_fails(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test detecting from None connection fails gracefully."""
        result = factory.detect_server_type_from_root_dse(None)

        assert result.is_failure is True
        assert result.error and "connection" in result.error.lower()


class TestFlextLdapServersFactorySupportedTypes:
    """Test factory supported types and registry methods."""

    @pytest.fixture(autouse=True)
    def factory(self) -> FlextLdapServersFactory:
        """Provide a factory instance."""
        return FlextLdapServersFactory()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_supported_server_types(self, factory: FlextLdapServersFactory) -> None:
        """Test getting list of supported server types."""
        types = factory.get_supported_server_types()

        assert isinstance(types, list)
        assert len(types) > 0
        assert "openldap2" in types
        assert "generic" in types

    @pytest.mark.docker
    @pytest.mark.unit
    def test_is_server_type_supported_true(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test checking supported server type returns True."""
        supported = factory.is_server_type_supported("openldap2")

        assert supported is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_is_server_type_supported_false(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test checking unsupported server type returns False."""
        supported = factory.is_server_type_supported("unknown-xyz")

        assert supported is False

    @pytest.mark.docker
    @pytest.mark.unit
    def test_is_server_type_supported_case_insensitive(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test supported type check is case insensitive."""
        supported = factory.is_server_type_supported("OPENLDAP2")

        assert supported is True


class TestFlextLdapServersFactoryServerInfo:
    """Test factory server information retrieval."""

    @pytest.fixture(autouse=True)
    def factory(self) -> FlextLdapServersFactory:
        """Provide a factory instance."""
        return FlextLdapServersFactory()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info_openldap2(self, factory: FlextLdapServersFactory) -> None:
        """Test getting server information for OpenLDAP2."""
        result = factory.get_server_info("openldap2")

        assert result.is_success is True
        info = result.unwrap()
        assert isinstance(info, dict)
        assert "server_type" in info
        assert "class_name" in info
        assert "default_port" in info
        assert info["default_port"] == 389

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info_ssl_port(self, factory: FlextLdapServersFactory) -> None:
        """Test getting SSL port information."""
        result = factory.get_server_info("openldap2")

        assert result.is_success is True
        info = result.unwrap()
        assert "default_ssl_port" in info
        assert info["default_ssl_port"] == 636

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info_supports_tls(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test getting TLS support information."""
        result = factory.get_server_info("openldap2")

        assert result.is_success is True
        info = result.unwrap()
        assert "supports_start_tls" in info
        assert info["supports_start_tls"] is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info_bind_mechanisms(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test getting bind mechanisms information."""
        result = factory.get_server_info("openldap2")

        assert result.is_success is True
        info = result.unwrap()
        assert "bind_mechanisms" in info
        assert isinstance(info["bind_mechanisms"], list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info_schema_dn(self, factory: FlextLdapServersFactory) -> None:
        """Test getting schema DN information."""
        result = factory.get_server_info("openldap2")

        assert result.is_success is True
        info = result.unwrap()
        assert "schema_dn" in info
        assert isinstance(info["schema_dn"], str)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info_unsupported_type_fails(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test getting info for unsupported server type fails."""
        result = factory.get_server_info("unknown-server-xyz")

        assert result.is_failure is True
        assert result.error and "unsupported" in result.error.lower()


class TestFlextLdapServersFactoryOperationsInstances:
    """Test that factory creates correct operation instances."""

    @pytest.fixture(autouse=True)
    def factory(self) -> FlextLdapServersFactory:
        """Provide a factory instance."""
        return FlextLdapServersFactory()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_created_operations_has_required_methods(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test created operations instance has required methods."""
        result = factory.create_from_server_type("openldap2")

        assert result.is_success is True
        operations = result.unwrap()

        # Check required methods exist
        assert hasattr(operations, "get_schema_dn")
        assert hasattr(operations, "get_default_port")
        assert hasattr(operations, "supports_start_tls")
        assert hasattr(operations, "get_bind_mechanisms")

    @pytest.mark.docker
    @pytest.mark.unit
    def test_operations_instance_callable(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test operations instance methods are callable."""
        result = factory.create_from_server_type("openldap2")

        assert result.is_success is True
        operations = result.unwrap()

        # Test calling methods
        port = operations.get_default_port()
        assert isinstance(port, int)

        tls_supported = operations.supports_start_tls()
        assert isinstance(tls_supported, bool)

        mechanisms = operations.get_bind_mechanisms()
        assert isinstance(mechanisms, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_different_server_types_have_different_instances(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test creating from different types creates different instances."""
        result1 = factory.create_from_server_type("openldap2")
        result2 = factory.create_from_server_type("generic")

        assert result1.is_success is True
        assert result2.is_success is True

        ops1 = result1.unwrap()
        ops2 = result2.unwrap()

        # Same type should have different instances
        assert ops1 is not ops2


class TestFlextLdapServersFactoryEdgeCases:
    """Test factory edge cases and error handling."""

    @pytest.fixture(autouse=True)
    def factory(self) -> FlextLdapServersFactory:
        """Provide a factory instance."""
        return FlextLdapServersFactory()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_server_type_with_whitespace(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test server type with whitespace is handled."""
        result = factory.create_from_server_type("  openldap2  ")

        assert result.is_success is True
        operations = result.unwrap()
        assert operations is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_multiple_instances_from_same_type(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test creating multiple instances from same type works."""
        result1 = factory.create_from_server_type("openldap2")
        result2 = factory.create_from_server_type("openldap2")

        assert result1.is_success is True
        assert result2.is_success is True

        ops1 = result1.unwrap()
        ops2 = result2.unwrap()

        # Different instances despite same type
        assert ops1 is not ops2

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_from_entries_empty_list(
        self, factory: FlextLdapServersFactory
    ) -> None:
        """Test creating from empty entry list defaults to generic."""
        result = factory.create_from_entries([])

        assert result.is_success is True
        operations = result.unwrap()
        assert operations is not None


__all__ = [
    "TestFlextLdapServersFactoryCreation",
    "TestFlextLdapServersFactoryEdgeCases",
    "TestFlextLdapServersFactoryOperationsInstances",
    "TestFlextLdapServersFactoryServerInfo",
    "TestFlextLdapServersFactorySupportedTypes",
]
