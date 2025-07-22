"""Tests for domain ports (service interfaces).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from abc import ABC
from typing import Any

import pytest

from flext_ldap.domain import ports


class TestLDAPConnectionService:
    """Test suite for LDAPConnectionService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that LDAPConnectionService is an abstract base class."""
        assert issubclass(ports.LDAPConnectionService, ABC)
        assert inspect.isabstract(ports.LDAPConnectionService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that LDAPConnectionService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.LDAPConnectionService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.LDAPConnectionService.__abstractmethods__
        expected_methods = {
            "connect",
            "disconnect",
            "bind",
            "unbind",
            "test_connection",
            "get_connection_info",
        }

        assert abstract_methods == expected_methods

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test connect method signature
        connect_sig = inspect.signature(ports.LDAPConnectionService.connect)
        assert "self" in connect_sig.parameters
        assert "server_url" in connect_sig.parameters
        assert "bind_dn" in connect_sig.parameters
        assert "password" in connect_sig.parameters

        # Test disconnect method signature
        disconnect_sig = inspect.signature(ports.LDAPConnectionService.disconnect)
        assert "self" in disconnect_sig.parameters
        assert "connection" in disconnect_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteConnectionService(ports.LDAPConnectionService):
            async def connect(
                self,
                server_url: str,
                bind_dn: str | None = None,
                password: str | None = None,
            ) -> Any:
                return None

            async def disconnect(self, connection: Any) -> Any:
                return None

            async def bind(self, connection: Any, bind_dn: str, password: str) -> Any:
                return None

            async def unbind(self, connection: Any) -> Any:
                return None

            async def test_connection(self, connection: Any) -> Any:
                return None

            async def get_connection_info(self, connection: Any) -> Any:
                return None

        # Should not raise any errors
        service = ConcreteConnectionService()
        assert isinstance(service, ports.LDAPConnectionService)


class TestLDAPSearchService:
    """Test suite for LDAPSearchService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that LDAPSearchService is an abstract base class."""
        assert issubclass(ports.LDAPSearchService, ABC)
        assert inspect.isabstract(ports.LDAPSearchService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that LDAPSearchService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.LDAPSearchService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.LDAPSearchService.__abstractmethods__
        expected_methods = {"search", "search_users"}

        assert abstract_methods == expected_methods

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test search method signature
        search_sig = inspect.signature(ports.LDAPSearchService.search)
        assert "self" in search_sig.parameters
        assert "connection" in search_sig.parameters
        assert "base_dn" in search_sig.parameters
        assert "filter_string" in search_sig.parameters
        assert "attributes" in search_sig.parameters
        assert "scope" in search_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteSearchService(ports.LDAPSearchService):
            async def search(
                self,
                connection: Any,
                base_dn: str,
                filter_string: str,
                attributes: list[str] | None = None,
                scope: str = "sub",
            ) -> Any:
                return None

            async def search_users(
                self,
                connection: Any,
                base_dn: str,
                filter_string: str | None = None,
            ) -> Any:
                return None

        # Should not raise any errors
        service = ConcreteSearchService()
        assert isinstance(service, ports.LDAPSearchService)


class TestLDAPUserService:
    """Test suite for LDAPUserService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that LDAPUserService is an abstract base class."""
        assert issubclass(ports.LDAPUserService, ABC)
        assert inspect.isabstract(ports.LDAPUserService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that LDAPUserService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.LDAPUserService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.LDAPUserService.__abstractmethods__
        expected_methods = {
            "create_user",
            "get_user",
            "update_user",
            "delete_user",
            "list_users",
        }

        assert abstract_methods == expected_methods

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test create_user method signature
        create_sig = inspect.signature(ports.LDAPUserService.create_user)
        assert "self" in create_sig.parameters
        assert "connection" in create_sig.parameters
        assert "dn" in create_sig.parameters
        assert "attributes" in create_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteUserService(ports.LDAPUserService):
            async def create_user(
                self,
                connection: Any,
                dn: str,
                attributes: dict[str, list[str]],
            ) -> Any:
                return None

            async def get_user(self, connection: Any, dn: str) -> Any:
                return None

            async def update_user(
                self,
                connection: Any,
                dn: str,
                modifications: dict[str, list[str]],
            ) -> Any:
                return None

            async def delete_user(self, connection: Any, dn: str) -> Any:
                return None

            async def list_users(
                self,
                connection: Any,
                base_dn: str,
                limit: int = 100,
            ) -> Any:
                return None

        # Should not raise any errors
        service = ConcreteUserService()
        assert isinstance(service, ports.LDAPUserService)


class TestLDAPSchemaService:
    """Test suite for LDAPSchemaService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that LDAPSchemaService is an abstract base class."""
        assert issubclass(ports.LDAPSchemaService, ABC)
        assert inspect.isabstract(ports.LDAPSchemaService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that LDAPSchemaService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.LDAPSchemaService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.LDAPSchemaService.__abstractmethods__
        expected_methods = {"get_schema", "validate_entry"}

        assert abstract_methods == expected_methods

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteSchemaService(ports.LDAPSchemaService):
            async def get_schema(self, connection: Any) -> Any:
                return None

            async def validate_entry(
                self,
                connection: Any,
                dn: str,
                attributes: dict[str, list[str]],
            ) -> Any:
                return None

        # Should not raise any errors
        service = ConcreteSchemaService()
        assert isinstance(service, ports.LDAPSchemaService)


class TestLDAPMigrationService:
    """Test suite for LDAPMigrationService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that LDAPMigrationService is an abstract base class."""
        assert issubclass(ports.LDAPMigrationService, ABC)
        assert inspect.isabstract(ports.LDAPMigrationService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that LDAPMigrationService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.LDAPMigrationService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.LDAPMigrationService.__abstractmethods__
        expected_methods = {"export_entries", "import_entries", "migrate_users"}

        assert abstract_methods == expected_methods

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test export_entries method signature
        export_sig = inspect.signature(ports.LDAPMigrationService.export_entries)
        assert "self" in export_sig.parameters
        assert "connection" in export_sig.parameters
        assert "base_dn" in export_sig.parameters
        assert "output_format" in export_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteMigrationService(ports.LDAPMigrationService):
            async def export_entries(
                self,
                connection: Any,
                base_dn: str,
                output_format: str = "ldif",
            ) -> Any:
                return None

            async def import_entries(
                self,
                connection: Any,
                data: str,
                format_type: str = "ldif",
            ) -> Any:
                return None

            async def migrate_users(
                self,
                source_connection: Any,
                target_connection: Any,
                base_dn: str,
            ) -> Any:
                return None

        # Should not raise any errors
        service = ConcreteMigrationService()
        assert isinstance(service, ports.LDAPMigrationService)


class TestPortsModule:
    """Test suite for the ports module as a whole."""

    def test_all_services_defined(self) -> None:
        """Test that all expected service interfaces are defined."""
        expected_services = [
            "LDAPConnectionService",
            "LDAPSearchService",
            "LDAPUserService",
            "LDAPSchemaService",
            "LDAPMigrationService",
        ]

        for service_name in expected_services:
            assert hasattr(ports, service_name)
            service_class = getattr(ports, service_name)
            assert issubclass(service_class, ABC)

    def test_no_concrete_implementations(self) -> None:
        """Test that all services are abstract (no concrete implementations)."""
        for name in dir(ports):
            obj = getattr(ports, name)
            if (
                inspect.isclass(obj)
                and name.endswith("Service")
                and not name.startswith("_")
            ):
                assert inspect.isabstract(obj), f"{name} should be abstract"

    def test_module_docstring(self) -> None:
        """Test that module has proper docstring."""
        assert ports.__doc__ is not None
        assert "Domain ports" in ports.__doc__
        assert "service interfaces" in ports.__doc__

    def test_type_checking_imports(self) -> None:
        """Test that TYPE_CHECKING imports are properly defined."""
        # This tests that the module can be imported without circular import issues
        import flext_ldap.domain.ports

        # Test that the module has the expected structure
        assert hasattr(flext_ldap.domain.ports, "LDAPConnectionService")
        assert hasattr(flext_ldap.domain.ports, "LDAPSearchService")
        assert hasattr(flext_ldap.domain.ports, "LDAPUserService")
        assert hasattr(flext_ldap.domain.ports, "LDAPSchemaService")
        assert hasattr(flext_ldap.domain.ports, "LDAPMigrationService")
