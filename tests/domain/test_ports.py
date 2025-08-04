"""Tests for domain ports (service interfaces).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import inspect
from abc import ABC
from typing import TYPE_CHECKING

import flext_ldap.domain.ports
import pytest
from flext_ldap.domain import ports

if TYPE_CHECKING:
    from flext_core import FlextResult
    from flext_ldap.entities import FlextLdapConnection


class TestFlextLdapConnectionService:
    """Test suite for FlextLdapConnectionService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that FlextLdapConnectionService is an abstract base class."""
        assert issubclass(ports.FlextLdapConnectionService, ABC)
        assert inspect.isabstract(ports.FlextLdapConnectionService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that FlextLdapConnectionService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.FlextLdapConnectionService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.FlextLdapConnectionService.__abstractmethods__
        expected_methods = {
            "connect",
            "disconnect",
            "bind",
            "unbind",
            "test_connection",
            "get_connection_info",
        }

        if abstract_methods != expected_methods:
            msg: str = f"Expected {expected_methods}, got {abstract_methods}"
            raise AssertionError(msg)

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test connect method signature
        connect_sig = inspect.signature(ports.FlextLdapConnectionService.connect)
        if "self" not in connect_sig.parameters:
            msg: str = f"Expected {'self'} in {connect_sig.parameters}"
            raise AssertionError(msg)
        assert "server_url" in connect_sig.parameters
        if "bind_dn" not in connect_sig.parameters:
            msg: str = f"Expected {'bind_dn'} in {connect_sig.parameters}"
            raise AssertionError(msg)
        assert "password" in connect_sig.parameters

        # Test disconnect method signature
        disconnect_sig = inspect.signature(ports.FlextLdapConnectionService.disconnect)
        if "self" not in disconnect_sig.parameters:
            msg: str = f"Expected {'self'} in {disconnect_sig.parameters}"
            raise AssertionError(msg)
        assert "connection" in disconnect_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteConnectionService(ports.FlextLdapConnectionService):
            async def connect(
                self,
                server_url: str,
                bind_dn: str | None = None,
                password: str | None = None,
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def disconnect(
                self, connection: FlextLdapConnection
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def bind(
                self, connection: FlextLdapConnection, bind_dn: str, password: str
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def unbind(
                self, connection: FlextLdapConnection
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def test_connection(
                self, connection: FlextLdapConnection
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def get_connection_info(
                self, connection: FlextLdapConnection
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

        # Should not raise any errors
        service = ConcreteConnectionService()
        assert isinstance(service, ports.FlextLdapConnectionService)


class TestFlextLdapSearchService:
    """Test suite for FlextLdapSearchService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that FlextLdapSearchService is an abstract base class."""
        assert issubclass(ports.FlextLdapSearchService, ABC)
        assert inspect.isabstract(ports.FlextLdapSearchService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that FlextLdapSearchService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.FlextLdapSearchService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.FlextLdapSearchService.__abstractmethods__
        expected_methods = {"search", "search_users"}

        if abstract_methods != expected_methods:
            msg: str = f"Expected {expected_methods}, got {abstract_methods}"
            raise AssertionError(msg)

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test search method signature
        search_sig = inspect.signature(ports.FlextLdapSearchService.search)
        if "self" not in search_sig.parameters:
            msg: str = f"Expected {'self'} in {search_sig.parameters}"
            raise AssertionError(msg)
        assert "connection" in search_sig.parameters
        if "base_dn" not in search_sig.parameters:
            msg: str = f"Expected {'base_dn'} in {search_sig.parameters}"
            raise AssertionError(msg)
        assert "filter_string" in search_sig.parameters
        if "attributes" not in search_sig.parameters:
            msg: str = f"Expected {'attributes'} in {search_sig.parameters}"
            raise AssertionError(msg)
        assert "scope" in search_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteSearchService(ports.FlextLdapSearchService):
            async def search(
                self,
                connection: FlextLdapConnection,
                base_dn: str,
                filter_string: str,
                attributes: list[str] | None = None,
                scope: str = "sub",
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def search_users(
                self,
                connection: FlextLdapConnection,
                base_dn: str,
                filter_string: str | None = None,
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

        # Should not raise any errors
        service = ConcreteSearchService()
        assert isinstance(service, ports.FlextLdapSearchService)


class TestFlextLdapUserService:
    """Test suite for FlextLdapUserService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that FlextLdapUserService is an abstract base class."""
        assert issubclass(ports.FlextLdapUserService, ABC)
        assert inspect.isabstract(ports.FlextLdapUserService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that FlextLdapUserService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.FlextLdapUserService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.FlextLdapUserService.__abstractmethods__
        expected_methods = {
            "create_user",
            "get_user",
            "update_user",
            "delete_user",
            "list_users",
        }

        if abstract_methods != expected_methods:
            msg: str = f"Expected {expected_methods}, got {abstract_methods}"
            raise AssertionError(msg)

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test create_user method signature
        create_sig = inspect.signature(ports.FlextLdapUserService.create_user)
        if "self" not in create_sig.parameters:
            msg: str = f"Expected {'self'} in {create_sig.parameters}"
            raise AssertionError(msg)
        assert "connection" in create_sig.parameters
        if "dn" not in create_sig.parameters:
            msg: str = f"Expected {'dn'} in {create_sig.parameters}"
            raise AssertionError(msg)
        assert "attributes" in create_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteUserService(ports.FlextLdapUserService):
            async def create_user(
                self,
                connection: FlextLdapConnection,
                dn: str,
                attributes: dict[str, list[str]],
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def get_user(
                self, connection: FlextLdapConnection, dn: str
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def update_user(
                self,
                connection: FlextLdapConnection,
                dn: str,
                modifications: dict[str, list[str]],
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def delete_user(
                self, connection: FlextLdapConnection, dn: str
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def list_users(
                self,
                connection: FlextLdapConnection,
                base_dn: str,
                limit: int = 100,
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

        # Should not raise any errors
        service = ConcreteUserService()
        assert isinstance(service, ports.FlextLdapUserService)


class TestFlextLdapSchemaService:
    """Test suite for FlextLdapSchemaService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that FlextLdapSchemaService is an abstract base class."""
        assert issubclass(ports.FlextLdapSchemaService, ABC)
        assert inspect.isabstract(ports.FlextLdapSchemaService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that FlextLdapSchemaService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.FlextLdapSchemaService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.FlextLdapSchemaService.__abstractmethods__
        expected_methods = {"get_schema", "validate_entry"}

        if abstract_methods != expected_methods:
            msg: str = f"Expected {expected_methods}, got {abstract_methods}"
            raise AssertionError(msg)

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteSchemaService(ports.FlextLdapSchemaService):
            async def get_schema(
                self, connection: FlextLdapConnection
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def validate_entry(
                self,
                connection: FlextLdapConnection,
                dn: str,
                attributes: dict[str, list[str]],
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

        # Should not raise any errors
        service = ConcreteSchemaService()
        assert isinstance(service, ports.FlextLdapSchemaService)


class TestFlextLdapMigrationService:
    """Test suite for FlextLdapMigrationService interface."""

    def test_is_abstract_base_class(self) -> None:
        """Test that FlextLdapMigrationService is an abstract base class."""
        assert issubclass(ports.FlextLdapMigrationService, ABC)
        assert inspect.isabstract(ports.FlextLdapMigrationService)

    def test_cannot_instantiate_directly(self) -> None:
        """Test that FlextLdapMigrationService cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ports.FlextLdapMigrationService()  # Intentionally trying to instantiate abstract class

    def test_has_required_abstract_methods(self) -> None:
        """Test that all required abstract methods are defined."""
        abstract_methods = ports.FlextLdapMigrationService.__abstractmethods__
        expected_methods = {"export_entries", "import_entries", "migrate_users"}

        if abstract_methods != expected_methods:
            msg: str = f"Expected {expected_methods}, got {abstract_methods}"
            raise AssertionError(msg)

    def test_method_signatures(self) -> None:
        """Test that abstract method signatures are correct."""
        # Test export_entries method signature
        export_sig = inspect.signature(ports.FlextLdapMigrationService.export_entries)
        if "self" not in export_sig.parameters:
            msg: str = f"Expected {'self'} in {export_sig.parameters}"
            raise AssertionError(msg)
        assert "connection" in export_sig.parameters
        if "base_dn" not in export_sig.parameters:
            msg: str = f"Expected {'base_dn'} in {export_sig.parameters}"
            raise AssertionError(msg)
        assert "output_format" in export_sig.parameters

    def test_concrete_implementation_works(self) -> None:
        """Test that concrete implementation can be created."""

        class ConcreteMigrationService(ports.FlextLdapMigrationService):
            async def export_entries(
                self,
                connection: FlextLdapConnection,
                base_dn: str,
                output_format: str = "ldif",
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def import_entries(
                self,
                connection: FlextLdapConnection,
                data: str,
                format_type: str = "ldif",
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

            async def migrate_users(
                self,
                source_connection: FlextLdapConnection,
                target_connection: FlextLdapConnection,
                base_dn: str,
            ) -> FlextResult[object]:
                from flext_core import FlextResult

                return FlextResult.success(None)

        # Should not raise any errors
        service = ConcreteMigrationService()
        assert isinstance(service, ports.FlextLdapMigrationService)


class TestPortsModule:
    """Test suite for the ports module as a whole."""

    def test_all_services_defined(self) -> None:
        """Test that all expected service interfaces are defined."""
        expected_services = [
            "FlextLdapConnectionService",
            "FlextLdapSearchService",
            "FlextLdapUserService",
            "FlextLdapSchemaService",
            "FlextLdapMigrationService",
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
        if "Domain ports" not in ports.__doc__:
            msg: str = f"Expected {'Domain ports'} in {ports.__doc__}"
            raise AssertionError(msg)
        assert "service interfaces" in ports.__doc__

    def test_type_checking_imports(self) -> None:
        """Test that TYPE_CHECKING imports are properly defined."""
        # This tests that the module can be imported without circular import issues

        # Test that the module has the expected structure
        assert hasattr(flext_ldap.domain.ports, "FlextLdapConnectionService")
        assert hasattr(flext_ldap.domain.ports, "FlextLdapSearchService")
        assert hasattr(flext_ldap.domain.ports, "FlextLdapUserService")
        assert hasattr(flext_ldap.domain.ports, "FlextLdapSchemaService")
        assert hasattr(flext_ldap.domain.ports, "FlextLdapMigrationService")
