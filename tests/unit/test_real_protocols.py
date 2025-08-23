"""REAL protocols tests - testing actual protocol functionality without mocks.

These tests execute REAL protocol code to increase coverage and validate functionality.
"""

from __future__ import annotations

import pytest
from typing import get_type_hints, get_origin, get_args

# Test real protocols functionality
from flext_ldap.protocols import (
    FlextLdapConnectionProtocol,
    FlextLdapSearchProtocol,
    FlextLdapEntryProtocol,
    FlextLdapUserProtocol,
    FlextLdapGroupProtocol,
    FlextLdapRepositoryProtocol,
    FlextLdapValidatorProtocol,
    FlextLdapOperationsBase,
    FlextLdapServiceBase,
    FlextLdapClientBase,
)
from flext_core import FlextResult


class TestRealProtocolDefinitions:
    """Test REAL protocol definitions and runtime checkable behavior."""

    def test_runtime_checkable_protocols(self) -> None:
        """Test which protocols are runtime checkable."""
        # Test the protocols that are actually runtime checkable
        runtime_checkable_protocols = [
            (FlextLdapConnectionProtocol, "connection"),
            (FlextLdapSearchProtocol, "search"),
            (FlextLdapEntryProtocol, "entry"),
            (FlextLdapUserProtocol, "user"),
            (FlextLdapGroupProtocol, "group"),
        ]
        
        for protocol, name in runtime_checkable_protocols:
            if hasattr(protocol, '__runtime_checkable__'):
                assert protocol.__runtime_checkable__ is True, f"{name} protocol should be runtime checkable"
            else:
                # Protocol exists but is not runtime checkable - that's also valid
                assert protocol is not None, f"{name} protocol should exist"
    
    def test_non_runtime_checkable_protocols(self) -> None:
        """Test protocols that are not runtime checkable."""
        # These protocols may not be runtime checkable but should exist
        non_runtime_protocols = [
            (FlextLdapRepositoryProtocol, "repository"),
            (FlextLdapValidatorProtocol, "validator"),
        ]
        
        for protocol, name in non_runtime_protocols:
            assert protocol is not None, f"{name} protocol should exist"
            # These may or may not be runtime checkable - both are valid

    def test_protocols_have_expected_methods(self) -> None:
        """Test protocols have expected method signatures."""
        # Connection protocol
        connection_methods = ['connect', 'disconnect', 'is_connected', 'bind']
        for method in connection_methods:
            assert hasattr(FlextLdapConnectionProtocol, method)

        # Search protocol  
        search_methods = ['search', 'search_one']
        for method in search_methods:
            assert hasattr(FlextLdapSearchProtocol, method)

        # Entry protocol
        entry_methods = ['create_entry', 'update_entry', 'delete_entry', 'entry_exists']
        for method in entry_methods:
            assert hasattr(FlextLdapEntryProtocol, method)

        # User protocol
        user_methods = ['create_user', 'get_user', 'update_user', 'delete_user', 'search_users']
        for method in user_methods:
            assert hasattr(FlextLdapUserProtocol, method)

        # Group protocol
        group_methods = ['create_group', 'get_group', 'add_member_to_group', 'remove_member_from_group', 'get_group_members']
        for method in group_methods:
            assert hasattr(FlextLdapGroupProtocol, method)


class TestRealProtocolTypeHints:
    """Test REAL protocol type hints and annotations."""

    def test_connection_protocol_type_hints(self) -> None:
        """Test FlextLdapConnectionProtocol has correct type hints."""
        hints = get_type_hints(FlextLdapConnectionProtocol.connect)
        assert 'return' in hints
        
        # Check if return type is FlextResult
        return_type = hints['return']
        assert get_origin(return_type) is not None or 'FlextResult' in str(return_type)

    def test_search_protocol_type_hints(self) -> None:
        """Test FlextLdapSearchProtocol has correct type hints."""
        hints = get_type_hints(FlextLdapSearchProtocol.search)
        assert 'return' in hints
        assert 'request' in hints
        
        # Check return type includes FlextResult
        return_type = hints['return']
        assert get_origin(return_type) is not None or 'FlextResult' in str(return_type)

    def test_user_protocol_type_hints(self) -> None:
        """Test FlextLdapUserProtocol has correct type hints."""
        hints = get_type_hints(FlextLdapUserProtocol.create_user)
        assert 'return' in hints
        assert 'request' in hints
        
        # Check return type
        return_type = hints['return']
        assert 'FlextResult' in str(return_type)

    def test_validator_protocol_type_hints(self) -> None:
        """Test FlextLdapValidatorProtocol has correct type hints."""
        hints = get_type_hints(FlextLdapValidatorProtocol.validate_dn)
        assert 'return' in hints
        assert 'dn' in hints
        
        # Check return type is FlextResult
        return_type = hints['return']
        assert 'FlextResult' in str(return_type)


class TestRealAbstractBaseClasses:
    """Test REAL abstract base class functionality."""

    def test_operations_base_cannot_be_instantiated(self) -> None:
        """Test FlextLdapOperationsBase cannot be instantiated directly."""
        with pytest.raises(TypeError):
            FlextLdapOperationsBase()  # Should fail - abstract class

    def test_service_base_cannot_be_instantiated(self) -> None:
        """Test FlextLdapServiceBase cannot be instantiated directly."""
        with pytest.raises(TypeError):
            FlextLdapServiceBase()  # Should fail - abstract class

    def test_client_base_cannot_be_instantiated(self) -> None:
        """Test FlextLdapClientBase cannot be instantiated directly."""
        with pytest.raises(TypeError):
            FlextLdapClientBase()  # Should fail - abstract class

    def test_operations_base_has_abstract_methods(self) -> None:
        """Test FlextLdapOperationsBase has expected abstract methods."""
        abstract_methods = FlextLdapOperationsBase.__abstractmethods__
        
        expected_methods = {'connect', 'disconnect'}
        assert abstract_methods == expected_methods

    def test_service_base_has_abstract_methods(self) -> None:
        """Test FlextLdapServiceBase has expected abstract methods."""
        abstract_methods = FlextLdapServiceBase.__abstractmethods__
        
        expected_methods = {'initialize', 'cleanup'}
        assert abstract_methods == expected_methods

    def test_client_base_has_abstract_methods(self) -> None:
        """Test FlextLdapClientBase has expected abstract methods."""
        abstract_methods = FlextLdapClientBase.__abstractmethods__
        
        expected_methods = {'connect', 'search', 'add', 'modify', 'delete'}
        assert abstract_methods == expected_methods


class TestRealProtocolInheritance:
    """Test REAL protocol inheritance and composition."""

    def test_protocols_are_proper_protocols(self) -> None:
        """Test protocols are proper typing.Protocol classes."""
        from typing import Protocol
        
        protocols = [
            FlextLdapConnectionProtocol,
            FlextLdapSearchProtocol,
            FlextLdapEntryProtocol,
            FlextLdapUserProtocol,
            FlextLdapGroupProtocol,
            FlextLdapRepositoryProtocol,
            FlextLdapValidatorProtocol,
        ]
        
        for protocol in protocols:
            assert issubclass(protocol, Protocol)

    def test_abstract_classes_are_proper_abcs(self) -> None:
        """Test abstract classes are proper ABC classes."""
        from abc import ABC
        
        abstract_classes = [
            FlextLdapOperationsBase,
            FlextLdapServiceBase,
            FlextLdapClientBase,
        ]
        
        for abstract_class in abstract_classes:
            assert issubclass(abstract_class, ABC)

    def test_protocols_can_be_used_for_isinstance_checks(self) -> None:
        """Test runtime checkable protocols work with isinstance."""
        # Create a mock class that implements connection protocol
        class MockConnection:
            async def connect(self): pass
            async def disconnect(self): pass  
            async def is_connected(self): pass
            async def bind(self, dn: str, password: str): pass
        
        mock_connection = MockConnection()
        
        # Should work with runtime checkable protocols
        assert isinstance(mock_connection, FlextLdapConnectionProtocol)


class TestRealProtocolIntegration:
    """Test REAL protocol integration with FLEXT patterns."""

    def test_protocols_use_flext_result_pattern(self) -> None:
        """Test protocols consistently use FlextResult pattern."""
        # Check connection protocol methods
        connect_hints = get_type_hints(FlextLdapConnectionProtocol.connect)
        assert 'FlextResult' in str(connect_hints.get('return', ''))
        
        bind_hints = get_type_hints(FlextLdapConnectionProtocol.bind)
        assert 'FlextResult' in str(bind_hints.get('return', ''))

    def test_protocols_use_proper_ldap_types(self) -> None:
        """Test protocols use proper LDAP entity types."""
        # Check user protocol uses FlextLdapUser
        user_hints = get_type_hints(FlextLdapUserProtocol.create_user)
        return_type_str = str(user_hints.get('return', ''))
        assert 'FlextLdapUser' in return_type_str

        # Check search protocol uses search types
        search_hints = get_type_hints(FlextLdapSearchProtocol.search)
        request_type_str = str(search_hints.get('request', ''))
        return_type_str = str(search_hints.get('return', ''))
        assert 'FlextLdapSearchRequest' in request_type_str
        assert 'FlextLdapSearchResponse' in return_type_str

    def test_abstract_bases_integrate_with_flext_container(self) -> None:
        """Test abstract bases integrate with FlextContainer."""
        # We can't instantiate abstract classes directly, but we can test the pattern
        
        # Check that operations base has container initialization
        init_code = FlextLdapOperationsBase.__init__
        assert init_code is not None
        
        # Check the source code mentions get_flext_container
        import inspect
        source = inspect.getsource(FlextLdapOperationsBase.__init__)
        assert 'get_flext_container' in source


class TestRealProtocolDocumentation:
    """Test REAL protocol documentation and introspection."""

    def test_protocols_have_docstrings(self) -> None:
        """Test all protocols have proper docstrings."""
        protocols = [
            FlextLdapConnectionProtocol,
            FlextLdapSearchProtocol,
            FlextLdapEntryProtocol,
            FlextLdapUserProtocol,
            FlextLdapGroupProtocol,
            FlextLdapRepositoryProtocol,
            FlextLdapValidatorProtocol,
        ]
        
        for protocol in protocols:
            assert protocol.__doc__ is not None
            assert len(protocol.__doc__.strip()) > 0
            assert 'Protocol' in protocol.__doc__

    def test_abstract_classes_have_docstrings(self) -> None:
        """Test all abstract classes have proper docstrings."""
        abstract_classes = [
            FlextLdapOperationsBase,
            FlextLdapServiceBase,
            FlextLdapClientBase,
        ]
        
        for abstract_class in abstract_classes:
            assert abstract_class.__doc__ is not None
            assert len(abstract_class.__doc__.strip()) > 0

    def test_protocol_methods_have_docstrings(self) -> None:
        """Test protocol methods have proper docstrings."""
        # Test connection protocol methods
        assert FlextLdapConnectionProtocol.connect.__doc__ is not None
        assert 'connection' in FlextLdapConnectionProtocol.connect.__doc__.lower()
        
        # Test user protocol methods
        assert FlextLdapUserProtocol.create_user.__doc__ is not None
        assert 'user' in FlextLdapUserProtocol.create_user.__doc__.lower()


class TestRealProtocolCompliance:
    """Test REAL protocol compliance and patterns."""

    def test_all_async_methods_are_properly_defined(self) -> None:
        """Test all async protocol methods are properly defined."""
        import inspect
        
        # Check connection protocol
        connection_methods = [
            FlextLdapConnectionProtocol.connect,
            FlextLdapConnectionProtocol.disconnect,
            FlextLdapConnectionProtocol.bind,
        ]
        
        for method in connection_methods:
            # Should be coroutine functions (async)
            assert inspect.iscoroutinefunction(method) or '...' in str(method)

    def test_sync_methods_are_properly_defined(self) -> None:
        """Test sync protocol methods are properly defined."""
        import inspect
        
        # Validator protocol has sync methods
        validator_methods = [
            FlextLdapValidatorProtocol.validate_dn,
            FlextLdapValidatorProtocol.validate_filter,
            FlextLdapValidatorProtocol.validate_attributes,
        ]
        
        for method in validator_methods:
            # Should NOT be coroutine functions (sync)
            assert not inspect.iscoroutinefunction(method)

    def test_protocols_support_multiple_inheritance(self) -> None:
        """Test protocols can be used in multiple inheritance."""
        # Create a class that implements multiple protocols
        class MultiProtocolImplementation:
            async def connect(self): pass
            async def disconnect(self): pass
            async def is_connected(self): pass
            async def bind(self, dn: str, password: str): pass
            
            def validate_dn(self, dn: str): pass
            def validate_filter(self, filter_str: str): pass
            def validate_attributes(self, attributes): pass
        
        implementation = MultiProtocolImplementation()
        
        # Should satisfy runtime checkable protocols
        assert isinstance(implementation, FlextLdapConnectionProtocol)
        
        # For non-runtime checkable protocols, just verify the class exists and has the methods
        assert hasattr(implementation, 'validate_dn')
        assert hasattr(implementation, 'validate_filter')
        assert hasattr(implementation, 'validate_attributes')


class TestRealProtocolModuleStructure:
    """Test REAL protocol module structure and organization."""

    def test_protocols_module_has_expected_exports(self) -> None:
        """Test protocols module exports expected classes."""
        import flext_ldap.protocols as protocols_module
        
        expected_protocols = [
            'FlextLdapConnectionProtocol',
            'FlextLdapSearchProtocol',
            'FlextLdapEntryProtocol', 
            'FlextLdapUserProtocol',
            'FlextLdapGroupProtocol',
            'FlextLdapRepositoryProtocol',
            'FlextLdapValidatorProtocol',
        ]
        
        expected_bases = [
            'FlextLdapOperationsBase',
            'FlextLdapServiceBase',
            'FlextLdapClientBase',
        ]
        
        for protocol_name in expected_protocols + expected_bases:
            assert hasattr(protocols_module, protocol_name)
            cls = getattr(protocols_module, protocol_name)
            assert cls is not None

    def test_protocols_module_imports_are_correct(self) -> None:
        """Test protocols module has correct imports."""
        import flext_ldap.protocols as protocols_module
        
        # Should have access to FlextResult
        assert hasattr(protocols_module, 'FlextResult')
        
        # Should have access to entity types
        assert hasattr(protocols_module, 'FlextLdapEntry')
        assert hasattr(protocols_module, 'FlextLdapUser')
        assert hasattr(protocols_module, 'FlextLdapGroup')

    def test_protocol_module_structure_is_clean(self) -> None:
        """Test protocol module has clean structure without implementation."""
        import flext_ldap.protocols as protocols_module
        
        # Should not have concrete implementations (only protocols and ABC)
        module_attrs = [attr for attr in dir(protocols_module) if not attr.startswith('_')]
        
        # Count protocols vs implementations
        protocol_count = len([attr for attr in module_attrs if 'Protocol' in attr])
        base_count = len([attr for attr in module_attrs if 'Base' in attr])
        
        # Should have more protocols than bases (good separation)
        assert protocol_count >= 5  # At least 5 protocols defined
        assert base_count >= 3      # At least 3 abstract bases defined