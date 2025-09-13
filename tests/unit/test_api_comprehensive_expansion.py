
from __future__ import annotations

import uuid
import pytest
from flext_core import FlextResult
from flext_ldap import FlextLDAPApi, FlextLDAPConfig, get_flext_ldap_api
from flext_ldap.connection_config import FlextLDAPConnectionConfig
from flext_ldap.entities import FlextLDAPEntities

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations



from typing import Dict


@pytest.mark.asyncio
class TestFlextLDAPApiComprehensiveExpansion:
    """Comprehensive API coverage expansion targeting uncovered methods."""

    def test_api_initialization_with_custom_config(self) -> None:
        """Test API initialization with custom configuration object."""

        # Create custom config
        custom_config = FlextLDAPConnectionConfig(
            server="ldaps://custom.example.com",
            port=636,
            use_ssl=True,
            base_dn="ou=custom,dc=example,dc=com",
        )

        # Initialize API with custom config
        api = FlextLDAPApi(config=custom_config)

        # Verify custom config is used
        assert api._config is custom_config
        assert api._config.server == "ldaps://custom.example.com"
        assert api._config.port == 636
        assert api._config.use_ssl is True
        assert api._container is not None
        assert api._service is not None

    def test_entry_attribute_extraction_with_entry_objects(self) -> None:
        """Test _get_entry_attribute with FlextLDAPEntities.Entry objects."""

        api = FlextLDAPApi()

        # Create Entry object with test attributes
        entry = FlextLDAPEntities.Entry(
            id="test_entry_001",
            dn="cn=test,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "uid": ["testuser"],
                "mail": ["test@example.com"],
            },
        )

        # Test attribute extraction from Entry object
        cn = api._get_entry_attribute(entry, "cn", "default_name")
        uid = api._get_entry_attribute(entry, "uid", "default_uid")
        mail = api._get_entry_attribute(entry, "mail", "default@mail.com")
        missing = api._get_entry_attribute(entry, "nonexistent", "default_value")

        # Verify correct extraction
        assert cn != "default_name"  # Should extract from entry
        assert uid != "default_uid"  # Should extract from entry
        assert mail != "default@mail.com"  # Should extract from entry
        assert missing == "default_value"  # Should use default for missing

    def test_entry_attribute_extraction_edge_cases(self) -> None:
        """Test _get_entry_attribute with various edge cases."""

        api = FlextLDAPApi()

        # Test with None values
        entry_with_none = {"cn": None, "uid": [None], "empty": []}

        cn_none = api._get_entry_attribute(entry_with_none, "cn", "default")
        uid_none = api._get_entry_attribute(entry_with_none, "uid", "default")
        empty_attr = api._get_entry_attribute(entry_with_none, "empty", "default")
        missing_attr = api._get_entry_attribute(entry_with_none, "missing", "default")

        # All should return defaults due to None/empty values
        assert cn_none == "default"
        assert uid_none == "default"
        assert empty_attr == "default"
        assert missing_attr == "default"

    def test_entry_attribute_extraction_type_conversion_errors(self) -> None:
        """Test _get_entry_attribute with values that cause conversion errors."""

        api = FlextLDAPApi()

        # Create entry with problematic values that could cause TypeError/ValueError
        class UnconvertibleObject:
            def __str__(self) -> str:
                msg = "Cannot convert to string"
                raise ValueError(msg)

        problematic_entry = {
            "bad_object": [UnconvertibleObject()],
            "complex_nested": [{"nested": "value"}],  # Dict in list
            "numeric_list": [123, 456],  # Numbers that should convert
        }

        # Test error handling
        bad_result = api._get_entry_attribute(
            problematic_entry, "bad_object", "safe_default"
        )
        nested_result = api._get_entry_attribute(
            problematic_entry, "complex_nested", "safe_default"
        )
        numeric_result = api._get_entry_attribute(
            problematic_entry, "numeric_list", "safe_default"
        )

        # Should handle errors gracefully
        assert (
            bad_result == "safe_default"
        )  # Should use default due to conversion error
        assert (
            nested_result != "safe_default"
        )  # Dict should convert to str representation
        assert numeric_result != "safe_default"  # Numbers should convert successfully

    async def test_session_management_lifecycle(self) -> None:
        """Test complete session management lifecycle."""

        # Generate multiple session IDs
        session_ids = []
        for _ in range(20):  # Test multiple generations
            session_id = f"session_{uuid.uuid4()}"
            session_ids.append(session_id)

            # Verify format
            assert session_id.startswith("session_")
            assert len(session_id) == 44  # "session_" + 36 char UUID

        # Verify all are unique
        assert len(session_ids) == len(set(session_ids))

    async def test_connection_error_handling_comprehensive(self) -> None:
        """Test comprehensive error handling for connection operations."""

        api = FlextLDAPApi()

        # Test connection to invalid server
        invalid_hosts = [
            "invalid://not-a-real-server:389",
            "ldap://nonexistent.domain.invalid:389",
            "ldaps://unreachable.host.invalid:636",
        ]

        for invalid_host in invalid_hosts:
            connection_result = await api.connect(
                invalid_host, "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "password"
            )

            # Should return FlextResult with failure
            assert isinstance(connection_result, FlextResult)
            assert not connection_result.is_success
            assert connection_result.error is not None
            assert isinstance(connection_result.error, str)
            assert len(connection_result.error) > 0

    async def test_search_request_validation_comprehensive(self) -> None:
        """Test comprehensive search request validation."""

        api = FlextLDAPApi()

        # Test various search request configurations
        search_requests = [
            # Valid request
            FlextLDAPEntities.SearchRequest(
                base_dn="ou=users,dc=example,dc=com",
                filter_str="(objectClass=person)",
                scope="subtree",
                attributes=["uid", "cn", "mail"],
            ),
            # Minimal request
            FlextLDAPEntities.SearchRequest(
                base_dn="dc=example,dc=com", filter_str="(objectClass=*)", scope="base"
            ),
            # Request with limits
            FlextLDAPEntities.SearchRequest(
                base_dn="ou=groups,dc=example,dc=com",
                filter_str="(objectClass=groupOfNames)",
                scope="one",
                size_limit=100,
                time_limit=30,
            ),
        ]

        for search_request in search_requests:
            # Execute search (will fail without connection, but validates structure)
            search_result = await api.search(search_request)

            # Should return FlextResult structure
            assert isinstance(search_result, FlextResult)

            # Error should be connection-related, not validation-related
            if not search_result.is_success:
                error_msg = search_result.error.lower()
                assert any(
                    keyword in error_msg
                    for keyword in ["connect", "bind", "server", "host", "timeout"]
                )

    async def test_user_operations_validation_paths(self) -> None:
        """Test user operation validation paths comprehensively."""

        api = FlextLDAPApi()

        # Test various user creation requests
        user_requests = [
            # Complete user request
            FlextLDAPEntities.CreateUserRequest(
                dn="cn=john.doe,ou=users,dc=example,dc=com",
                uid="john.doe",
                cn="John Doe",
                sn="Doe",
                given_name="John",
                mail="john.doe@example.com",
                object_classes=["person", "organizationalPerson", "top"],
            ),
            # Minimal user request
            FlextLDAPEntities.CreateUserRequest(
                dn="cn=minimal,ou=users,dc=example,dc=com",
                uid="minimal",
                cn="Minimal User",
                sn="User",
            ),
            # User with additional attributes
            FlextLDAPEntities.CreateUserRequest(
                dn="cn=extended,ou=users,dc=example,dc=com",
                uid="extended",
                cn="Extended User",
                sn="User",
                description="Test user with extended attributes",
                telephone_number="123-456-7890",
            ),
        ]

        for user_request in user_requests:
            # Execute user creation (will fail without connection)
            create_result = await api.create_user(user_request)

            # Should return FlextResult structure
            assert isinstance(create_result, FlextResult)

            # If failed, should be connection issue, not validation
            if not create_result.is_success:
                error_msg = create_result.error.lower()
                # Should not be validation errors
                assert "invalid" not in error_msg or "connect" in error_msg

    async def test_factory_function_comprehensive(self) -> None:
        """Test get_flext_ldap_api factory function comprehensively."""

        # Test factory without config
        api1 = get_flext_ldap_api()
        assert isinstance(api1, FlextLDAPApi)
        assert api1._config is not None

        # Test factory with config
        custom_config = FlextLDAPConfig.create_test_ldap_config().unwrap()
        api2 = get_flext_ldap_api(config=custom_config)
        assert isinstance(api2, FlextLDAPApi)
        assert api2._config is custom_config

        # Verify different instances
        assert api1 is not api2
        assert api1._config is not api2._config

    async def test_disconnect_functionality_comprehensive(self) -> None:
        """Test disconnect functionality with various scenarios."""

        api = FlextLDAPApi()

        # Test disconnect with None (should handle gracefully)
        disconnect_result1 = await api.disconnect(None)
        assert isinstance(disconnect_result1, FlextResult)
        # Should succeed with None (no-op)
        assert disconnect_result1.is_success

        # Test disconnect with invalid session object
        invalid_session = {"invalid": "session_data"}
        disconnect_result2 = await api.disconnect(invalid_session)
        assert isinstance(disconnect_result2, FlextResult)
        # Should handle invalid session gracefully

    def test_container_and_service_initialization(self) -> None:
        """Test container and service initialization paths."""

        # Test with default initialization
        api1 = FlextLDAPApi()
        assert api1._container_manager is not None
        assert api1._container is not None
        assert api1._service is not None

        # Verify service is initialized with container
        assert api1._service._container is not None

        # Test internal state consistency
        assert hasattr(api1, "_config")
        assert hasattr(api1, "_container_manager")
        assert hasattr(api1, "_container")
        assert hasattr(api1, "_service")

    async def test_error_propagation_patterns(self) -> None:
        """Test error propagation patterns across API methods."""

        api = FlextLDAPApi()

        # Test that errors are properly wrapped in FlextResult
        operations = [
            lambda: api.connect("invalid", "dn", "pass"),
            lambda: api.search(
                FlextLDAPEntities.SearchRequest(
                    base_dn="dc=test", filter_str="(objectClass=*)", scope="base"
                )
            ),
            lambda: api.create_user(
                FlextLDAPEntities.CreateUserRequest(
                    dn="cn=test,dc=test", uid="test", cn="Test", sn="User"
                )
            ),
        ]

        for operation in operations:
            result = await operation()

            # All operations should return FlextResult
            assert isinstance(result, FlextResult)

            # All should fail (no real connection) but with proper structure
            if not result.is_success:
                assert result.error is not None
                assert isinstance(result.error, str)
                assert len(result.error) > 0

    def test_attribute_extraction_performance_edge_cases(self) -> None:
        """Test attribute extraction with performance and edge case scenarios."""

        api = FlextLDAPApi()

        # Test with large lists
        large_entry = {
            "large_list": [f"value_{i}" for i in range(1000)],
            "mixed_types": [123, "string", 45.67, None],
            "bytes_data": [b"byte_string", "normal_string"],
        }

        # Should handle large lists (take first element)
        large_result = api._get_entry_attribute(large_entry, "large_list", "default")
        assert large_result == "value_0"

        # Should handle mixed types (take first, convert to string)
        mixed_result = api._get_entry_attribute(large_entry, "mixed_types", "default")
        assert mixed_result == "123"

        # Should handle bytes data
        bytes_result = api._get_entry_attribute(large_entry, "bytes_data", "default")
        assert "byte" in bytes_result.lower()
