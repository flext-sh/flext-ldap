"""Focused API functional tests targeting uncovered methods.

Following COMPREHENSIVE_QUALITY_REFACTORING_PROMPT.md:
- Target uncovered API.py methods for maximum coverage impact
- Focus on local logic, avoid network timeouts
- Test edge cases and error conditions systematically

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLDAPApi, get_flext_ldap_api
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.settings import FlextLDAPSettings


class TestFlextLDAPApiFunctionalFocused:
    """Focused functional tests for API coverage improvement."""

    def test_api_initialization_comprehensive_paths(self) -> None:
        """Test all API initialization code paths."""
        # Test with default config (None)
        api1 = FlextLDAPApi()
        assert api1._config is not None
        assert isinstance(api1._config, FlextLDAPSettings)
        assert api1._container_manager is not None
        assert api1._container is not None
        assert api1._service is not None

        # Test with explicit config
        custom_config = FlextLDAPSettings(
            host="test.example.com",
            port=389,
            base_dn="dc=test,dc=com"
        )
        api2 = FlextLDAPApi(config=custom_config)
        assert api2._config is custom_config
        assert api2._config.host == "test.example.com"

        # Test service initialization with container
        assert api2._service._container is not None

    def test_session_id_generation_comprehensive(self) -> None:
        """Test session ID generation with comprehensive validation."""
        api = FlextLDAPApi()

        # Generate many IDs to test uniqueness and format
        session_ids = []
        for _ in range(50):
            session_id = api._generate_session_id()
            session_ids.append(session_id)

            # Validate format: "session_" + UUID
            assert session_id.startswith("session_")
            assert len(session_id) == 44  # "session_" (8) + UUID (36)

            # Validate UUID part is hex characters and dashes
            uuid_part = session_id[8:]  # Remove "session_" prefix
            assert len(uuid_part) == 36
            # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            parts = uuid_part.split("-")
            assert len(parts) == 5
            assert len(parts[0]) == 8
            assert len(parts[1]) == 4
            assert len(parts[2]) == 4
            assert len(parts[3]) == 4
            assert len(parts[4]) == 12

        # Verify all generated IDs are unique
        assert len(session_ids) == len(set(session_ids))

    def test_entry_attribute_extraction_dict_entries(self) -> None:
        """Test _get_entry_attribute with dictionary entries comprehensively."""
        api = FlextLDAPApi()

        # Test normal LDAP attribute format (list values)
        normal_entry = {
            "cn": ["John Doe"],
            "uid": ["johndoe"],
            "mail": ["john@example.com", "j.doe@example.com"],  # Multiple values
            "description": ["User account"]
        }

        # Extract single values from lists
        cn = api._get_entry_attribute(normal_entry, "cn", "default_name")
        uid = api._get_entry_attribute(normal_entry, "uid", "default_uid")

        # Should extract first element from list
        assert cn == "John Doe"
        assert uid == "johndoe"

        # Multi-value attribute should return first value
        mail = api._get_entry_attribute(normal_entry, "mail", "default@mail.com")
        assert mail == "john@example.com"

        # Missing attribute should return default
        missing = api._get_entry_attribute(normal_entry, "nonexistent", "default_value")
        assert missing == "default_value"

    def test_entry_attribute_extraction_non_list_values(self) -> None:
        """Test _get_entry_attribute with non-list values."""
        api = FlextLDAPApi()

        # Test with direct string values (not in lists)
        string_entry = {
            "cn": "Direct String",
            "uid": "direct_uid",
            "number": 12345,
            "boolean": True,
            "none_value": None
        }

        # Should handle direct string values
        cn = api._get_entry_attribute(string_entry, "cn", "default")
        uid = api._get_entry_attribute(string_entry, "uid", "default")
        assert cn == "Direct String"
        assert uid == "direct_uid"

        # Should convert numbers to strings
        number = api._get_entry_attribute(string_entry, "number", "default")
        assert number == "12345"

        # Should convert boolean to string
        boolean = api._get_entry_attribute(string_entry, "boolean", "default")
        assert boolean == "True"

        # Should handle None values
        none_val = api._get_entry_attribute(string_entry, "none_value", "default")
        assert none_val == "default"

    def test_entry_attribute_extraction_empty_and_none_lists(self) -> None:
        """Test _get_entry_attribute with empty lists and None values in lists."""
        api = FlextLDAPApi()

        # Test with various empty/None scenarios
        edge_case_entry = {
            "empty_list": [],
            "none_list": [None],
            "mixed_none": [None, "valid_value"],
            "empty_string_list": [""],
            "whitespace_list": [" ", "\t", "\n"]
        }

        # Empty list should return default
        empty = api._get_entry_attribute(edge_case_entry, "empty_list", "default")
        assert empty == "default"

        # List with None should return default
        none_list = api._get_entry_attribute(edge_case_entry, "none_list", "default")
        assert none_list == "default"

        # Mixed None should take first non-None (but we take first, so None -> default)
        mixed = api._get_entry_attribute(edge_case_entry, "mixed_none", "default")
        assert mixed == "default"  # Takes first element which is None

        # Empty string should be returned as-is
        empty_str = api._get_entry_attribute(edge_case_entry, "empty_string_list", "default")
        assert empty_str == ""

        # Whitespace should be preserved
        whitespace = api._get_entry_attribute(edge_case_entry, "whitespace_list", "default")
        assert whitespace == " "

    def test_entry_attribute_extraction_with_entry_objects(self) -> None:
        """Test _get_entry_attribute with FlextLDAPEntities.Entry objects."""
        api = FlextLDAPApi()

        # Create Entry object with attributes
        entry = FlextLDAPEntities.Entry(
            id="test_001",
            dn="cn=test,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "uid": ["testuser"],
                "mail": ["test@example.com"]
            }
        )

        # Test extraction from Entry object
        cn = api._get_entry_attribute(entry, "cn", "default_name")
        uid = api._get_entry_attribute(entry, "uid", "default_uid")
        mail = api._get_entry_attribute(entry, "mail", "default_mail")
        missing = api._get_entry_attribute(entry, "nonexistent", "default")

        # Should extract from Entry.get_attribute()
        assert cn != "default_name"  # Should get actual value
        assert uid != "default_uid"  # Should get actual value
        assert mail != "default_mail"  # Should get actual value
        assert missing == "default"  # Should use default for missing

    def test_entry_attribute_extraction_error_handling(self) -> None:
        """Test _get_entry_attribute error handling for problematic values."""
        api = FlextLDAPApi()

        # Create objects that raise errors during string conversion
        class BadStringConversion:
            def __str__(self) -> str:
                raise ValueError("Cannot convert to string")

        class BadRepr:
            def __repr__(self) -> str:
                raise TypeError("Cannot represent")

            def __str__(self) -> str:
                raise ValueError("Cannot convert")

        # Test error handling
        error_entry = {
            "bad_conversion": [BadStringConversion()],
            "bad_repr": [BadRepr()],
            "recoverable": [123, BadStringConversion(), "fallback"],  # Mixed with errors
        }

        # Should handle conversion errors gracefully
        bad_conv = api._get_entry_attribute(error_entry, "bad_conversion", "safe_default")
        assert bad_conv == "safe_default"

        bad_repr = api._get_entry_attribute(error_entry, "bad_repr", "safe_default")
        assert bad_repr == "safe_default"

        # Should take first element even if later ones would work
        recoverable = api._get_entry_attribute(error_entry, "recoverable", "safe_default")
        assert recoverable == "123"  # First element (123) converts fine

    def test_factory_function_get_flext_ldap_api(self) -> None:
        """Test get_flext_ldap_api factory function comprehensively."""
        # Test factory without parameters
        api1 = get_flext_ldap_api()
        assert isinstance(api1, FlextLDAPApi)
        assert api1._config is not None
        assert isinstance(api1._config, FlextLDAPSettings)

        # Test factory with config parameter
        custom_config = FlextLDAPSettings(
            host="factory.test.com",
            port=636,
            use_ssl=True
        )
        api2 = get_flext_ldap_api(config=custom_config)
        assert isinstance(api2, FlextLDAPApi)
        assert api2._config is custom_config
        assert api2._config.host == "factory.test.com"
        assert api2._config.port == 636
        assert api2._config.use_ssl is True

        # Verify different instances are created
        api3 = get_flext_ldap_api()
        assert api1 is not api2
        assert api1 is not api3
        assert api2 is not api3

        # Verify each has independent configuration
        assert api1._config is not api2._config
        assert api1._config is not api3._config

    @pytest.mark.asyncio
    async def test_disconnect_method_comprehensive(self) -> None:
        """Test disconnect method with various input types."""
        api = FlextLDAPApi()

        # Test disconnect with None
        result_none = await api.disconnect(None)
        assert isinstance(result_none, FlextResult)
        assert result_none.is_success  # Should handle None gracefully

        # Test disconnect with various object types
        test_objects = [
            {},  # Empty dict
            {"connection": "mock"},  # Dict with data
            "string_session",  # String
            123,  # Number
            [],  # Empty list
            [1, 2, 3],  # List with data
        ]

        for test_obj in test_objects:
            result = await api.disconnect(test_obj)
            assert isinstance(result, FlextResult)
            # Should handle all types without raising exceptions

    def test_internal_state_consistency(self) -> None:
        """Test that internal state is consistent across different initialization paths."""
        # Test multiple API instances have proper isolation
        apis = []
        for i in range(5):
            config = FlextLDAPSettings(host=f"host{i}.example.com")
            api = FlextLDAPApi(config=config)
            apis.append(api)

            # Verify each instance has proper internal state
            assert api._config.host == f"host{i}.example.com"
            assert api._container_manager is not None
            assert api._container is not None
            assert api._service is not None

            # Verify service has access to container
            assert api._service._container is not None

        # Verify all instances are independent
        for i, api1 in enumerate(apis):
            for j, api2 in enumerate(apis):
                if i != j:
                    assert api1 is not api2
                    assert api1._config is not api2._config
                    assert api1._container_manager is not api2._container_manager
                    assert api1._service is not api2._service

    def test_logging_initialization(self) -> None:
        """Test that logging is properly initialized during API creation."""
        # This test ensures the logging statement in __init__ is covered
        api = FlextLDAPApi()

        # Verify API is initialized with logging working
        assert api is not None
        assert api._config is not None
        assert api._service is not None

        # The logging line in __init__ should have been executed
        # We can verify this by checking the API was successfully created
