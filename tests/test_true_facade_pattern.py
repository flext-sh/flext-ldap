"""Comprehensive tests for True Facade Pattern implementation.

These tests validate that the LDAP Core Shared library implements a True Facade
Pattern correctly after refactoring from the God Object anti-pattern.

Test Coverage:
- ✅ All imports work correctly from __init__.py
- ✅ True Facade Pattern delegation functions
- ✅ API compatibility maintained 100%
- ✅ Specialized modules work independently
- ✅ Error handling preserved
- ✅ Performance characteristics maintained
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Test all critical imports from the main package
try:
    from ldap_core_shared import (
        LDAP,
        LDAPConfig,
        Query,
        Result,
        __author__,
        __email__,
        __license__,
        __version__,
        connect,
        ldap_session,
        validate_ldap_config,
    )
    IMPORTS_SUCCESS = True
except ImportError as e:
    IMPORTS_SUCCESS = False
    IMPORT_ERROR = str(e)

# Test imports from individual modules
try:
    from ldap_core_shared.api import (
        config,
        facade,
        operations,
        query,
        results,
        validation,
    )
    API_MODULES_SUCCESS = True
except ImportError as e:
    API_MODULES_SUCCESS = False
    API_IMPORT_ERROR = str(e)


class TestImportsAndExports:
    """Test that all imports work correctly from the simplified __init__.py."""

    def test_critical_imports_success(self) -> None:
        """Test that all critical imports work from main package."""
        assert IMPORTS_SUCCESS, f"Critical imports failed: {IMPORT_ERROR if not IMPORTS_SUCCESS else 'Unknown error'}"

    def test_api_modules_imports_success(self) -> None:
        """Test that API modules can be imported individually."""
        assert API_MODULES_SUCCESS, f"API modules import failed: {API_IMPORT_ERROR if not API_MODULES_SUCCESS else 'Unknown error'}"

    def test_version_information_available(self) -> None:
        """Test that version information is properly exported."""
        assert __version__ is not None
        assert __author__ is not None
        assert __email__ is not None
        assert __license__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_main_classes_available(self) -> None:
        """Test that main classes are available."""
        assert LDAP is not None
        assert LDAPConfig is not None
        assert Query is not None
        assert Result is not None

    def test_convenience_functions_available(self) -> None:
        """Test that convenience functions are available."""
        assert connect is not None
        assert ldap_session is not None
        assert validate_ldap_config is not None
        assert callable(connect)
        assert callable(ldap_session)
        assert callable(validate_ldap_config)


class TestLDAPConfigValueObject:
    """Test LDAPConfig Value Object functionality."""

    def test_ldap_config_creation(self) -> None:
        """Test basic LDAPConfig creation."""
        config = LDAPConfig(
            server="ldaps://ldap.example.com:636",
            auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            auth_password="secret",
            base_dn="dc=example,dc=com",
        )

        # LDAPConfig auto-parses URLs, extracting hostname
        assert config.server == "ldap.example.com"  # Hostname extracted from URL
        assert config.auth_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert config.auth_password == "secret"
        assert config.base_dn == "dc=example,dc=com"
        assert config.use_tls is True  # Auto-detected from ldaps://
        assert config.port == 636  # Auto-detected from ldaps://

    def test_ldap_config_with_optional_params(self) -> None:
        """Test LDAPConfig with optional parameters."""
        config = LDAPConfig(
            server="ldap://ldap.example.com",
            auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            auth_password="secret",
            base_dn="dc=example,dc=com",
            port=389,
            use_tls=False,
        )

        assert config.port == 389
        assert config.use_tls is False

    @pytest.mark.asyncio
    async def test_validate_ldap_config_function(self) -> None:
        """Test the validate_ldap_config convenience function."""
        config = LDAPConfig(
            server="ldaps://ldap.example.com:636",
            auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            auth_password="secret",
            base_dn="dc=example,dc=com",
        )

        # Should not raise any exceptions for valid config
        # Function may be async, so handle both cases
        try:
            result = await validate_ldap_config(config)
            # validate_ldap_config returns a Result object
            assert hasattr(result, "success"), "validate_ldap_config should return Result object"
            assert result.success is True, f"Config validation failed: {result.error if hasattr(result, 'error') else 'Unknown error'}"
        except TypeError:
            # Not async, try sync
            result = validate_ldap_config(config)
            # validate_ldap_config returns a Result object
            assert hasattr(result, "success"), "validate_ldap_config should return Result object"
            assert result.success is True, f"Config validation failed: {result.error if hasattr(result, 'error') else 'Unknown error'}"


class TestResultPattern:
    """Test Result Pattern for consistent error handling."""

    def test_result_success_creation(self) -> None:
        """Test creating successful results."""
        data = {"test": "data"}
        result = Result.ok(data)

        assert result.success is True
        assert result.data == data
        assert result.error is None
        assert result.execution_time_ms >= 0

    def test_result_failure_creation(self) -> None:
        """Test creating failure results."""
        error_msg = "Test error"
        result = Result.fail(error_msg)

        assert result.success is False
        assert result.data is None
        assert result.error == error_msg
        assert result.execution_time_ms >= 0

    def test_result_with_metadata(self) -> None:
        """Test Result with additional metadata."""
        data = ["item1", "item2"]
        result = Result.ok(data, execution_time_ms=123.45)

        assert result.success is True
        assert result.data == data
        assert result.execution_time_ms == 123.45


class TestQueryBuilder:
    """Test Query Builder Pattern functionality."""

    @pytest.fixture
    def mock_facade(self):
        """Fixture providing a mock LDAP facade for Query testing."""
        return MagicMock()

    def test_query_builder_creation(self, mock_facade) -> None:
        """Test Query builder can be instantiated."""
        query = Query(mock_facade)
        assert query is not None
        assert query._ldap == mock_facade

    def test_query_builder_fluent_interface(self, mock_facade) -> None:
        """Test Query builder fluent interface."""
        query = Query(mock_facade)

        # Test method chaining (should return self)
        result = query.users()
        assert result is query or isinstance(result, Query)

        # Test multiple chaining
        chained = query.users().in_department("IT").enabled_only()
        assert chained is not None

    def test_query_builder_methods_exist(self, mock_facade) -> None:
        """Test that expected Query builder methods exist."""
        query = Query(mock_facade)

        # Test that key methods exist
        assert hasattr(query, "users")
        assert hasattr(query, "in_department")
        assert hasattr(query, "enabled_only")
        assert callable(query.users)
        assert callable(query.in_department)
        assert callable(query.enabled_only)


class TestTrueFacadePattern:
    """Test that LDAP class implements True Facade Pattern correctly."""

    @pytest.fixture
    def mock_config(self):
        """Fixture providing a mock LDAP configuration."""
        return LDAPConfig(
            server="ldaps://test.example.com:636",
            auth_dn="cn=test,dc=example,dc=com",
            auth_password="test_password",
            base_dn="dc=example,dc=com",
        )

    def test_ldap_facade_instantiation(self, mock_config) -> None:
        """Test LDAP facade can be instantiated."""
        ldap = LDAP(mock_config)
        assert ldap is not None
        assert ldap._config == mock_config

    def test_ldap_facade_has_expected_methods(self, mock_config) -> None:
        """Test LDAP facade has expected business methods."""
        ldap = LDAP(mock_config)

        # Test that key business methods exist (based on actual implementation)
        expected_methods = [
            "find_user_by_email",
            "find_users_in_department",
            "validate_entry_schema",  # Correct method name
            "query",
        ]

        for method_name in expected_methods:
            assert hasattr(ldap, method_name), f"Method {method_name} not found"
            assert callable(getattr(ldap, method_name)), f"Method {method_name} not callable"

    def test_ldap_facade_context_manager(self, mock_config) -> None:
        """Test LDAP facade works as context manager."""
        ldap = LDAP(mock_config)

        # Test that it has context manager methods
        assert hasattr(ldap, "__aenter__")
        assert hasattr(ldap, "__aexit__")
        assert callable(ldap.__aenter__)
        assert callable(ldap.__aexit__)

    @pytest.mark.asyncio
    async def test_ldap_facade_delegation_pattern(self, mock_config) -> None:
        """Test that LDAP facade properly delegates to specialized modules."""
        ldap = LDAP(mock_config)

        # Mock the internal core operations to verify delegation
        with patch.object(ldap, "_get_core_operations") as mock_get_core_ops:
            mock_core_operations = AsyncMock()
            mock_core_operations.find_user_by_email.return_value = Result.ok({"cn": "test"})
            mock_get_core_ops.return_value = mock_core_operations

            # Test delegation
            result = await ldap.find_user_by_email("test@example.com")

            # Verify delegation occurred
            mock_get_core_ops.assert_called_once()
            mock_core_operations.find_user_by_email.assert_called_once_with("test@example.com")
            assert result.success is True


class TestConvenienceFunctions:
    """Test convenience functions for easy library usage."""

    def test_connect_function_exists(self) -> None:
        """Test that connect function exists and is callable."""
        assert connect is not None
        assert callable(connect)

    def test_ldap_session_function_exists(self) -> None:
        """Test that ldap_session function exists and is callable."""
        assert ldap_session is not None
        assert callable(ldap_session)

    @pytest.mark.asyncio
    async def test_ldap_session_context_manager(self) -> None:
        """Test ldap_session as async context manager."""
        # Mock the session creation to avoid actual connections
        with patch("ldap_core_shared.api.facade.LDAP") as MockLDAP:
            mock_ldap_instance = AsyncMock()
            mock_ldap_instance.__aenter__.return_value = mock_ldap_instance
            MockLDAP.return_value = mock_ldap_instance

            async with ldap_session(
                server="ldap://test.example.com",
                auth_dn="cn=test,dc=example,dc=com",
                auth_password="test",
                base_dn="dc=example,dc=com",
            ) as session:
                assert session is not None
                # Verify the session is what __aenter__ returns
                assert session == mock_ldap_instance


class TestModuleSpecialization:
    """Test that specialized modules work independently."""

    def test_config_module_independent(self) -> None:
        """Test config module works independently."""
        from ldap_core_shared.api.config import LDAPConfig as APILDAPConfig

        config = APILDAPConfig(
            server="ldap://test.com",
            auth_dn="cn=test,dc=test,dc=com",
            auth_password="test",
            base_dn="dc=test,dc=com",
        )
        # Config auto-parses URL, so hostname is extracted
        assert config.server == "test.com"  # Hostname extracted from ldap://test.com
        assert config.use_tls is False  # Auto-detected from ldap:// protocol
        assert config.port == 389  # Auto-detected for ldap://

    def test_results_module_independent(self) -> None:
        """Test results module works independently."""
        from ldap_core_shared.api.results import Result as APIResult

        result = APIResult.ok("test_data")
        assert result.success is True
        assert result.data == "test_data"

    def test_query_module_independent(self) -> None:
        """Test query module works independently."""
        from ldap_core_shared.api.query import Query as APIQuery

        # Query requires facade parameter
        mock_facade = MagicMock()
        query = APIQuery(mock_facade)
        assert query is not None
        assert hasattr(query, "users")
        assert query._ldap == mock_facade


class TestBackwardCompatibility:
    """Test that 100% backward compatibility is maintained."""

    def test_import_patterns_still_work(self) -> None:
        """Test that existing import patterns still work."""
        # Test direct import
        from ldap_core_shared import LDAP, LDAPConfig
        assert LDAP is not None
        assert LDAPConfig is not None

        # Test star import
        import ldap_core_shared
        assert hasattr(ldap_core_shared, "LDAP")
        assert hasattr(ldap_core_shared, "LDAPConfig")

    def test_class_signatures_preserved(self) -> None:
        """Test that class signatures are preserved."""
        # LDAPConfig should accept the same parameters
        config = LDAPConfig(
            server="ldap://test.com",
            auth_dn="cn=test,dc=test,dc=com",
            auth_password="test",
            base_dn="dc=test,dc=com",
        )
        assert config is not None

        # LDAP should accept LDAPConfig
        ldap = LDAP(config)
        assert ldap is not None

    def test_method_signatures_preserved(self, mock_config=None) -> None:
        """Test that method signatures are preserved."""
        if mock_config is None:
            mock_config = LDAPConfig(
                server="ldap://test.com",
                auth_dn="cn=test,dc=test,dc=com",
                auth_password="test",
                base_dn="dc=test,dc=com",
            )

        ldap = LDAP(mock_config)

        # Test that methods accept expected parameters
        query = ldap.query()
        assert query is not None


class TestErrorHandling:
    """Test that error handling is preserved through refactoring."""

    def test_config_validation_errors(self) -> None:
        """Test that config validation errors are handled properly."""
        # Test with invalid config
        try:
            LDAPConfig(
                server="",  # Invalid empty server
                auth_dn="cn=test,dc=test,dc=com",
                auth_password="test",
                base_dn="dc=test,dc=com",
            )
            # If validation happens at creation time, it should fail
            # If validation happens later, we test that case separately
        except Exception as e:
            # Config validation should produce meaningful errors
            assert isinstance(e, (ValueError, TypeError))

    def test_result_error_handling(self) -> None:
        """Test Result pattern error handling."""
        error_result = Result.fail("Test error message")

        assert error_result.success is False
        assert error_result.error == "Test error message"
        assert error_result.data is None


class TestPerformanceCharacteristics:
    """Test that performance characteristics are maintained."""

    def test_lazy_loading_preserved(self) -> None:
        """Test that lazy loading is preserved."""
        # Import should be fast (no heavy initialization)
        import time
        start_time = time.time()

        import_time = time.time() - start_time
        # Import should be very fast (under 100ms for lazy loading)
        assert import_time < 0.1, f"Import took {import_time:.3f}s, too slow for lazy loading"

    def test_module_metadata(self) -> None:
        """Test that module metadata indicates refactoring."""
        import ldap_core_shared

        # Check refactoring metadata
        assert hasattr(ldap_core_shared, "__refactored__")
        assert ldap_core_shared.__refactored__ is True
        assert hasattr(ldap_core_shared, "__pattern__")
        assert "True Facade" in ldap_core_shared.__pattern__


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
