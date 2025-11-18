"""Unit tests for FlextLdapModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldap.models import FlextLdapModels


class TestConnectionConfig:
    """Tests for ConnectionConfig model."""

    def test_connection_config_defaults(self) -> None:
        """Test ConnectionConfig with default values."""
        config = FlextLdapModels.ConnectionConfig(host="ldap.example.com")
        assert config.host == "ldap.example.com"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.use_tls is False
        assert config.bind_dn is None
        assert config.bind_password is None
        assert config.timeout == 30
        assert config.auto_bind is True
        assert config.auto_range is True

    def test_connection_config_custom(self) -> None:
        """Test ConnectionConfig with custom values."""
        config = FlextLdapModels.ConnectionConfig(
            host="ldap.example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="password",
            timeout=60,
        )
        assert config.host == "ldap.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert config.bind_password == "password"
        assert config.timeout == 60


class TestSearchOptions:
    """Tests for SearchOptions model."""

    def test_search_options_defaults(self) -> None:
        """Test SearchOptions with default values."""
        options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        assert options.base_dn == "dc=example,dc=com"
        assert options.filter_str == "(objectClass=*)"
        assert options.scope == "SUBTREE"
        assert options.attributes is None
        assert options.size_limit == 0
        assert options.time_limit == 0

    def test_search_options_custom(self) -> None:
        """Test SearchOptions with custom values."""
        options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(cn=test)",
            scope="ONELEVEL",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
        )
        assert options.base_dn == "dc=example,dc=com"
        assert options.filter_str == "(cn=test)"
        assert options.scope == "ONELEVEL"
        assert options.attributes == ["cn", "mail"]
        assert options.size_limit == 100
        assert options.time_limit == 30


class TestOperationResult:
    """Tests for OperationResult model."""

    def test_operation_result_success(self) -> None:
        """Test OperationResult with success."""
        result = FlextLdapModels.OperationResult(
            success=True,
            operation_type="add",
            entries_affected=1,
        )
        assert result.success is True
        assert result.operation_type == "add"
        assert result.entries_affected == 1

    def test_operation_result_failure(self) -> None:
        """Test OperationResult with failure."""
        result = FlextLdapModels.OperationResult(
            success=False,
            operation_type="add",
            entries_affected=0,
        )
        assert result.success is False
        assert result.operation_type == "add"
        assert result.entries_affected == 0


class TestSyncStats:
    """Tests for SyncStats model."""

    def test_sync_stats_defaults(self) -> None:
        """Test SyncStats with default values."""
        stats = FlextLdapModels.SyncStats()
        assert stats.added == 0
        assert stats.skipped == 0
        assert stats.failed == 0
        assert stats.total == 0
        assert stats.duration_seconds == 0.0

    def test_sync_stats_custom(self) -> None:
        """Test SyncStats with custom values."""
        stats = FlextLdapModels.SyncStats(
            added=5,
            skipped=2,
            failed=1,
            total=8,
            duration_seconds=1.5,
        )
        assert stats.added == 5
        assert stats.skipped == 2
        assert stats.failed == 1
        assert stats.total == 8
        assert stats.duration_seconds == 1.5

    def test_sync_stats_success_rate(self) -> None:
        """Test SyncStats success_rate calculation."""
        stats = FlextLdapModels.SyncStats(
            added=7,
            skipped=2,
            failed=1,
            total=10,
        )
        # success_rate = (7 + 2) / 10 = 0.9
        assert stats.success_rate == 0.9

    def test_sync_stats_success_rate_zero_total(self) -> None:
        """Test SyncStats success_rate when total is 0 (covers line 309)."""
        stats = FlextLdapModels.SyncStats(
            added=0,
            skipped=0,
            failed=0,
            total=0,  # Zero total - should return 0.0 (covers line 309)
        )
        # When total is 0, success_rate should return 0.0 (covers line 309)
        assert stats.success_rate == 0.0


class TestConfigDefault:
    """Tests for _get_config_default helper function."""

    def test_get_config_default_with_valid_types(self) -> None:
        """Test _get_config_default with valid types."""
        from flext_ldap.models import _get_config_default

        # Test with valid field names that return expected types
        host = _get_config_default("ldap_host")
        assert isinstance(host, (str, type(None)))

        port = _get_config_default("ldap_port")
        assert isinstance(port, (int, type(None)))

        use_ssl = _get_config_default("ldap_use_ssl")
        assert isinstance(use_ssl, (bool, type(None)))

    def test_get_config_default_with_unexpected_type(
        self,
    ) -> None:
        """Test _get_config_default with unexpected type (covers lines 59-63).

        This test uses class substitution to modify the config class before
        _get_config_default creates an instance. This is a real operation
        (not a mock) - we're creating a real subclass and temporarily replacing
        the class in the module.

        The test creates a subclass of FlextLdapConfig that returns an invalid
        type via property override. When _get_config_default creates an instance
        and calls getattr(), it will receive the invalid type and trigger the
        defensive check at lines 59-63.
        """
        import importlib
        import sys

        import flext_ldap.config as config_module
        from flext_ldap.config import FlextLdapConfig
        from flext_ldap.models import _get_config_default

        # Save original class
        original_config_class = config_module.FlextLdapConfig

        # Create a subclass that sets invalid type after Pydantic validation
        # We override __init__ to set invalid type using object.__setattr__
        # after calling super().__init__() which validates with Pydantic
        class InvalidTypeConfig(FlextLdapConfig):
            """Config that sets invalid type after Pydantic validation."""

            def __init__(self, **kwargs: object) -> None:
                """Initialize with Pydantic validation, then set invalid type."""
                # Call parent __init__ which validates with Pydantic
                super().__init__(**kwargs)
                # After validation, use object.__setattr__ to set invalid type
                # This bypasses Pydantic's validation but tests defensive code
                object.__setattr__(self, "ldap_host", ["invalid", "list", "type"])

        # Temporarily replace the class in the config module
        config_module.FlextLdapConfig = InvalidTypeConfig  # type: ignore[assignment]

        # Reload models module to pick up the patched class
        # Since _get_config_default does "from flext_ldap.config import FlextLdapConfig"
        # inside the function, we need to reload the module to clear the import cache
        if "flext_ldap.models" in sys.modules:
            importlib.reload(sys.modules["flext_ldap.models"])

        try:
            # This should raise TypeError (covers lines 59-63)
            # The InvalidTypeConfig.__init__ sets ldap_host to a list after Pydantic validation
            # When _get_config_default calls getattr(config, "ldap_host"), it gets the list
            # The isinstance check at line 56 will fail (list is not str/int/bool/None)
            # So it will execute lines 59-63 (covers lines 59-63)
            with pytest.raises(TypeError) as exc_info:
                _get_config_default("ldap_host")

            # Verify the error message matches lines 59-63
            error_msg = str(exc_info.value)
            assert "Unexpected type" in error_msg
            assert "ldap_host" in error_msg or "config field" in error_msg
            assert "list" in error_msg or "List" in error_msg
            assert "Expected str, int, bool, or None" in error_msg
        finally:
            # Restore original class
            config_module.FlextLdapConfig = original_config_class
            # Reload models module to restore original import
            if "flext_ldap.models" in sys.modules:
                importlib.reload(sys.modules["flext_ldap.models"])
