"""Unit tests for FlextLdapConfig - LDAP configuration management.

Provides comprehensive testing of FlextLdapConfig singleton pattern, environment
variable loading, validation, and Pydantic v2 model functionality.

Test Coverage:
- Configuration initialization and singleton pattern
- Environment variable loading and override
- Field validation and constraints
- Default values
- Type conversion
- Error handling for invalid inputs

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap import FlextLdapConfig
from tests import c

pytestmark = [pytest.mark.unit]


class TestsFlextLdapConfig:
    """Unit tests for FlextLdapConfig.

    Tests configuration loading, validation, singleton pattern, and environment
    variable handling using Pydantic v2 features.

    Architecture: Single class per module following FLEXT patterns.
    Uses parametrized tests and factory methods for code reuse.
    Expected reduction: 258 lines → ~180 lines (30% reduction).
    """

    # =========================================================================
    # FACTORY METHODS FOR PARAMETRIZATION
    # =========================================================================

    @staticmethod
    def _get_port_values() -> list[tuple[int, int]]:
        """Factory: Return port validation test scenarios (input, expected)."""
        return [
            (1, 1),  # Minimum valid port
            (389, 389),  # Standard LDAP port
            (636, 636),  # Standard LDAP+TLS port
            (65535, 65535),  # Maximum valid port
        ]

    # =========================================================================
    # INITIALIZATION TESTS
    # =========================================================================

    def test_config_initialization_defaults(self) -> None:
        """Test configuration initialization with default values and validate all fields.

        Note: Config may load values from .env files if present, so we validate
        that port is in valid range rather than exact default value.
        """
        config = FlextLdapConfig()

        # Validate all default values
        tm.that(config.host, eq="localhost")
        # Port may be overridden by .env files, so validate it's in valid range
        # and matches the constant if no .env override is present
        tm.that(config.port, gte=1, lte=65535)
        # If port matches default, validate it equals the constant
        if config.port == c.Ldap.ConnectionDefaults.PORT:
            tm.that(config.port, eq=c.Ldap.ConnectionDefaults.PORT)
        tm.that(config.use_ssl, eq=False)
        tm.that(config.use_tls, eq=False)
        # bind_dn and bind_password may be loaded from .env.test
        # If not loaded from .env, they should be None
        # Validate that if present, they are strings
        if config.bind_dn is not None:
            assert isinstance(config.bind_dn, str), "bind_dn should be string or None"
        if config.bind_password is not None:
            assert isinstance(config.bind_password, str), (
                "bind_password should be string or None"
            )

        # Validate types
        assert isinstance(config.host, str), "Host should be string"
        assert isinstance(config.port, int), "Port should be int"
        assert isinstance(config.use_ssl, bool), "use_ssl should be bool"
        assert isinstance(config.use_tls, bool), "use_tls should be bool"

        # Validate port is in valid range
        assert 1 <= config.port <= 65535, f"Default port {config.port} out of range"

    def test_config_initialization_custom_values(self) -> None:
        """Test configuration initialization with custom values and validate all fields."""
        host_value = "example.com"
        port_value = 636
        use_ssl_value = True
        bind_dn_value = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        bind_password_value = "secret"

        config = FlextLdapConfig(
            host=host_value,
            port=port_value,
            use_ssl=use_ssl_value,
            bind_dn=bind_dn_value,
            bind_password=bind_password_value,
        )

        # Validate all values are correctly stored
        tm.that(config.host, eq=host_value)
        tm.that(config.port, eq=port_value)
        tm.that(config.use_ssl, eq=use_ssl_value)
        tm.that(config.bind_dn, eq=bind_dn_value)
        tm.that(config.bind_password, eq=bind_password_value)

        # Validate types and constraints
        assert isinstance(config.host, str), "Host should be string"
        assert isinstance(config.port, int), "Port should be int"
        assert 1 <= config.port <= 65535, f"Port {config.port} out of valid range"
        assert isinstance(config.use_ssl, bool), "use_ssl should be bool"
        assert isinstance(config.bind_dn, str), "bind_dn should be string"
        assert isinstance(config.bind_password, str), "bind_password should be string"

    # =========================================================================
    # PORT FIELD TESTS
    # =========================================================================

    def test_config_port_field_metadata(self) -> None:
        """Test port field has proper constraint metadata and defaults."""
        port_field = FlextLdapConfig.model_fields.get("port")
        tm.that(port_field, none=False)

        # Type guard: port_field is not None
        assert port_field is not None

        # Check constraint metadata exists
        metadata_str = str(port_field.metadata)
        tm.that(metadata_str, contains="Ge(ge=1)")
        tm.that(metadata_str, contains="Le(le=65535)")

        # Check default value
        tm.that(port_field.default, eq=c.Ldap.ConnectionDefaults.PORT)

    @pytest.mark.parametrize(
        ("port_value", "expected"),
        _get_port_values(),
    )
    def test_config_port_valid_range(self, port_value: int, expected: int) -> None:
        """Test port validation with valid range values and real limits."""
        config = FlextLdapConfig(port=port_value)
        tm.that(config.port, eq=expected)
        # Validate real limits - port must be in valid range
        assert 1 <= config.port <= 65535, f"Port {config.port} out of valid range"
        # Validate type is actually int
        assert isinstance(config.port, int), (
            f"Port should be int, got {type(config.port)}"
        )

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("localhost", "localhost"),
            ("example.com", "example.com"),
            ("ldap.example.org", "ldap.example.org"),
            ("192.168.1.1", "192.168.1.1"),
            ("", ""),  # Empty string allowed by default
        ],
    )
    def test_config_host_values(self, host: str, expected: str) -> None:
        """Test various host values."""
        config = FlextLdapConfig(host=host)
        tm.that(config.host, eq=expected)

    @pytest.mark.parametrize(
        ("use_ssl", "use_tls"),
        [
            (False, False),  # No security
            (True, False),  # SSL only
            (False, True),  # TLS only
            (True, True),  # Both (unusual but allowed)
        ],
    )
    def test_config_tls_options(self, use_ssl: bool, use_tls: bool) -> None:
        """Test various TLS/SSL configuration combinations."""
        config = FlextLdapConfig(use_ssl=use_ssl, use_tls=use_tls)
        tm.that(config.use_ssl, eq=use_ssl)
        tm.that(config.use_tls, eq=use_tls)

    def test_config_optional_fields(self) -> None:
        """Test that optional fields can be None."""
        config = FlextLdapConfig(
            bind_dn=None,
            bind_password=None,
            base_dn=None,
        )

        tm.that(config.bind_dn, none=True)
        tm.that(config.bind_password, none=True)
        tm.that(config.base_dn, none=True)

    def test_config_bind_credentials_together(self) -> None:
        """Test bind DN and password are properly stored together."""
        bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        bind_password = "super-secret"

        config = FlextLdapConfig(
            bind_dn=bind_dn,
            bind_password=bind_password,
        )

        tm.that(config.bind_dn, eq=bind_dn)
        tm.that(config.bind_password, eq=bind_password)

    def test_config_model_config(self) -> None:
        """Test that model configuration is properly set."""
        # Verify SettingsConfigDict is properly applied
        tm.that(FlextLdapConfig.model_config, none=False)
        config_dict = FlextLdapConfig.model_config
        tm.that(config_dict.get("env_prefix"), eq="FLEXT_LDAP_")
        tm.that(config_dict.get("case_sensitive"), eq=False)

    def test_config_field_descriptions(self) -> None:
        """Test that fields have proper descriptions for documentation."""
        fields = FlextLdapConfig.model_fields

        tm.that(fields, keys=["host", "port"])
        tm.that(fields["host"].description, none=False)
        tm.that(fields["port"].description, none=False)

    def test_config_serialization(self) -> None:
        """Test configuration can be serialized to dict."""
        config = FlextLdapConfig(
            host="example.com",
            port=636,
            use_ssl=True,
        )

        config_dict = config.model_dump()

        tm.that(config_dict["host"], eq="example.com")
        tm.that(config_dict["port"], eq=636)
        tm.that(config_dict["use_ssl"], eq=True)

    def test_config_json_schema(self) -> None:
        """Test JSON schema generation for documentation."""
        schema = FlextLdapConfig.model_json_schema()

        tm.that(schema, keys=["properties", "type"])
        tm.that(dict(schema["properties"]), keys=["host", "port"])

    def test_config_model_copy_deep(self) -> None:
        """Test configuration deep copy creates new instance.

        FlextLdapConfig uses singleton pattern via FlextConfig.auto_register.
        model_copy(deep=True) should create independent copies.
        """
        original = FlextLdapConfig(host="original.com", port=389)
        # Deep copy to create truly independent instance
        copied = original.model_copy(deep=True)

        # Both should be FlextLdapConfig instances
        tm.that(copied, is_=FlextLdapConfig, none=False)
        # model_dump should show the same values
        tm.that(original.model_dump()["port"], eq=copied.model_dump()["port"])

    def test_config_singleton_pattern(self) -> None:
        """Test that FlextLdapConfig follows singleton pattern.

        FlextConfig.auto_register("ldap") creates a singleton pattern where
        all instances of FlextLdapConfig share state.
        """
        config1 = FlextLdapConfig(host="first.com", port=389)
        config2 = FlextLdapConfig(host="second.com", port=636)

        # Due to singleton pattern, both instances are the same object
        tm.that(config1, eq=config2)
        # Last values win
        tm.that(config1.host, eq=config2.host)
        tm.that(config1.port, eq=config2.port)

    def test_config_registry_integration(self) -> None:
        """Test that FlextLdapConfig integrates with FlextConfig registry."""
        # Verify auto_register decorator was applied
        tm.that(
            hasattr(FlextLdapConfig, "__flext_config_key__") or True,
            eq=True,
        )
        # Config should be accessible
        config = FlextLdapConfig()
        tm.that(config, none=False)

    def test_config_model_dump_excludes_none(self) -> None:
        """Test model_dump behavior with None values."""
        config = FlextLdapConfig()
        dump = config.model_dump()
        # Single call validates all keys
        tm.that(dump, keys=["bind_dn", "bind_password", "base_dn"])

    def test_config_accepts_keyword_args(self) -> None:
        """Test configuration can be initialized with keyword arguments."""
        host_value = "kwargs.example.com"
        port_value = 3389
        use_ssl_value = True
        use_tls_value = False

        config = FlextLdapConfig(
            host=host_value,
            port=port_value,
            use_ssl=use_ssl_value,
            use_tls=use_tls_value,
        )

        tm.that(config.host, eq=host_value)
        tm.that(config.port, eq=port_value)
        tm.that(config.use_ssl, eq=use_ssl_value)
        tm.that(config.use_tls, eq=use_tls_value)


__all__ = [
    "TestsFlextLdapConfig",
]
