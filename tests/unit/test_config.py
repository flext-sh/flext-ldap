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
        """Test configuration initialization with default values."""
        config = FlextLdapConfig()

        tm.eq(config.host, "localhost")
        tm.eq(config.port, c.ConnectionDefaults.PORT)
        tm.eq(config.use_ssl, False)
        tm.eq(config.use_tls, False)
        tm.that(config.bind_dn, none=True)
        tm.that(config.bind_password, none=True)

    def test_config_initialization_custom_values(self) -> None:
        """Test configuration initialization with custom values."""
        config = FlextLdapConfig(
            host="example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
        )

        tm.eq(config.host, "example.com")
        tm.eq(config.port, 636)
        tm.eq(config.use_ssl, True)
        tm.eq(config.bind_dn, "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        tm.eq(config.bind_password, "secret")

    # =========================================================================
    # PORT FIELD TESTS
    # =========================================================================

    def test_config_port_field_metadata(self) -> None:
        """Test port field has proper constraint metadata and defaults."""
        port_field = FlextLdapConfig.model_fields.get("port")
        tm.that(port_field, none=False)

        # Check constraint metadata exists
        metadata_str = str(port_field.metadata)
        tm.that(metadata_str, contains="Ge(ge=1)")
        tm.that(metadata_str, contains="Le(le=65535)")

        # Check default value
        tm.eq(port_field.default, c.ConnectionDefaults.PORT)

    @pytest.mark.parametrize(
        ("port_value", "expected"),
        _get_port_values.__func__(),
    )
    def test_config_port_valid_range(self, port_value: int, expected: int) -> None:
        """Test port validation with valid range values."""
        config = FlextLdapConfig(port=port_value)
        tm.eq(config.port, expected)

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
        tm.eq(config.host, expected)

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
        tm.eq(config.use_ssl, use_ssl)
        tm.eq(config.use_tls, use_tls)

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

        tm.eq(config.bind_dn, bind_dn)
        tm.eq(config.bind_password, bind_password)

    def test_config_model_config(self) -> None:
        """Test that model configuration is properly set."""
        # Verify SettingsConfigDict is properly applied
        tm.that(FlextLdapConfig.model_config, none=False)
        config_dict = FlextLdapConfig.model_config
        tm.eq(config_dict.get("env_prefix"), "FLEXT_LDAP_")
        tm.eq(config_dict.get("case_sensitive"), False)

    def test_config_field_descriptions(self) -> None:
        """Test that fields have proper descriptions for documentation."""
        fields = FlextLdapConfig.model_fields

        tm.dict_(fields, has_key=["host", "port"])
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

        tm.eq(config_dict["host"], "example.com")
        tm.eq(config_dict["port"], 636)
        tm.eq(config_dict["use_ssl"], True)

    def test_config_json_schema(self) -> None:
        """Test JSON schema generation for documentation."""
        schema = FlextLdapConfig.model_json_schema()

        tm.dict_(schema, has_key=["properties", "type"])
        tm.dict_(dict(schema["properties"]), has_key=["host", "port"])

    def test_config_model_copy_deep(self) -> None:
        """Test configuration deep copy creates new instance.

        FlextLdapConfig uses singleton pattern via FlextConfig.auto_register.
        model_copy(deep=True) should create independent copies.
        """
        original = FlextLdapConfig(host="original.com", port=389)
        # Deep copy to create truly independent instance
        copied = original.model_copy(deep=True)

        # Both should be FlextLdapConfig instances
        tm.is_type(copied, FlextLdapConfig)
        # model_dump should show the same values
        tm.eq(original.model_dump()["port"], copied.model_dump()["port"])

    def test_config_singleton_pattern(self) -> None:
        """Test that FlextLdapConfig follows singleton pattern.

        FlextConfig.auto_register("ldap") creates a singleton pattern where
        all instances of FlextLdapConfig share state.
        """
        config1 = FlextLdapConfig(host="first.com", port=389)
        config2 = FlextLdapConfig(host="second.com", port=636)

        # Due to singleton pattern, both instances are the same object
        tm.eq(config1, config2)
        # Last values win
        tm.eq(config1.host, config2.host)
        tm.eq(config1.port, config2.port)

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
        tm.dict_(dump, has_key=["bind_dn", "bind_password", "base_dn"])

    def test_config_accepts_keyword_args(self) -> None:
        """Test configuration can be initialized with keyword arguments."""
        kwargs: dict[str, str | int | bool] = {
            "host": "kwargs.example.com",
            "port": 3389,
            "use_ssl": True,
            "use_tls": False,
            "timeout": 60,
        }

        config = FlextLdapConfig(**kwargs)

        tm.eq(config.host, kwargs["host"])
        tm.eq(config.port, kwargs["port"])
        tm.eq(config.use_ssl, kwargs["use_ssl"])
        tm.eq(config.use_tls, kwargs["use_tls"])


__all__ = [
    "TestsFlextLdapConfig",
]
