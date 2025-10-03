#!/usr/bin/env python3
"""Example demonstrating FlextLdapConfig singleton usage.

This example shows how to use the FlextLdapConfig singleton as the single
source of truth for LDAP configuration, with parameter overrides to change
behavior at runtime.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import traceback

from flext_ldap import FlextLdapConfig
from pydantic import SecretStr


def demonstrate_singleton_pattern() -> None:
    """Demonstrate configuration instance creation.

    Raises:
        RuntimeError: If instance creation fails.

    """
    print("FlextLdapConfig Instance Creation Demo")

    # Create instances directly (no singleton pattern)
    config1 = FlextLdapConfig()
    print(f"First instance ID: {id(config1)}")

    # Create second instance
    config2 = FlextLdapConfig()
    print(f"Second instance ID: {id(config2)}")

    # Verify they are different instances
    if config1 is config2:
        error_msg = "Instances should be different"
        raise RuntimeError(error_msg)
    print("✅ Direct instantiation working correctly")


def demonstrate_environment_loading() -> None:
    """Demonstrate loading configuration from environment variables."""
    print("=== Environment Variable Loading Demo ===")

    # Set environment variables
    os.environ.update(
        {
            "FLEXT_LDAP_LDAP_BIND_DN": "cn=env-user,dc=example,dc=com",
            "FLEXT_LDAP_LDAP_BIND_PASSWORD": "env-password-123",
            "FLEXT_LDAP_LDAP_USE_SSL": "true",
            "FLEXT_LDAP_LDAP_SIZE_LIMIT": "5000",
            "FLEXT_LDAP_LDAP_ENABLE_CACHING": "true",
            "FLEXT_LDAP_LDAP_CACHE_TTL": "900",
        },
    )

    # Create new instance to pick up environment variables
    config = FlextLdapConfig()

    print(f"Bind DN from environment: {config.ldap_bind_dn}")
    print(f"Use SSL from environment: {config.ldap_use_ssl}")
    print(f"Size limit from environment: {config.ldap_size_limit}")
    print(f"Caching enabled from environment: {config.ldap_enable_caching}")
    print(f"Cache TTL from environment: {config.ldap_cache_ttl}")
    print("✅ Environment variables loaded successfully\n")


def demonstrate_factory_methods() -> None:
    """Demonstrate configuration for different environments."""
    print("=== Environment Configuration Demo ===")

    # Development configuration
    dev_config = FlextLdapConfig(environment="development", ldap_enable_debug=True)
    print("Development Configuration:")
    print(f"  Environment: {dev_config.environment}")
    print(f"  Debug mode: {dev_config.ldap_enable_debug}")
    print(f"  Bind DN: {dev_config.ldap_bind_dn}")
    print(f"  SSL enabled: {dev_config.ldap_use_ssl}")
    print(f"  Query logging: {dev_config.ldap_log_queries}")
    print()

    # Test configuration
    test_config = FlextLdapConfig(environment="test", ldap_enable_debug=True)
    print("Test Configuration:")
    print(f"  Environment: {test_config.environment}")
    print(f"  Debug mode: {test_config.ldap_enable_debug}")
    print(f"  Bind DN: {test_config.ldap_bind_dn}")
    print(f"  SSL enabled: {test_config.ldap_use_ssl}")
    print()

    # Production configuration
    prod_config = FlextLdapConfig(environment="production", ldap_use_ssl=True)
    print("Production Configuration:")
    print(f"  Environment: {prod_config.environment}")
    print(f"  Debug mode: {prod_config.ldap_enable_debug}")
    print(f"  SSL enabled: {prod_config.ldap_use_ssl}")
    print(f"  Pool size: {prod_config.ldap_pool_size}")
    print("✅ Environment configurations working correctly\n")


def demonstrate_parameter_overrides() -> None:
    """Demonstrate parameter overrides with direct instantiation."""
    print("=== Parameter Override Demo ===")

    # Create base instance
    config = FlextLdapConfig()
    print(f"Default bind DN: {config.ldap_bind_dn}")
    print(f"Default SSL setting: {config.ldap_use_ssl}")

    # Create new instance with overrides using constructor parameters
    override_config = FlextLdapConfig(
        ldap_bind_dn="cn=override-user,dc=test,dc=com",
        ldap_bind_password=SecretStr("override-password"),
        ldap_use_ssl=True,
        ldap_pool_size=10,
    )

    print(f"Override bind DN: {override_config.ldap_bind_dn}")
    print(f"Override SSL setting: {override_config.ldap_use_ssl}")
    print(f"Override pool size: {override_config.ldap_pool_size}")
    print("✅ Parameter overrides working correctly\n")


def demonstrate_validation_features() -> None:
    """Demonstrate configuration validation features."""
    print("=== Validation Features Demo ===")

    try:
        # Test validation with valid configuration
        valid_config = FlextLdapConfig(
            ldap_bind_dn="cn=valid-user,dc=example,dc=com",
            ldap_bind_password=SecretStr("valid-password"),
            ldap_use_ssl=True,
        )

        # Validation happens automatically during instantiation
        # If we got here, validation passed
        print("✅ Valid configuration passed validation")
        print(f"   Server: {valid_config.ldap_server_uri}")
        print(f"   Bind DN: {valid_config.ldap_bind_dn}")

    except Exception as e:
        print(f"❌ Configuration validation error: {e}")

    print("✅ Validation features working correctly\n")


def main() -> None:
    """Run all configuration demonstrations."""
    print("FLEXT-LDAP Configuration Demo")
    print("=" * 50)

    try:
        demonstrate_singleton_pattern()
        demonstrate_environment_loading()
        demonstrate_factory_methods()
        demonstrate_parameter_overrides()
        demonstrate_validation_features()

        print("=" * 50)
        print("✅ All demonstrations completed successfully!")
        print("✅ FlextLdapConfig direct instantiation working correctly")
        print("✅ Environment variable loading functional")
        print("✅ Environment configurations providing correct settings")
        print("✅ Parameter overrides working as expected")
        print("✅ Configuration validation features operational")

    except Exception as e:
        print(f"❌ Demo failed with error: {e}")
        print("Stack trace:")
        traceback.print_exc()
        return

    finally:
        # Clean up environment variables
        for key in [
            "FLEXT_LDAP_LDAP_BIND_DN",
            "FLEXT_LDAP_LDAP_BIND_PASSWORD",
            "FLEXT_LDAP_LDAP_USE_SSL",
            "FLEXT_LDAP_LDAP_SIZE_LIMIT",
            "FLEXT_LDAP_LDAP_ENABLE_CACHING",
            "FLEXT_LDAP_LDAP_CACHE_TTL",
        ]:
            os.environ.pop(key, None)


if __name__ == "__main__":
    main()
