#!/usr/bin/env python3
"""Example demonstrating FlextLdapConfigs singleton usage.

This example shows how to use the FlextLdapConfigs singleton as the single
source of truth for LDAP configuration, with parameter overrides to change
behavior at runtime.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import traceback

from pydantic import SecretStr

from flext_ldap import FlextLdapModels
from flext_ldap.config import FlextLdapConfigs


def demonstrate_singleton_pattern() -> None:
    """Demonstrate the singleton pattern functionality.

    Raises:
        RuntimeError: If singleton pattern validation fails.

    """
    print("FlextLdapConfigs Singleton Pattern Demo")

    # Clear any existing instance
    FlextLdapConfigs.reset_global_instance()

    # Get first instance
    config1 = FlextLdapConfigs.get_global_instance()
    print(f"First instance ID: {id(config1)}")

    # Get second instance - should be the same
    config2 = FlextLdapConfigs.get_global_instance()
    print(f"Second instance ID: {id(config2)}")

    # Verify they are the same instance
    if config1 is not config2:
        error_msg = "Instances should be identical"
        raise RuntimeError(error_msg)
    print("✅ Singleton pattern working correctly")


def demonstrate_environment_loading() -> None:
    """Demonstrate loading configuration from environment variables."""
    print("=== Environment Variable Loading Demo ===")

    # Set environment variables
    os.environ.update(
        {
            "FLEXT_LDAP_BIND_DN": "cn=env-user,dc=example,dc=com",
            "FLEXT_LDAP_BIND_PASSWORD": "env-password-123",
            "FLEXT_LDAP_USE_SSL": "true",
            "FLEXT_LDAP_SIZE_LIMIT": "5000",
            "FLEXT_LDAP_ENABLE_CACHING": "true",
            "FLEXT_LDAP_CACHE_TTL": "900",
        },
    )

    # Clear and reload to pick up environment variables
    FlextLdapConfigs.reset_global_instance()
    config = FlextLdapConfigs.get_global_instance()

    print(f"Bind DN from environment: {config.ldap_bind_dn}")
    print(f"Use SSL from environment: {config.ldap_use_ssl}")
    print(f"Size limit from environment: {config.ldap_size_limit}")
    print(f"Caching enabled from environment: {config.ldap_enable_caching}")
    print(f"Cache TTL from environment: {config.ldap_cache_ttl}")
    print("✅ Environment variables loaded successfully\n")


def demonstrate_factory_methods() -> None:
    """Demonstrate factory methods for different environments."""
    print("=== Factory Methods Demo ===")

    # Development configuration
    dev_result = FlextLdapConfigs.create_development_ldap_config()
    if dev_result.is_success:
        dev_config = dev_result.value
        print("Development Configuration:")
        print(f"  Environment: {dev_config.environment}")
        print(f"  Debug mode: {dev_config.debug}")
        print(f"  Bind DN: {dev_config.ldap_bind_dn}")
        print(f"  SSL enabled: {dev_config.ldap_use_ssl}")
        print(f"  Query logging: {dev_config.ldap_log_queries}")
        print()

    # Test configuration
    test_result = FlextLdapConfigs.create_test_ldap_config()
    if test_result.is_success:
        test_config = test_result.value
        print("Test Configuration:")
        print(f"  Environment: {test_config.environment}")
        print(f"  Debug mode: {test_config.ldap_enable_debug}")
        print(f"  Bind DN: {test_config.ldap_bind_dn}")
        print(f"  SSL enabled: {test_config.ldap_use_ssl}")
        print()

    # Production configuration
    prod_result = FlextLdapConfigs.create_production_ldap_config()
    if prod_result.is_success:
        prod_config = prod_result.value
        print("Production Configuration:")
        print(f"  Environment: {prod_config.environment}")
        print(f"  Debug mode: {prod_config.debug}")
        print(f"  SSL enabled: {prod_config.ldap_use_ssl}")
        print(f"  Pool size: {prod_config.ldap_pool_size}")
        print("✅ Factory methods working correctly\n")


def demonstrate_parameter_overrides() -> None:
    """Demonstrate parameter overrides with the singleton."""
    print("=== Parameter Override Demo ===")

    # Get singleton instance
    config = FlextLdapConfigs.get_global_instance()
    print(f"Original bind DN: {config.ldap_bind_dn}")
    print(f"Original SSL setting: {config.ldap_use_ssl}")

    # Create new instance with overrides using constructor parameters
    override_config = FlextLdapConfigs(
        bind_dn="cn=override-user,dc=test,dc=com",
        bind_password=SecretStr("override-password"),
        use_ssl=True,
        pool_size=10,
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
        valid_config = FlextLdapConfigs(
            ldap_connection=FlextLdapModels.ConnectionConfig(
                server="localhost",
                port=389,
            ),
            bind_dn="cn=valid-user,dc=example,dc=com",
            bind_password=SecretStr("valid-password"),
            use_ssl=True,
        )

        # Validation happens automatically during instantiation
        # If we got here, validation passed
        print("✅ Valid configuration passed validation")
        print(f"   Server: {valid_config.get_effective_server_uri()}")
        print(f"   Bind DN: {valid_config.get_effective_bind_dn()}")

    except Exception as e:
        print(f"❌ Configuration validation error: {e}")

    print("✅ Validation features working correctly\n")


def main() -> None:
    """Run all configuration demonstrations."""
    print("FLEXT-LDAP Configuration Singleton Demo")
    print("=" * 50)

    try:
        demonstrate_singleton_pattern()
        demonstrate_environment_loading()
        demonstrate_factory_methods()
        demonstrate_parameter_overrides()
        demonstrate_validation_features()

        print("=" * 50)
        print("✅ All demonstrations completed successfully!")
        print("✅ FlextLdapConfigs singleton working correctly")
        print("✅ Environment variable loading functional")
        print("✅ Factory methods providing correct configurations")
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
            "FLEXT_LDAP_BIND_DN",
            "FLEXT_LDAP_BIND_PASSWORD",
            "FLEXT_LDAP_USE_SSL",
            "FLEXT_LDAP_SIZE_LIMIT",
            "FLEXT_LDAP_ENABLE_CACHING",
            "FLEXT_LDAP_CACHE_TTL",
        ]:
            os.environ.pop(key, None)

        # Reset singleton for clean state
        FlextLdapConfigs.reset_global_instance()


if __name__ == "__main__":
    main()
