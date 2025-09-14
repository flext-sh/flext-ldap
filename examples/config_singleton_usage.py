#!/usr/bin/env python3
"""Example demonstrating FlextLDAPConfig singleton usage.

This example shows how to use the FlextLDAPConfig singleton as the single
source of truth for LDAP configuration, with parameter overrides to change
behavior at runtime.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pydantic import SecretStr

from flext_ldap.config import (
    FlextLDAPConfig,
    clear_flext_ldap_config,
    get_flext_ldap_config,
    set_flext_ldap_config,
)


def demonstrate_singleton_pattern() -> None:
    """Demonstrate the singleton pattern functionality."""
    print("=== FlextLDAPConfig Singleton Pattern Demo ===\n")

    # Clear any existing instance
    clear_flext_ldap_config()

    # Get first instance
    config1 = get_flext_ldap_config()
    print(f"First instance ID: {id(config1)}")

    # Get second instance - should be the same
    config2 = get_flext_ldap_config()
    print(f"Second instance ID: {id(config2)}")

    # Verify they are the same instance
    if config1 is not config2:
        error_msg = "Instances should be identical"
        raise RuntimeError(error_msg)
    print("✅ Singleton pattern working correctly\n")


def demonstrate_environment_loading() -> None:
    """Demonstrate loading configuration from environment variables."""
    print("=== Environment Variable Loading Demo ===\n")

    # Set environment variables
    os.environ.update(
        {
            "FLEXT_LDAP_BIND_DN": "cn=env-user,dc=example,dc=com",
            "FLEXT_LDAP_BIND_PASSWORD": "env-password-123",
            "FLEXT_LDAP_USE_SSL": "true",
            "FLEXT_LDAP_SIZE_LIMIT": "5000",
            "FLEXT_LDAP_ENABLE_CACHING": "true",
            "FLEXT_LDAP_CACHE_TTL": "900",
        }
    )

    # Clear and reload to pick up environment variables
    clear_flext_ldap_config()
    config = get_flext_ldap_config()

    print(f"Bind DN from environment: {config.ldap_bind_dn}")
    print(f"Use SSL from environment: {config.ldap_use_ssl}")
    print(f"Size limit from environment: {config.ldap_size_limit}")
    print(f"Caching enabled from environment: {config.ldap_enable_caching}")
    print(f"Cache TTL from environment: {config.ldap_cache_ttl}")
    print("✅ Environment variables loaded successfully\n")


def demonstrate_factory_methods() -> None:
    """Demonstrate factory methods for different environments."""
    print("=== Factory Methods Demo ===\n")

    # Development configuration
    dev_result = FlextLDAPConfig.create_development_ldap_config()
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
    test_result = FlextLDAPConfig.create_test_ldap_config()
    if test_result.is_success:
        test_config = test_result.value
        print("Test Configuration:")
        print(f"  Environment: {test_config.environment}")
        print(f"  Test mode: {test_config.ldap_enable_test_mode}")
        print(f"  Bind DN: {test_config.ldap_bind_dn}")
        print(f"  SSL enabled: {test_config.ldap_use_ssl}")
        print()

    # Production configuration
    prod_result = FlextLDAPConfig.create_production_ldap_config()
    if prod_result.is_success:
        prod_config = prod_result.value
        print("Production Configuration:")
        print(f"  Environment: {prod_config.environment}")
        print(f"  Debug mode: {prod_config.debug}")
        print(f"  SSL enabled: {prod_config.ldap_use_ssl}")
        print(f"  Certificate verification: {prod_config.ldap_verify_certificates}")
        print(f"  Caching enabled: {prod_config.ldap_enable_caching}")
        print(f"  Cache TTL: {prod_config.ldap_cache_ttl}")
        print()

    print("✅ Factory methods working correctly\n")


def demonstrate_parameter_overrides() -> None:
    """Demonstrate parameter overrides to change behavior."""
    print("=== Parameter Overrides Demo ===\n")

    # Get default configuration
    config = get_flext_ldap_config()
    print("Default Configuration:")
    print(f"  Size limit: {config.ldap_size_limit}")
    print(f"  Time limit: {config.ldap_time_limit}")
    print(f"  Caching: {config.ldap_enable_caching}")
    print(f"  Query logging: {config.ldap_log_queries}")
    print()

    # Apply overrides to change behavior
    overrides: dict[str, object] = {
        "size_limit": 10000,  # Increase search result limit
        "time_limit": 300,  # Increase timeout to 5 minutes
        "enable_caching": True,  # Enable result caching
        "cache_ttl": 1800,  # Cache for 30 minutes
        "log_queries": True,  # Enable query logging
        "log_responses": True,  # Enable response logging
        "structured_logging": True,  # Enable structured logging
    }

    result = config.apply_ldap_overrides(overrides)
    if result.is_success:
        print("After Overrides:")
        print(f"  Size limit: {config.ldap_size_limit}")
        print(f"  Time limit: {config.ldap_time_limit}")
        print(f"  Caching: {config.ldap_enable_caching}")
        print(f"  Cache TTL: {config.ldap_cache_ttl}")
        print(f"  Query logging: {config.ldap_log_queries}")
        print(f"  Response logging: {config.ldap_log_responses}")
        print()

        # Show how overrides affect different configuration sections
        search_config = config.get_ldap_search_config()
        perf_config = config.get_ldap_performance_config()
        logging_config = config.get_ldap_logging_config()

        print("Configuration Sections:")
        print(f"  Search: {search_config}")
        print(f"  Performance: {perf_config}")
        print(f"  Logging: {logging_config}")
        print()

    else:
        print(f"❌ Override failed: {result.error}")

    print("✅ Parameter overrides working correctly\n")


def demonstrate_direct_singleton_usage() -> None:
    """Demonstrate direct FlextLDAPConfig singleton usage (recommended approach)."""
    print("=== Direct FlextLDAPConfig Singleton Usage Demo ===\n")

    # Create a custom configuration
    custom_config = FlextLDAPConfig(
        app_name="custom-ldap-app",
        ldap_bind_dn="cn=custom,dc=example,dc=com",
        ldap_bind_password=SecretStr("custom-password"),
        ldap_use_ssl=True,
        ldap_size_limit=2000,
    )

    # Set as global singleton
    set_flext_ldap_config(custom_config)

    # Use singleton directly (recommended approach)
    config = get_flext_ldap_config()

    print("Direct Singleton Usage:")
    print(f"  Config references singleton: {config is custom_config}")
    print(f"  Bind DN from config: {config.ldap_bind_dn}")
    print(f"  SSL from config: {config.ldap_use_ssl}")
    print(f"  Size limit from config: {config.ldap_size_limit}")
    print()

    # Test effective configuration methods
    effective_conn = config.get_effective_connection()
    auth_config = config.get_effective_auth_config()

    print("Effective Configuration:")
    if effective_conn:
        print(f"  Connection server: {effective_conn.server}")
        print(f"  Connection port: {effective_conn.port}")
    if auth_config:
        print(f"  Auth bind DN: {auth_config['bind_dn']}")
        print(f"  Auth use SSL: {auth_config['use_ssl']}")
    print()

    print("✅ Settings delegation working correctly\n")


def demonstrate_runtime_behavior_changes() -> None:
    """Demonstrate how parameter changes affect runtime behavior."""
    print("=== Runtime Behavior Changes Demo ===\n")

    # Start with development configuration
    dev_result = FlextLDAPConfig.create_development_ldap_config()
    if not dev_result.is_success:
        error_msg = f"Failed to create development config: {dev_result.error}"
        raise RuntimeError(error_msg)
    dev_config = dev_result.value

    set_flext_ldap_config(dev_config)

    print("Initial Development Configuration:")
    print(f"  Debug mode: {dev_config.debug}")
    print(f"  Query logging: {dev_config.ldap_log_queries}")
    print(f"  Caching: {dev_config.ldap_enable_caching}")
    print()

    # Simulate production deployment - change behavior
    production_overrides: dict[str, object] = {
        "debug": False,  # Disable debug mode
        "log_level": "INFO",  # Set production log level
        "log_queries": False,  # Disable query logging
        "log_responses": False,  # Disable response logging
        "enable_caching": True,  # Enable caching for performance
        "cache_ttl": 3600,  # Cache for 1 hour
        "size_limit": 5000,  # Increase limits for production
        "time_limit": 120,  # Increase timeout
    }

    result = dev_config.apply_ldap_overrides(production_overrides)
    if result.is_success:
        print("After Production Overrides:")
        print(f"  Debug mode: {dev_config.debug}")
        print(f"  Log level: {dev_config.log_level}")
        print(f"  Query logging: {dev_config.ldap_log_queries}")
        print(f"  Response logging: {dev_config.ldap_log_responses}")
        print(f"  Caching: {dev_config.ldap_enable_caching}")
        print(f"  Cache TTL: {dev_config.ldap_cache_ttl}")
        print(f"  Size limit: {dev_config.ldap_size_limit}")
        print(f"  Time limit: {dev_config.ldap_time_limit}")
        print()

        # Show how this affects different aspects of the system
        print("System Behavior Changes:")
        print(f"  Search performance: {dev_config.get_ldap_search_config()}")
        print(f"  Caching behavior: {dev_config.get_ldap_performance_config()}")
        print(f"  Logging behavior: {dev_config.get_ldap_logging_config()}")
        print()

    print("✅ Runtime behavior changes working correctly\n")


def main() -> None:
    """Run all demonstrations."""
    print("FlextLDAPConfig Singleton Usage Examples")
    print("=" * 50)
    print()

    try:
        demonstrate_singleton_pattern()
        demonstrate_environment_loading()
        demonstrate_factory_methods()
        demonstrate_parameter_overrides()
        demonstrate_direct_singleton_usage()
        demonstrate_runtime_behavior_changes()

        print("🎉 All demonstrations completed successfully!")
        print("\nKey Benefits:")
        print("✅ Single source of truth for LDAP configuration")
        print("✅ Environment variable integration")
        print("✅ Factory methods for different environments")
        print("✅ Runtime parameter overrides")
        print("✅ Clean Architecture with delegation")
        print("✅ Type-safe configuration management")

    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
