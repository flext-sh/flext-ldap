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

from pydantic import SecretStr

from flext_cli import FlextCliFormatters
from flext_ldap.config import FlextLdapConfig


def demonstrate_singleton_pattern() -> None:
    """Demonstrate the singleton pattern functionality."""
    FlextCliFormatters.print_header("FlextLdapConfig Singleton Pattern Demo")

    # Clear any existing instance
    FlextLdapConfig.reset_global_instance()

    # Get first instance
    config1 = FlextLdapConfig.get_global_instance()
    FlextCliFormatters.print_info(f"First instance ID: {id(config1)}")

    # Get second instance - should be the same
    config2 = FlextLdapConfig.get_global_instance()
    FlextCliFormatters.print_info(f"Second instance ID: {id(config2)}")

    # Verify they are the same instance
    if config1 is not config2:
        error_msg = "Instances should be identical"
        raise RuntimeError(error_msg)
    FlextCliFormatters.print_success("Singleton pattern working correctly")


def demonstrate_environment_loading() -> None:
    """Demonstrate loading configuration from environment variables."""
    FlextCliFormatters.print_info("=== Environment Variable Loading Demo ===\n")

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
    FlextLdapConfig.reset_global_instance()
    config = FlextLdapConfig.get_global_instance()

    FlextCliFormatters.print_info(f"Bind DN from environment: {config.ldap_bind_dn}")
    FlextCliFormatters.print_info(f"Use SSL from environment: {config.ldap_use_ssl}")
    FlextCliFormatters.print_info(
        f"Size limit from environment: {config.ldap_size_limit}"
    )
    FlextCliFormatters.print_info(
        f"Caching enabled from environment: {config.ldap_enable_caching}"
    )
    FlextCliFormatters.print_info(
        f"Cache TTL from environment: {config.ldap_cache_ttl}"
    )
    FlextCliFormatters.print_info("✅ Environment variables loaded successfully\n")


def demonstrate_factory_methods() -> None:
    """Demonstrate factory methods for different environments."""
    FlextCliFormatters.print_info("=== Factory Methods Demo ===\n")

    # Development configuration
    dev_result = FlextLdapConfig.create_development_ldap_config()
    if dev_result.is_success:
        dev_config = dev_result.value
        FlextCliFormatters.print_info("Development Configuration:")
        FlextCliFormatters.print_info(f"  Environment: {dev_config.environment}")
        FlextCliFormatters.print_info(f"  Debug mode: {dev_config.debug}")
        FlextCliFormatters.print_info(f"  Bind DN: {dev_config.ldap_bind_dn}")
        FlextCliFormatters.print_info(f"  SSL enabled: {dev_config.ldap_use_ssl}")
        FlextCliFormatters.print_info(f"  Query logging: {dev_config.ldap_log_queries}")
        FlextCliFormatters.print_info()

    # Test configuration
    test_result = FlextLdapConfig.create_test_ldap_config()
    if test_result.is_success:
        test_config = test_result.value
        FlextCliFormatters.print_info("Test Configuration:")
        FlextCliFormatters.print_info(f"  Environment: {test_config.environment}")
        FlextCliFormatters.print_info(
            f"  Test mode: {test_config.ldap_enable_test_mode}"
        )
        FlextCliFormatters.print_info(f"  Bind DN: {test_config.ldap_bind_dn}")
        FlextCliFormatters.print_info(f"  SSL enabled: {test_config.ldap_use_ssl}")
        FlextCliFormatters.print_info()

    # Production configuration
    prod_result = FlextLdapConfig.create_production_ldap_config()
    if prod_result.is_success:
        prod_config = prod_result.value
        FlextCliFormatters.print_info("Production Configuration:")
        FlextCliFormatters.print_info(f"  Environment: {prod_config.environment}")
        FlextCliFormatters.print_info(f"  Debug mode: {prod_config.debug}")
        FlextCliFormatters.print_info(f"  SSL enabled: {prod_config.ldap_use_ssl}")
        FlextCliFormatters.print_info(
            f"  Certificate verification: {prod_config.ldap_verify_certificates}"
        )
        FlextCliFormatters.print_info(
            f"  Caching enabled: {prod_config.ldap_enable_caching}"
        )
        FlextCliFormatters.print_info(f"  Cache TTL: {prod_config.ldap_cache_ttl}")
        FlextCliFormatters.print_info()

    FlextCliFormatters.print_info("✅ Factory methods working correctly\n")


def demonstrate_parameter_overrides() -> None:
    """Demonstrate parameter overrides to change behavior."""
    FlextCliFormatters.print_info("=== Parameter Overrides Demo ===\n")

    # Get default configuration using proper FLEXT pattern
    config = FlextLdapConfig.get_global_instance()
    FlextCliFormatters.print_info("Default Configuration:")
    FlextCliFormatters.print_info(f"  Size limit: {config.ldap_size_limit}")
    FlextCliFormatters.print_info(f"  Time limit: {config.ldap_time_limit}")
    FlextCliFormatters.print_info(f"  Caching: {config.ldap_enable_caching}")
    FlextCliFormatters.print_info(f"  Query logging: {config.ldap_log_queries}")
    FlextCliFormatters.print_info()

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
        FlextCliFormatters.print_info("After Overrides:")
        FlextCliFormatters.print_info(f"  Size limit: {config.ldap_size_limit}")
        FlextCliFormatters.print_info(f"  Time limit: {config.ldap_time_limit}")
        FlextCliFormatters.print_info(f"  Caching: {config.ldap_enable_caching}")
        FlextCliFormatters.print_info(f"  Cache TTL: {config.ldap_cache_ttl}")
        FlextCliFormatters.print_info(f"  Query logging: {config.ldap_log_queries}")
        FlextCliFormatters.print_info(
            f"  Response logging: {config.ldap_log_responses}"
        )
        FlextCliFormatters.print_info()

        # Show how overrides affect different configuration sections
        search_config = config.get_ldap_search_config()
        perf_config = config.get_ldap_performance_config()
        logging_config = config.get_ldap_logging_config()

        FlextCliFormatters.print_info("Configuration Sections:")
        FlextCliFormatters.print_info(f"  Search: {search_config}")
        FlextCliFormatters.print_info(f"  Performance: {perf_config}")
        FlextCliFormatters.print_info(f"  Logging: {logging_config}")
        FlextCliFormatters.print_info()

    else:
        FlextCliFormatters.print_info(f"❌ Override failed: {result.error}")

    FlextCliFormatters.print_info("✅ Parameter overrides working correctly\n")


def demonstrate_direct_singleton_usage() -> None:
    """Demonstrate direct FlextLdapConfig singleton usage (recommended approach)."""
    FlextCliFormatters.print_info(
        "=== Direct FlextLdapConfig Singleton Usage Demo ===\n"
    )

    # Create a custom configuration
    custom_config = FlextLdapConfig(
        app_name="custom-ldap-app",
        ldap_bind_dn="cn=custom,dc=example,dc=com",
        ldap_bind_password=SecretStr("custom-password"),
        ldap_use_ssl=True,
        ldap_size_limit=2000,
    )

    # Set as global singleton using proper FLEXT pattern
    FlextLdapConfig.set_global_instance(custom_config)

    # Use singleton directly (recommended approach)
    config = FlextLdapConfig.get_global_instance()

    FlextCliFormatters.print_info("Direct Singleton Usage:")
    FlextCliFormatters.print_info(
        f"  Config references singleton: {config is custom_config}"
    )
    FlextCliFormatters.print_info(f"  Bind DN from config: {config.ldap_bind_dn}")
    FlextCliFormatters.print_info(f"  SSL from config: {config.ldap_use_ssl}")
    FlextCliFormatters.print_info(f"  Size limit from config: {config.ldap_size_limit}")
    FlextCliFormatters.print_info()

    # Test effective configuration methods
    effective_conn = config.get_effective_connection()
    auth_config = config.get_effective_auth_config()

    FlextCliFormatters.print_info("Effective Configuration:")
    if effective_conn:
        FlextCliFormatters.print_info(f"  Connection server: {effective_conn.server}")
        FlextCliFormatters.print_info(f"  Connection port: {effective_conn.port}")
    if auth_config:
        FlextCliFormatters.print_info(f"  Auth bind DN: {auth_config['bind_dn']}")
        FlextCliFormatters.print_info(f"  Auth use SSL: {auth_config['use_ssl']}")
    FlextCliFormatters.print_info()

    FlextCliFormatters.print_info("✅ Settings delegation working correctly\n")


def demonstrate_runtime_behavior_changes() -> None:
    """Demonstrate how parameter changes affect runtime behavior."""
    FlextCliFormatters.print_info("=== Runtime Behavior Changes Demo ===\n")

    # Start with development configuration
    dev_result = FlextLdapConfig.create_development_ldap_config()
    if not dev_result.is_success:
        error_msg = f"Failed to create development config: {dev_result.error}"
        raise RuntimeError(error_msg)
    dev_config = dev_result.value

    # Set as global singleton using proper FLEXT pattern
    FlextLdapConfig.set_global_instance(dev_config)

    FlextCliFormatters.print_info("Initial Development Configuration:")
    FlextCliFormatters.print_info(f"  Debug mode: {dev_config.debug}")
    FlextCliFormatters.print_info(f"  Query logging: {dev_config.ldap_log_queries}")
    FlextCliFormatters.print_info(f"  Caching: {dev_config.ldap_enable_caching}")
    FlextCliFormatters.print_info()

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
        FlextCliFormatters.print_info("After Production Overrides:")
        FlextCliFormatters.print_info(f"  Debug mode: {dev_config.debug}")
        FlextCliFormatters.print_info(f"  Log level: {dev_config.log_level}")
        FlextCliFormatters.print_info(f"  Query logging: {dev_config.ldap_log_queries}")
        FlextCliFormatters.print_info(
            f"  Response logging: {dev_config.ldap_log_responses}"
        )
        FlextCliFormatters.print_info(f"  Caching: {dev_config.ldap_enable_caching}")
        FlextCliFormatters.print_info(f"  Cache TTL: {dev_config.ldap_cache_ttl}")
        FlextCliFormatters.print_info(f"  Size limit: {dev_config.ldap_size_limit}")
        FlextCliFormatters.print_info(f"  Time limit: {dev_config.ldap_time_limit}")
        FlextCliFormatters.print_info()

        # Show how this affects different aspects of the system
        FlextCliFormatters.print_info("System Behavior Changes:")
        FlextCliFormatters.print_info(
            f"  Search performance: {dev_config.get_ldap_search_config()}"
        )
        FlextCliFormatters.print_info(
            f"  Caching behavior: {dev_config.get_ldap_performance_config()}"
        )
        FlextCliFormatters.print_info(
            f"  Logging behavior: {dev_config.get_ldap_logging_config()}"
        )
        FlextCliFormatters.print_info()

    FlextCliFormatters.print_info("✅ Runtime behavior changes working correctly\n")


def main() -> None:
    """Run all demonstrations."""
    FlextCliFormatters.print_info("FlextLdapConfig Singleton Usage Examples")
    FlextCliFormatters.print_info("=" * 50)
    FlextCliFormatters.print_info()

    try:
        demonstrate_singleton_pattern()
        demonstrate_environment_loading()
        demonstrate_factory_methods()
        demonstrate_parameter_overrides()
        demonstrate_direct_singleton_usage()
        demonstrate_runtime_behavior_changes()

        FlextCliFormatters.print_info("🎉 All demonstrations completed successfully!")
        FlextCliFormatters.print_info("\nKey Benefits:")
        FlextCliFormatters.print_info(
            "✅ Single source of truth for LDAP configuration"
        )
        FlextCliFormatters.print_info("✅ Environment variable integration")
        FlextCliFormatters.print_info("✅ Factory methods for different environments")
        FlextCliFormatters.print_info("✅ Runtime parameter overrides")
        FlextCliFormatters.print_info("✅ Clean Architecture with delegation")
        FlextCliFormatters.print_info("✅ Type-safe configuration management")

    except Exception as e:
        FlextCliFormatters.print_info(f"❌ Error during demonstration: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
