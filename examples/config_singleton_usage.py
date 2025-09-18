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
    formatters = FlextCliFormatters()
    formatters.display_message("FlextLdapConfig Singleton Pattern Demo", "info")

    # Clear any existing instance
    FlextLdapConfig.reset_global_instance()

    # Get first instance
    config1 = FlextLdapConfig.get_global_instance()
    formatters.display_message(f"First instance ID: {id(config1)}", "info")

    # Get second instance - should be the same
    config2 = FlextLdapConfig.get_global_instance()
    formatters.display_message(f"Second instance ID: {id(config2)}", "info")

    # Verify they are the same instance
    if config1 is not config2:
        error_msg = "Instances should be identical"
        raise RuntimeError(error_msg)
    formatters.print_success("Singleton pattern working correctly")


def demonstrate_environment_loading() -> None:
    """Demonstrate loading configuration from environment variables."""
    formatters = FlextCliFormatters()
    formatters.display_message("=== Environment Variable Loading Demo ===", "info")

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

    formatters.display_message(
        f"Bind DN from environment: {config.ldap_bind_dn}", "info"
    )
    formatters.display_message(
        f"Use SSL from environment: {config.ldap_use_ssl}", "info"
    )
    formatters.display_message(f"Size limit from environment: {config.ldap_size_limit}")
    formatters.display_message(
        f"Caching enabled from environment: {config.ldap_enable_caching}"
    )
    formatters.display_message(f"Cache TTL from environment: {config.ldap_cache_ttl}")
    formatters.display_message("✅ Environment variables loaded successfully\n", "info")


def demonstrate_factory_methods() -> None:
    """Demonstrate factory methods for different environments."""
    formatters = FlextCliFormatters()
    formatters.display_message("=== Factory Methods Demo ===", "info")

    # Development configuration
    dev_result = FlextLdapConfig.create_development_ldap_config()
    if dev_result.is_success:
        dev_config = dev_result.value
        formatters.display_message("Development Configuration:", "info")
        formatters.display_message(f"  Environment: {dev_config.environment}", "info")
        formatters.display_message(f"  Debug mode: {dev_config.debug}", "info")
        formatters.display_message(f"  Bind DN: {dev_config.ldap_bind_dn}", "info")
        formatters.display_message(f"  SSL enabled: {dev_config.ldap_use_ssl}", "info")
        formatters.display_message(
            f"  Query logging: {dev_config.ldap_log_queries}", "info"
        )
        formatters.display_message("", "info")

    # Test configuration
    test_result = FlextLdapConfig.create_test_ldap_config()
    if test_result.is_success:
        test_config = test_result.value
        formatters.display_message("Test Configuration:", "info")
        formatters.display_message(f"  Environment: {test_config.environment}", "info")
        formatters.display_message(
            f"  Test mode: {test_config.ldap_enable_test_mode}", "info"
        )
        formatters.display_message(f"  Bind DN: {test_config.ldap_bind_dn}", "info")
        formatters.display_message(f"  SSL enabled: {test_config.ldap_use_ssl}", "info")
        formatters.display_message("", "info")

    # Production configuration
    prod_result = FlextLdapConfig.create_production_ldap_config()
    if prod_result.is_success:
        prod_config = prod_result.value
        formatters.display_message("Production Configuration:", "info")
        formatters.display_message(f"  Environment: {prod_config.environment}", "info")
        formatters.display_message(f"  Debug mode: {prod_config.debug}", "info")
        formatters.display_message(f"  SSL enabled: {prod_config.ldap_use_ssl}", "info")
        formatters.display_message(
            f"  Certificate verification: {prod_config.ldap_verify_certificates}",
            "info",
        )
        formatters.display_message(
            f"  Caching enabled: {prod_config.ldap_enable_caching}", "info"
        )
        formatters.display_message(f"  Cache TTL: {prod_config.ldap_cache_ttl}", "info")
        formatters.display_message("", "info")

    formatters.display_message("✅ Factory methods working correctly\n", "info")


def demonstrate_parameter_overrides() -> None:
    """Demonstrate parameter overrides to change behavior."""
    formatters = FlextCliFormatters()
    formatters.display_message("=== Parameter Overrides Demo ===", "info")

    # Get default configuration using proper FLEXT pattern
    config = FlextLdapConfig.get_global_instance()
    formatters.display_message("Default Configuration:", "info")
    formatters.display_message(f"  Size limit: {config.ldap_size_limit}", "info")
    formatters.display_message(f"  Time limit: {config.ldap_time_limit}", "info")
    formatters.display_message(f"  Caching: {config.ldap_enable_caching}", "info")
    formatters.display_message(f"  Query logging: {config.ldap_log_queries}", "info")
    formatters.display_message("", "info")

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
        formatters.display_message("After Overrides:", "info")
        formatters.display_message(f"  Size limit: {config.ldap_size_limit}", "info")
        formatters.display_message(f"  Time limit: {config.ldap_time_limit}", "info")
        formatters.display_message(f"  Caching: {config.ldap_enable_caching}", "info")
        formatters.display_message(f"  Cache TTL: {config.ldap_cache_ttl}", "info")
        formatters.display_message(
            f"  Query logging: {config.ldap_log_queries}", "info"
        )
        formatters.display_message(
            f"  Response logging: {config.ldap_log_responses}", "info"
        )
        formatters.display_message("", "info")

        # Show how overrides affect different configuration sections
        search_config = config.get_ldap_search_config()
        perf_config = config.get_ldap_performance_config()
        logging_config = config.get_ldap_logging_config()

        formatters.display_message("Configuration Sections:", "info")
        formatters.display_message(f"  Search: {search_config}", "info")
        formatters.display_message(f"  Performance: {perf_config}", "info")
        formatters.display_message(f"  Logging: {logging_config}", "info")
        formatters.display_message("", "info")

    else:
        formatters.display_message(f"❌ Override failed: {result.error}", "info")

    formatters.display_message("✅ Parameter overrides working correctly\n", "info")


def demonstrate_direct_singleton_usage() -> None:
    """Demonstrate direct FlextLdapConfig singleton usage (recommended approach)."""
    formatters = FlextCliFormatters()
    formatters.display_message(
        "=== Direct FlextLdapConfig Singleton Usage Demo ===", "info"
    )

    # Create a custom configuration using type: ignore for Pydantic model limitations
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

    formatters.display_message("Direct Singleton Usage:", "info")
    formatters.display_message(
        f"  Config references singleton: {config is custom_config}", "info"
    )
    formatters.display_message(f"  Bind DN from config: {config.ldap_bind_dn}", "info")
    formatters.display_message(f"  SSL from config: {config.ldap_use_ssl}", "info")
    formatters.display_message(
        f"  Size limit from config: {config.ldap_size_limit}", "info"
    )
    formatters.display_message("", "info")

    # Test effective configuration methods
    effective_conn = config.get_effective_connection()
    auth_config = config.get_effective_auth_config()

    formatters.display_message("Effective Configuration:", "info")
    if effective_conn:
        formatters.display_message(
            f"  Connection server: {effective_conn.get('server', 'N/A')}", "info"
        )
        formatters.display_message(
            f"  Connection port: {effective_conn.get('port', 'N/A')}", "info"
        )
    if auth_config:
        formatters.display_message(f"  Auth bind DN: {auth_config['bind_dn']}", "info")
        formatters.display_message(f"  Auth use SSL: {auth_config['use_ssl']}", "info")
    formatters.display_message("", "info")

    formatters.display_message("✅ Settings delegation working correctly\n", "info")


def demonstrate_runtime_behavior_changes() -> None:
    """Demonstrate how parameter changes affect runtime behavior."""
    formatters = FlextCliFormatters()
    formatters.display_message("=== Runtime Behavior Changes Demo ===", "info")

    # Start with development configuration
    dev_result = FlextLdapConfig.create_development_ldap_config()
    if not dev_result.is_success:
        error_msg = f"Failed to create development config: {dev_result.error}"
        raise RuntimeError(error_msg)
    dev_config = dev_result.value

    # Set as global singleton using proper FLEXT pattern
    FlextLdapConfig.set_global_instance(dev_config)

    formatters.display_message("Initial Development Configuration:", "info")
    formatters.display_message(f"  Debug mode: {dev_config.debug}", "info")
    formatters.display_message(
        f"  Query logging: {dev_config.ldap_log_queries}", "info"
    )
    formatters.display_message(f"  Caching: {dev_config.ldap_enable_caching}", "info")
    formatters.display_message("", "info")

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
        formatters.display_message("After Production Overrides:", "info")
        formatters.display_message(f"  Debug mode: {dev_config.debug}", "info")
        formatters.display_message(f"  Log level: {dev_config.log_level}", "info")
        formatters.display_message(
            f"  Query logging: {dev_config.ldap_log_queries}", "info"
        )
        formatters.display_message(
            f"  Response logging: {dev_config.ldap_log_responses}", "info"
        )
        formatters.display_message(
            f"  Caching: {dev_config.ldap_enable_caching}", "info"
        )
        formatters.display_message(f"  Cache TTL: {dev_config.ldap_cache_ttl}", "info")
        formatters.display_message(
            f"  Size limit: {dev_config.ldap_size_limit}", "info"
        )
        formatters.display_message(
            f"  Time limit: {dev_config.ldap_time_limit}", "info"
        )
        formatters.display_message("", "info")

        # Show how this affects different aspects of the system
        formatters.display_message("System Behavior Changes:", "info")
        formatters.display_message(
            f"  Search performance: {dev_config.get_ldap_search_config()}", "info"
        )
        formatters.display_message(
            f"  Caching behavior: {dev_config.get_ldap_performance_config()}", "info"
        )
        formatters.display_message(
            f"  Logging behavior: {dev_config.get_ldap_logging_config()}", "info"
        )
        formatters.display_message("", "info")

    formatters.display_message(
        "✅ Runtime behavior changes working correctly\n", "info"
    )


def main() -> None:
    """Run all demonstrations."""
    formatters = FlextCliFormatters()
    formatters.display_message("FlextLdapConfig Singleton Usage Examples", "info")
    formatters.display_message("=" * 50, "info")
    formatters.display_message("", "info")

    try:
        demonstrate_singleton_pattern()
        demonstrate_environment_loading()
        demonstrate_factory_methods()
        demonstrate_parameter_overrides()
        demonstrate_direct_singleton_usage()
        demonstrate_runtime_behavior_changes()

        formatters.display_message(
            "🎉 All demonstrations completed successfully!", "info"
        )
        formatters.display_message("\nKey Benefits:", "info")
        formatters.display_message(
            "✅ Single source of truth for LDAP configuration", "info"
        )
        formatters.display_message("✅ Environment variable integration", "info")
        formatters.display_message(
            "✅ Factory methods for different environments", "info"
        )
        formatters.display_message("✅ Runtime parameter overrides", "info")
        formatters.display_message("✅ Clean Architecture with delegation", "info")
        formatters.display_message("✅ Type-safe configuration management", "info")

    except Exception as e:
        formatters.display_message(f"❌ Error during demonstration: {e}", "info")
        traceback.print_exc()


if __name__ == "__main__":
    main()
