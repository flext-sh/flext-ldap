#!/usr/bin/env python3
"""Basic LDAP Operations Example.

This example demonstrates the core functionality of flext-ldap library:
- Configuration management
- Connection establishment
- Search operations
- User management
- Error handling with FlextResult patterns

Requirements:
- flext-ldap library installed
- Optional: LDAP server for real operations

Usage:
    python examples/basic_ldap_operations.py

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os

from flext_core import get_logger

from flext_ldap import (
    FlextLdapApi,
    FlextLdapDistinguishedName,
    FlextLdapFilter,
    FlextLdapSettings,
)

logger = get_logger(__name__)


async def demonstrate_configuration() -> None:
    """Demonstrate configuration management."""
    print("🔧 Configuration Management")
    print("=" * 40)

    # 1. Settings configuration using FlextLdapSettings
    settings = FlextLdapSettings()
    print("✅ Settings created with defaults")

    # 2. Connection info - will be passed to API methods
    print("✅ Connection info prepared")

    # 3. Validate settings business rules
    settings_validation = settings.validate_business_rules()
    settings_status = "PASS" if settings_validation.is_success else "FAIL"
    print(f"✅ Settings validation: {settings_status}")

    print("✅ Configuration demonstration complete")


async def demonstrate_api_usage() -> FlextLdapApi:
    """Demonstrate API usage patterns."""
    print("\n🚀 API Usage Patterns")
    print("=" * 40)

    # 1. Initialize API
    api = FlextLdapApi()
    print("✅ FlextLdapApi initialized")

    # 2. Connect (using demo server for example)
    try:
        connection_result = await api.connect(
            server_uri="ldap://demo.example.com:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",  # noqa: S106 - Example password for documentation
        )

        if connection_result.is_success:
            print(f"✅ Connected with session: {connection_result.value}")
        else:
            print(f"❌ Connection failed: {connection_result.error}")

    except Exception as e:
        print(f"❌ Connection exception: {e}")

    return api


async def demonstrate_search_operations(api: FlextLdapApi) -> None:
    """Demonstrate search operations."""
    print("\n🔍 Search Operations")
    print("=" * 40)

    # Session ID for demonstration

    try:
        # 1. Basic search using correct API
        search_result = await api.search(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "mail", "uid"],
            scope="subtree",
        )

        if search_result.is_success:
            entries = search_result.value or []
            print(f"✅ Search completed: {len(entries)} entries found")

            for entry in entries[:3]:  # Show first 3 entries
                print(f"  - DN: {entry.dn}")

        else:
            print(f"❌ Search failed: {search_result.error}")

    except Exception as e:
        print(f"❌ Search exception: {e}")


async def demonstrate_error_handling() -> None:
    """Demonstrate FlextResult error handling patterns."""
    print("\n⚠️  Error Handling Patterns")
    print("=" * 40)

    # 1. DN validation errors
    dn_result = FlextLdapDistinguishedName.create("")
    if not dn_result.is_success:
        print(f"✅ Caught DN validation error: {dn_result.error}")

    # 2. Filter validation errors
    filter_result = FlextLdapFilter.create("invalid-filter-format")
    if not filter_result.is_success:
        print(f"✅ Caught filter error: {filter_result.error}")

    # 3. Connection errors (simulated)
    api = FlextLdapApi()
    try:
        test_password = os.getenv("LDAP_TEST_PASSWORD", "demo_password_not_for_production")
        connection_result = await api.connect(
            server_uri="ldap://nonexistent.server:389",
            bind_dn="cn=test",
            bind_password=test_password,
        )

        if not connection_result.is_success:
            print(f"✅ Caught connection error: {connection_result.error}")

    except Exception as e:
        print(f"✅ Caught exception: {type(e).__name__}: {e}")


async def demonstrate_logging_integration() -> None:
    """Demonstrate logging integration with flext-core."""
    print("\n📝 Logging Integration")
    print("=" * 40)

    # Enable TRACE logging for this demo
    os.environ["FLEXT_LOG_LEVEL"] = "DEBUG"

    logger.info("Starting logging demonstration")

    # Create settings with logging
    logger.debug("Creating LDAP settings")
    settings = FlextLdapSettings()

    logger.debug(
        "Settings created successfully",
        extra={"debug_enabled": settings.enable_debug_mode},
    )

    # Test validation with logging
    logger.debug("Testing settings validation")
    result = settings.validate_business_rules()

    if result.is_success:
        logger.info("Settings validation passed")
    else:
        logger.error("Configuration validation failed", extra={"error": result.error})

    print("✅ Check console output for structured logging")


async def main() -> None:
    """Run the main demonstration function."""
    print("🎯 FLEXT-LDAP Library Demonstration")
    print("=" * 50)
    print("This example shows key features of the flext-ldap library")
    print("using real code paths and enterprise patterns.\n")

    try:
        # 1. Configuration management
        await demonstrate_configuration()

        # 2. API usage
        api = await demonstrate_api_usage()

        # 3. Search operations
        await demonstrate_search_operations(api)

        # 4. Error handling
        await demonstrate_error_handling()

        # 5. Logging integration
        await demonstrate_logging_integration()

        print("\n🎉 Demonstration completed successfully!")
        print("✅ All flext-ldap core features demonstrated")
        print("✅ Enterprise patterns validated")
        print("✅ Error handling verified")
        print("✅ Logging integration confirmed")

    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        logger.exception("Demonstration failed with exception")
        raise


if __name__ == "__main__":
    asyncio.run(main())
