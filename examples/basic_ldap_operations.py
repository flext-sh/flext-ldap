#!/usr/bin/env python3
"""Basic LDAP Operations Example.

This example demonstrates the core functionality of flext-ldap library:
- Configuration management
- Connection establishment
- Search operations
- User management
- Error handling with FlextResult patterns

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os

from flext_core import FlextLogger
from flext_ldap import (
    FlextLdapApi,
    FlextLdapConfigs,
    FlextLdapModels,
)

logger = FlextLogger(__name__)


def demonstrate_configuration() -> None:
    """Demonstrate configuration management."""
    # 1. Settings configuration using FlextLdapConfigs
    FlextLdapConfigs()

    # 2. Connection info - will be passed to API methods

    # 3. Configuration is automatically validated - no separate call needed
    logger.info("Configuration initialized successfully")


async def demonstrate_api_usage() -> FlextLdapApi:
    """Demonstrate API usage patterns."""
    # 1. Initialize API using factory function
    # Use explicit factory create() to avoid object-return typing for some loaders
    api = FlextLdapApi.create()

    # 2. Connect (using demo server for example)
    try:
        connection_result = await api.connect(
            server_uri=os.getenv("LDAP_SERVER_URI", "ldap://demo.example.com:389"),
            bind_dn=os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"),
            bind_password=os.getenv("LDAP_BIND_PASSWORD") or "",
        )

        if connection_result.is_success:
            logger.info(f"Connected with session: {connection_result.value}")
        else:
            logger.debug(f"Connection failed: {connection_result.error}")

    except Exception as e:
        # Continue demo with available operations
        logger.debug(f"Connection failed in demo: {e}")

    return api


async def demonstrate_search_operations(api: FlextLdapApi) -> None:
    """Demonstrate search operations."""
    # Session ID for demonstration

    try:
        # 1. Basic search using correct API
        search_result = await api.search_simple(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "mail", "uid"],
            scope="subtree",
        )

        if search_result.is_success:
            entries = search_result.value or []
            logger.info(f"Found {len(entries)} entries")

            for entry in entries[:3]:  # Show first 3 entries
                logger.debug(f"Entry DN: {entry.dn}")

    except Exception as e:
        # Continue demo with available operations
        logger.debug(f"Search operation failed in demo: {e}")


async def demonstrate_error_handling() -> None:
    """Demonstrate FlextResult error handling patterns."""
    # 1. DN validation errors
    dn_result = FlextLdapModels.ValueObjects.DistinguishedName.create("")
    if not dn_result.is_success:
        pass

    # 2. Filter validation errors
    filter_result = FlextLdapModels.ValueObjects.Filter.create("invalid-filter-format")
    if not filter_result.is_success:
        pass

    # 3. Connection errors (simulated)
    api = FlextLdapApi()
    try:
        test_password = os.getenv(
            "LDAP_TEST_PASSWORD", "demo_password_not_for_production",
        )
        connection_result = await api.connect(
            server_uri="ldap://nonexistent.server:389",
            bind_dn="cn=test",
            bind_password=test_password,
        )

        if not connection_result.is_success:
            pass

    except Exception as e:
        # Continue demo with available operations
        logger.debug(f"Connection test failed in demo: {e}")


def demonstrate_logging_integration() -> None:
    """Demonstrate logging integration with flext-core."""
    # Enable TRACE logging for this demo
    os.environ["FLEXT_LOG_LEVEL"] = "DEBUG"

    logger.info("Starting logging demonstration")

    # Create settings with logging
    logger.debug("Creating LDAP settings")
    settings = FlextLdapConfigs()

    # Use the public field name defined in FlextLdapConfigs
    logger.debug(
        "Settings created successfully",
        extra={"debug_enabled": settings.ldap_enable_debug},
    )

    # Test validation with logging
    logger.debug("Testing settings validation")
    result = settings.validate_business_rules()

    if result.is_success:
        logger.info("Settings validation passed")
    else:
        logger.error("Configuration validation failed", extra={"error": result.error})


async def main() -> None:
    """Run the main demonstration function."""
    try:
        # 1. Configuration management
        demonstrate_configuration()

        # 2. API usage
        api = await demonstrate_api_usage()

        # 3. Search operations
        await demonstrate_search_operations(api)

        # 4. Error handling
        await demonstrate_error_handling()

        # 5. Logging integration
        demonstrate_logging_integration()

    except Exception:
        logger.exception("Demonstration failed with exception")
        raise


if __name__ == "__main__":
    asyncio.run(main())
