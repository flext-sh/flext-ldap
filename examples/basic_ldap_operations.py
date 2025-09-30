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

from flext_core import FlextLogger, FlextResult
from flext_ldap import (
    FlextLdapClient,
    FlextLdapConfig,
    FlextLdapModels,
)

logger = FlextLogger(__name__)


def demonstrate_configuration() -> None:
    """Demonstrate configuration management."""
    # 1. Settings configuration using FlextLdapConfig
    FlextLdapConfig()

    # 2. Connection info - will be passed to API methods

    # 3. Configuration is automatically validated - no separate call needed
    logger.info("Configuration initialized successfully")


async def demonstrate_api_usage() -> FlextLdapClient:
    """Demonstrate API usage patterns.

    Returns:
        FlextLdapClient: The initialized LDAP API instance.

    """
    # 1. Initialize API using direct instantiation
    api = FlextLdapClient()

    # 2. Connect (using demo server for example)
    try:
        connection_result: FlextResult[bool] = await api.connect(
            server_uri=os.getenv("LDAP_SERVER_URI", "ldap://demo.example.com:389"),
            bind_dn=os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com"),
            password=os.getenv("LDAP_BIND_PASSWORD") or "",
        )

        if connection_result.is_success:
            logger.info(f"Connected with session: {connection_result.value}")
        else:
            logger.debug(f"Connection failed: {connection_result.error}")

    except Exception as e:
        # Continue demo with available operations
        logger.debug(f"Connection failed in demo: {e}")

    return api


async def demonstrate_search_operations(api: FlextLdapClient) -> None:
    """Demonstrate search operations."""
    # Session ID for demonstration

    try:
        # 1. Basic search using correct API
        search_result: FlextResult[list[FlextLdapModels.Entry]] = await api.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            attributes=["cn", "mail", "uid"],
        )

        if search_result.is_success:
            entries: list[FlextLdapModels.Entry] = search_result.value or []
            logger.info(f"Found {len(entries)} entries")

            for entry in entries[:3]:  # Show first 3 entries
                logger.debug(f"Entry: {entry}")

    except Exception as e:
        # Continue demo with available operations
        logger.debug(f"Search operation failed in demo: {e}")


async def demonstrate_error_handling() -> None:
    """Demonstrate FlextResult error handling patterns."""
    # 1. DN validation errors
    dn_result = FlextLdapModels.DistinguishedName.create("")
    if not dn_result.is_success:
        pass

    # 2. Filter validation errors
    filter_result: FlextLdapModels.Filter = FlextLdapModels.Filter.equals(
        "objectClass", "invalid-filter-format"
    )
    logger.debug(f"Created filter: {filter_result.expression}")

    # 3. Connection errors (simulated)
    api = FlextLdapClient()
    try:
        test_password = os.getenv(
            "LDAP_TEST_PASSWORD",
            "demo_password_not_for_production",
        )
        connection_result: FlextResult[bool] = await api.connect(
            server_uri="ldap://nonexistent.server:389",
            bind_dn="cn=test",
            password=test_password,
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
    settings = FlextLdapConfig()

    # Use the public field name defined in FlextLdapConfig
    logger.debug(
        "Settings created successfully",
        extra={"debug_enabled": settings.ldap_enable_debug},
    )

    # Test validation with logging
    logger.debug("Testing settings validation")
    try:
        # Configuration validation happens automatically during instantiation
        # Test by accessing configuration properties
        connection_config = settings.get_connection_config()
        logger.info(
            "Settings validation passed - connection config: %s", connection_config
        )
    except Exception:
        logger.exception("Settings validation failed")


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
