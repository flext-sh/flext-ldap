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
    # 1. Settings configuration using FlextLdapSettings
    settings = FlextLdapSettings()

    # 2. Connection info - will be passed to API methods

    # 3. Validate settings business rules
    settings.validate_business_rules()


async def demonstrate_api_usage() -> FlextLdapApi:
    """Demonstrate API usage patterns."""
    # 1. Initialize API
    api = FlextLdapApi()

    # 2. Connect (using demo server for example)
    try:
        connection_result = await api.connect(
            server_uri="ldap://demo.example.com:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
        )

        if connection_result.is_success:
            pass

    except Exception:
        # Continue demo with available operations
        pass

    return api


async def demonstrate_search_operations(api: FlextLdapApi) -> None:
    """Demonstrate search operations."""
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

            for _entry in entries[:3]:  # Show first 3 entries
                pass

    except Exception:
        # Continue demo with available operations
        pass


async def demonstrate_error_handling() -> None:
    """Demonstrate FlextResult error handling patterns."""
    # 1. DN validation errors
    dn_result = FlextLdapDistinguishedName.create("")
    if not dn_result.is_success:
        pass

    # 2. Filter validation errors
    filter_result = FlextLdapFilter.create("invalid-filter-format")
    if not filter_result.is_success:
        pass

    # 3. Connection errors (simulated)
    api = FlextLdapApi()
    try:
        test_password = os.getenv(
            "LDAP_TEST_PASSWORD", "demo_password_not_for_production"
        )
        connection_result = await api.connect(
            server_uri="ldap://nonexistent.server:389",
            bind_dn="cn=test",
            bind_password=test_password,
        )

        if not connection_result.is_success:
            pass

    except Exception:
        # Continue demo with available operations
        pass


async def demonstrate_logging_integration() -> None:
    """Demonstrate logging integration with flext-core."""
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


async def main() -> None:
    """Run the main demonstration function."""
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

    except Exception:
        logger.exception("Demonstration failed with exception")
        raise


if __name__ == "__main__":
    asyncio.run(main())
