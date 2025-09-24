#!/usr/bin/env python3
"""FLEXT Integrated LDAP Example - Proper FLEXT Patterns Implementation.

This example demonstrates the proper integration of universal LDAP compatibility
following FLEXT architectural patterns:

1. Single schema class (FlextLdapSchema) with subclasses
2. Models declared in FlextLdapModels class
3. Types used from FlextLdapTypes class
4. Constants from FlextLdapConstants class
5. Clean Architecture with proper domain separation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio
import os

from flext_core import FlextLogger
from flext_ldap import (
    FlextLdapClient,
    FlextLdapConstants,
    FlextLdapModels,
    FlextLdapSchema,
    FlextLdapTypes,
)


async def demonstrate_flext_integrated_ldap() -> None:
    """Demonstrate FLEXT-integrated LDAP client with universal compatibility."""
    logger = FlextLogger(__name__)

    # Configuration - works with any LDAP server
    server_uri = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
    bind_password = os.getenv("LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD")

    logger.info("Starting FLEXT Integrated LDAP demonstration")
    logger.info("Server URI: %s", server_uri)
    logger.info("Bind DN: %s", bind_dn)

    # Create FLEXT LDAP client (using actual client.py)
    client = FlextLdapClient()

    try:
        # Connect using FLEXT patterns
        logger.info("Connecting to LDAP server...")
        connect_result = await client.connect(server_uri, bind_dn, bind_password)

        if connect_result.is_failure:
            logger.error("Failed to connect: %s", connect_result.error)
            return

        logger.info("Successfully connected to LDAP server")

        # Demonstrate schema discovery using FLEXT patterns
        await demonstrate_schema_discovery(client, logger)

        # Demonstrate universal operations
        await demonstrate_universal_operations(client, logger)

        # Demonstrate FLEXT model usage
        demonstrate_flext_models(client, logger)

    except Exception:
        logger.exception("Error during demonstration")

    finally:
        # Disconnect using FLEXT patterns
        if client.is_connected():
            await client.unbind()
            logger.info("Disconnected from LDAP server")


async def demonstrate_schema_discovery(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate schema discovery using FLEXT patterns."""
    logger.info("\n=== FLEXT Schema Discovery ===")

    # Use FLEXT schema discovery
    discovery_result = await client.discover_schema()

    if discovery_result.is_success:
        schema_data = discovery_result.data

        # Access schema data using FLEXT models
        logger.info("Schema Discovery Results:")
        logger.info("  Server Type: %s", schema_data.server_type.value)
        logger.info(
            "  Server Info: %s", schema_data.server_info.get("vendorName", "Unknown")
        )
        logger.info("  Naming Contexts: %s", schema_data.naming_contexts)
        logger.info("  Supported Controls: %s", len(schema_data.supported_controls))
        logger.info("  Discovered Attributes: %s", len(schema_data.attributes))
        logger.info("  Discovered Object Classes: %s", len(schema_data.object_classes))

        # Demonstrate server quirks using FLEXT models
        quirks = schema_data.server_quirks
        logger.info("Server Quirks:")
        logger.info("  Case Sensitive DNs: %s", quirks.case_sensitive_dns)
        logger.info("  Case Sensitive Attributes: %s", quirks.case_sensitive_attributes)
        logger.info("  Supports Paged Results: %s", quirks.supports_paged_results)
        logger.info("  Supports VLV: %s", quirks.supports_vlv)
        logger.info("  Max Page Size: %s", quirks.max_page_size)

        # Demonstrate normalization using FLEXT patterns
        logger.info("Normalization Examples:")
        test_attr = client.normalize_attribute_name("objectClass")
        test_oc = client.normalize_object_class("person")
        test_dn = client.normalize_dn("cn=TestUser,dc=Example,dc=Com")
        logger.info("  objectClass → %s", test_attr)
        logger.info("  person → %s", test_oc)
        logger.info("  cn=TestUser,dc=Example,dc=Com → %s", test_dn)

    else:
        logger.error("Schema discovery failed: %s", discovery_result.error)


async def demonstrate_universal_operations(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate universal LDAP operations using FLEXT patterns."""
    logger.info("\n=== Universal LDAP Operations ===")

    # Get server information using FLEXT patterns
    server_info = client.get_server_info()
    if not server_info or not server_info.get("namingContexts"):
        logger.warning("No naming contexts available for operations")
        return

    base_dn = server_info["namingContexts"][0]
    logger.info("Using search base: %s", base_dn)

    # Create FLEXT models for search
    search_filter = FlextLdapModels.Filter.equals("objectClass", "person")
    search_scope = FlextLdapModels.Scope.subtree()

    logger.info("Search Filter: %s", search_filter.expression)
    logger.info("Search Scope: %s", search_scope.value)

    # Perform search using FLEXT patterns
    search_result = await client.search(
        base_dn=base_dn,
        search_filter=search_filter.expression,
        attributes=["cn", "sn", "mail", "objectClass"],
        scope=search_scope.value,
        size_limit=10,
    )

    if search_result.is_success:
        logger.info("Found %d entries", len(search_result.data))
        for i, entry in enumerate(search_result.data[:3]):  # Show first 3
            logger.info("  Entry %d: %s", i + 1, entry.get("dn", "No DN"))
            attrs = entry.get("attributes", {})
            if "cn" in attrs:
                logger.info("    CN: %s", attrs["cn"])
            if "objectClass" in attrs:
                logger.info("    Object Classes: %s", attrs["objectClass"])
    else:
        logger.error("Search failed: %s", search_result.error)


def demonstrate_flext_models(
    client: FlextLdapClient, logger: FlextLogger  # noqa: ARG001
) -> None:
    """Demonstrate FLEXT model usage."""
    logger.info("\n=== FLEXT Model Usage ===")

    # Demonstrate FLEXT value objects
    logger.info("FLEXT Value Objects:")

    # Distinguished Name
    dn_result = FlextLdapModels.DistinguishedName.create(
        "cn=testuser,dc=example,dc=com"
    )
    if dn_result.is_success:
        dn_obj = dn_result.data
        logger.info("  DN: %s", dn_obj.value)
        logger.info("  RDN: %s", dn_obj.rdn)

    # LDAP Filter
    filter_obj = FlextLdapModels.Filter.equals("cn", "testuser")
    logger.info("  Filter: %s", filter_obj.expression)

    # Search Scope
    scope_obj = FlextLdapModels.Scope.subtree()
    logger.info("  Scope: %s", scope_obj.value)

    # Demonstrate FLEXT constants
    logger.info("FLEXT Constants:")
    logger.info("  Default LDAP Port: %s", FlextLdapConstants.Protocol.DEFAULT_PORT)
    logger.info("  Default SSL Port: %s", FlextLdapConstants.Protocol.DEFAULT_SSL_PORT)
    logger.info("  LDAP Protocol: %s", FlextLdapConstants.Protocol.LDAP)
    logger.info("  LDAPS Protocol: %s", FlextLdapConstants.Protocol.LDAPS)
    logger.info("  Valid Scopes: %s", FlextLdapConstants.Scopes.VALID_SCOPES)

    # Demonstrate FLEXT types
    logger.info("FLEXT Types:")
    logger.info("  Entry Attribute Value: %s", FlextLdapTypes.EntryAttributeValue)
    logger.info("  Entry Attribute Dict: %s", FlextLdapTypes.EntryAttributeDict)
    logger.info("  Search Result: %s", FlextLdapTypes.SearchResult)
    logger.info("  Connection Server URI: %s", FlextLdapTypes.ConnectionServerURI)


def demonstrate_server_type_adaptations() -> None:
    """Demonstrate how FLEXT adapts to different server types."""
    logger = FlextLogger(__name__)

    logger.info("\n=== FLEXT Server Type Adaptations ===")

    # Demonstrate FLEXT server type enum
    logger.info("FLEXT Server Types:")
    for server_type in FlextLdapModels.LdapServerType:
        logger.info("  %s: %s", server_type.name, server_type.value)

    # Demonstrate FLEXT quirks detection
    logger.info("\nFLEXT Quirks Detection:")

    # Create FLEXT quirks detector
    detector = FlextLdapSchema.GenericQuirksDetector()

    # Test server detection
    test_servers = [
        {"vendorName": "OpenLDAP", "description": "OpenLDAP slapd 2.4.57"},
        {"vendorName": "Microsoft", "description": "Active Directory Domain Services"},
        {"vendorName": "Oracle", "description": "Oracle Directory Server"},
        {"vendorName": "Unknown", "description": "Generic LDAP Server"},
    ]

    for server_info in test_servers:
        server_type = detector.detect_server_type(server_info)
        quirks = detector.get_server_quirks(server_type)

        logger.info("  %s:", server_info["vendorName"])
        logger.info("    Detected Type: %s", server_type.value)
        logger.info("    Case Sensitive DNs: %s", quirks.case_sensitive_dns)
        logger.info(
            "    Case Sensitive Attributes: %s", quirks.case_sensitive_attributes
        )
        logger.info("    Supports Paged Results: %s", quirks.supports_paged_results)
        logger.info("    Supports VLV: %s", quirks.supports_vlv)


if __name__ == "__main__":
    """Run the FLEXT integrated LDAP demonstration."""
    print("FLEXT Integrated LDAP - Proper FLEXT Patterns Implementation")
    print("=" * 70)
    print()
    print("This example demonstrates proper FLEXT integration:")
    print("1. Single schema class (FlextLdapSchema) with subclasses")
    print("2. Models declared in FlextLdapModels class")
    print("3. Types used from FlextLdapTypes class")
    print("4. Constants from FlextLdapConstants class")
    print("5. Clean Architecture with proper domain separation")
    print()
    print("Environment Variables:")
    print("  LDAP_SERVER_URI - LDAP server URI (default: ldap://localhost:389)")
    print("  LDAP_BIND_DN - Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)")
    print("  LDAP_BIND_PASSWORD - Bind password (default: REDACTED_LDAP_BIND_PASSWORD)")
    print()

    # Run the demonstration
    asyncio.run(demonstrate_flext_integrated_ldap())

    # Show server type adaptations
    asyncio.run(demonstrate_server_type_adaptations())

    print("\nFLEXT Integration demonstration completed!")
    print("All components follow proper FLEXT architectural patterns.")
