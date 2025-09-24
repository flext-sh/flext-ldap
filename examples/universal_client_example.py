#!/usr/bin/env python3
"""Universal LDAP Client Example - Complete Generic Capabilities.

This example demonstrates the complete universal LDAP client capabilities
that can handle ANY LDAP server in ANY form:

1. Automatic server detection and adaptation
2. Universal search operations with all parameters
3. Universal CRUD operations (Create, Read, Update, Delete)
4. Universal compare and extended operations
5. Complete server quirks handling
6. Automatic schema discovery and normalization

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio
import os

from flext_core import FlextLogger
from flext_ldap import (
    FlextLdapClient,
    FlextLdapSchema,
)


async def demonstrate_universal_client() -> None:
    """Demonstrate complete universal LDAP client capabilities."""
    logger = FlextLogger(__name__)

    # Configuration - works with ANY LDAP server
    server_uri = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
    bind_password = os.getenv("LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD")

    logger.info("Starting Universal LDAP Client Demonstration")
    logger.info("Server URI: %s", server_uri)
    logger.info("Bind DN: %s", bind_dn)

    # Create universal FLEXT LDAP client
    client = FlextLdapClient()

    try:
        # Connect with automatic schema discovery
        logger.info("Connecting with automatic schema discovery...")
        connect_result = await client.connect(
            server_uri=server_uri,
            bind_dn=bind_dn,
            password=bind_password,
            auto_discover_schema=True,
            connection_options={
                "timeout": 30,
                "use_ssl": False,
                "auto_referrals": True,
            },
        )

        if connect_result.is_failure:
            logger.error("Failed to connect: %s", connect_result.error)
            return

        logger.info("Successfully connected to LDAP server")

        # Demonstrate server capabilities
        demonstrate_server_capabilities(client, logger)

        # Demonstrate universal search operations
        await demonstrate_universal_search(client, logger)

        # Demonstrate universal CRUD operations
        await demonstrate_universal_crud(client, logger)

        # Demonstrate universal compare operations
        await demonstrate_universal_compare(client, logger)

        # Demonstrate universal extended operations
        await demonstrate_universal_extended(client, logger)

        # Demonstrate server-specific adaptations
        demonstrate_server_adaptations(client, logger)

    except Exception:
        logger.exception("Error during demonstration")

    finally:
        # Disconnect
        if client.is_connected():
            await client.unbind()
            logger.info("Disconnected from LDAP server")


def demonstrate_server_capabilities(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate server capabilities detection."""
    logger.info("\n=== Server Capabilities Detection ===")

    # Get comprehensive server capabilities
    capabilities = client.get_server_capabilities()

    logger.info("Server Capabilities:")
    logger.info("  Connected: %s", capabilities["connected"])
    logger.info("  Schema Discovered: %s", capabilities["schema_discovered"])

    if capabilities["server_info"]:
        server_info = capabilities["server_info"]
        logger.info("  Vendor: %s", server_info.get("vendorName", "Unknown"))
        logger.info("  Description: %s", server_info.get("description", "Unknown"))
        logger.info(
            "  LDAP Version: %s", server_info.get("supportedLDAPVersion", "Unknown")
        )

    if capabilities["server_type"]:
        logger.info("  Server Type: %s", capabilities["server_type"].value)

    if capabilities["server_quirks"]:
        quirks = capabilities["server_quirks"]
        logger.info("  Server Quirks:")
        logger.info("    Case Sensitive DNs: %s", quirks.case_sensitive_dns)
        logger.info(
            "    Case Sensitive Attributes: %s", quirks.case_sensitive_attributes
        )
        logger.info("    Supports Paged Results: %s", quirks.supports_paged_results)
        logger.info("    Supports VLV: %s", quirks.supports_vlv)
        logger.info("    Supports Sync: %s", quirks.supports_sync)
        logger.info("    Max Page Size: %s", quirks.max_page_size)
        logger.info("    Default Timeout: %s", quirks.default_timeout)

    if "naming_contexts" in capabilities:
        logger.info("  Naming Contexts: %s", capabilities["naming_contexts"])

    if "supported_controls" in capabilities:
        logger.info("  Supported Controls: %d", len(capabilities["supported_controls"]))

    if "supported_extensions" in capabilities:
        logger.info(
            "  Supported Extensions: %d", len(capabilities["supported_extensions"])
        )

    if "discovered_attributes" in capabilities:
        logger.info(
            "  Discovered Attributes: %d", capabilities["discovered_attributes"]
        )

    if "discovered_object_classes" in capabilities:
        logger.info(
            "  Discovered Object Classes: %d", capabilities["discovered_object_classes"]
        )


async def demonstrate_universal_search(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate universal search operations."""
    logger.info("\n=== Universal Search Operations ===")

    # Get server info for base DN
    server_info = client.get_server_info()
    if not server_info or not server_info.get("naming_contexts"):
        logger.warning("No naming contexts available for search operations")
        return

    base_dn = server_info["naming_contexts"][0]
    logger.info("Using search base: %s", base_dn)

    # Universal search with all parameters
    logger.info("Performing universal search...")
    search_result = await client.search_universal(
        base_dn=base_dn,
        search_filter="(objectClass=*)",
        attributes=["cn", "sn", "mail", "objectClass"],
        scope="subtree",
        size_limit=10,
        time_limit=30,
        deref_aliases="deref_always",
        types_only=False,
        controls=None,
    )

    if search_result.is_success:
        logger.info(
            "Universal search successful: %d entries found", len(search_result.data)
        )
        for i, entry in enumerate(search_result.data[:3]):  # Show first 3
            logger.info("  Entry %d: %s", i + 1, entry.get("dn", "No DN"))
            if "cn" in entry:
                logger.info("    CN: %s", entry["cn"])
            if "objectClass" in entry:
                logger.info("    Object Classes: %s", entry["objectClass"])
    else:
        logger.error("Universal search failed: %s", search_result.error)

    # Search with controls (if supported)
    logger.info("Performing search with controls...")
    controls_result = await client.search_with_controls_universal(
        base_dn=base_dn,
        search_filter="(objectClass=person)",
        attributes=["cn", "sn"],
        scope="subtree",
        controls=None,  # Could add paged results control here
    )

    if controls_result.is_success:
        logger.info(
            "Search with controls successful: %d entries found",
            len(controls_result.data),
        )
    else:
        logger.error("Search with controls failed: %s", controls_result.error)


async def demonstrate_universal_crud(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate universal CRUD operations."""
    logger.info("\n=== Universal CRUD Operations ===")

    # Get server info for base DN
    server_info = client.get_server_info()
    if not server_info or not server_info.get("naming_contexts"):
        logger.warning("No naming contexts available for CRUD operations")
        return

    base_dn = server_info["naming_contexts"][0]
    test_dn = f"cn=testuser,{base_dn}"

    logger.info("Testing CRUD operations with DN: %s", test_dn)

    # Universal Add Entry
    logger.info("Testing universal add entry...")
    add_attributes = {
        "objectClass": ["person", "inetOrgPerson"],
        "cn": "testuser",
        "sn": "TestUser",
        "mail": "testuser@example.com",
        "description": "Test user for universal operations",
    }

    add_result = await client.add_entry_universal(
        dn=test_dn, attributes=add_attributes, controls=None
    )

    if add_result.is_success:
        logger.info("Universal add entry successful")

        # Universal Modify Entry
        logger.info("Testing universal modify entry...")
        modify_changes = {
            "description": "Modified test user description",
            "mail": "modified@example.com",
        }

        modify_result = await client.modify_entry_universal(
            dn=test_dn, changes=modify_changes, controls=None
        )

        if modify_result.is_success:
            logger.info("Universal modify entry successful")
        else:
            logger.error("Universal modify entry failed: %s", modify_result.error)

        # Universal Delete Entry
        logger.info("Testing universal delete entry...")
        delete_result = await client.delete_entry_universal(dn=test_dn, controls=None)

        if delete_result.is_success:
            logger.info("Universal delete entry successful")
        else:
            logger.error("Universal delete entry failed: %s", delete_result.error)

    else:
        logger.error("Universal add entry failed: %s", add_result.error)


async def demonstrate_universal_compare(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate universal compare operations."""
    logger.info("\n=== Universal Compare Operations ===")

    # Get server info for base DN
    server_info = client.get_server_info()
    if not server_info or not server_info.get("naming_contexts"):
        logger.warning("No naming contexts available for compare operations")
        return

    base_dn = server_info["naming_contexts"][0]
    test_dn = f"cn=REDACTED_LDAP_BIND_PASSWORD,{base_dn}"

    logger.info("Testing universal compare with DN: %s", test_dn)

    # Universal Compare
    compare_result = await client.compare_universal(
        dn=test_dn, attribute="objectClass", value="person"
    )

    if compare_result.is_success:
        logger.info("Universal compare successful: attribute matches")
    else:
        logger.error("Universal compare failed: %s", compare_result.error)


async def demonstrate_universal_extended(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate universal extended operations."""
    logger.info("\n=== Universal Extended Operations ===")

    # Test Who Am I extended operation
    logger.info("Testing Who Am I extended operation...")
    whoami_result = await client.extended_operation_universal(
        request_name="1.3.6.1.4.1.4203.1.11.3",  # Who Am I OID
        request_value=None,
        controls=None,
    )

    if whoami_result.is_success:
        logger.info("Who Am I extended operation successful")
        logger.info("  Response: %s", whoami_result.data)
    else:
        logger.error("Who Am I extended operation failed: %s", whoami_result.error)

    # Test other extended operations if supported
    server_info = client.get_server_info()
    if server_info and "supportedExtensions" in server_info:
        extensions = server_info["supportedExtensions"]
        logger.info("Supported extensions: %d", len(extensions))
        for ext in extensions[:5]:  # Show first 5
            logger.info("  Extension: %s", ext)


def demonstrate_server_adaptations(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate server-specific adaptations."""
    logger.info("\n=== Server-Specific Adaptations ===")

    # Demonstrate normalization
    logger.info("Demonstrating normalization adaptations:")

    test_cases = [
        ("objectClass", "objectclass"),
        ("cn", "CN"),
        ("sn", "SN"),
        ("mail", "MAIL"),
        ("userPrincipalName", "userprincipalname"),
    ]

    for _original, test_case in test_cases:
        normalized = client.normalize_attribute_name(test_case)
        logger.info("  %s → %s", test_case, normalized)

    # Demonstrate DN normalization
    dn_cases = [
        "cn=TestUser,dc=Example,dc=Com",
        "CN=TESTUSER,DC=EXAMPLE,DC=COM",
        "cn=testuser,dc=example,dc=com",
    ]

    logger.info("DN normalization examples:")
    for dn_case in dn_cases:
        normalized = client.normalize_dn(dn_case)
        logger.info("  %s → %s", dn_case, normalized)

    # Demonstrate object class normalization
    oc_cases = [
        "person",
        "PERSON",
        "inetOrgPerson",
        "INETORGPERSON",
    ]

    logger.info("Object class normalization examples:")
    for oc_case in oc_cases:
        normalized = client.normalize_object_class(oc_case)
        logger.info("  %s → %s", oc_case, normalized)


def demonstrate_server_type_detection() -> None:
    """Demonstrate server type detection capabilities."""
    logger = FlextLogger(__name__)

    logger.info("\n=== Server Type Detection ===")

    # Create quirks detector
    detector = FlextLdapSchema.GenericQuirksDetector()

    # Test various server types
    test_servers = [
        {
            "vendorName": "OpenLDAP",
            "description": "OpenLDAP slapd 2.4.57+dfsg-3ubuntu4.1",
        },
        {
            "vendorName": "Microsoft Corporation",
            "description": "Active Directory Domain Services",
        },
        {
            "vendorName": "Oracle Corporation",
            "description": "Oracle Directory Server Enterprise Edition",
        },
        {
            "vendorName": "Apache Software Foundation",
            "description": "Apache Directory Server",
        },
        {"vendorName": "389 Project", "description": "389 Directory Server"},
        {"vendorName": "Unknown Vendor", "description": "Generic LDAP Server v3.0"},
    ]

    for server_info in test_servers:
        server_type = detector.detect_server_type(server_info)
        quirks = detector.get_server_quirks(server_type)

        logger.info("Server: %s", server_info["vendorName"])
        logger.info("  Detected Type: %s", server_type.value)
        logger.info("  Case Sensitive DNs: %s", quirks.case_sensitive_dns)
        logger.info("  Case Sensitive Attributes: %s", quirks.case_sensitive_attributes)
        logger.info("  Supports Paged Results: %s", quirks.supports_paged_results)
        logger.info("  Supports VLV: %s", quirks.supports_vlv)
        logger.info("  Supports Sync: %s", quirks.supports_sync)
        logger.info("  Max Page Size: %s", quirks.max_page_size)
        logger.info("  Default Timeout: %s", quirks.default_timeout)
        logger.info()


if __name__ == "__main__":
    """Run the universal LDAP client demonstration."""
    print("Universal LDAP Client - Complete Generic Capabilities")
    print("=" * 60)
    print()
    print("This example demonstrates complete universal LDAP capabilities:")
    print("1. Automatic server detection and adaptation")
    print("2. Universal search operations with all parameters")
    print("3. Universal CRUD operations (Create, Read, Update, Delete)")
    print("4. Universal compare and extended operations")
    print("5. Complete server quirks handling")
    print("6. Automatic schema discovery and normalization")
    print()
    print("Environment Variables:")
    print("  LDAP_SERVER_URI - LDAP server URI (default: ldap://localhost:389)")
    print("  LDAP_BIND_DN - Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)")
    print("  LDAP_BIND_PASSWORD - Bind password (default: REDACTED_LDAP_BIND_PASSWORD)")
    print()

    # Run the demonstration
    asyncio.run(demonstrate_universal_client())

    # Show server type detection
    asyncio.run(demonstrate_server_type_detection())

    print("\nUniversal LDAP client demonstration completed!")
    print("The client can now handle ANY LDAP server in ANY form!")
