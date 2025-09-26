#!/usr/bin/env python3
"""Oracle OUD and Sun OpenDS Support Example.

This example demonstrates comprehensive support for Oracle OUD (Oracle Unified Directory)
and Sun OpenDS and all their derivatives:

1. Oracle OUD (Oracle Unified Directory)
2. Sun OpenDS (Sun Microsystems)
3. ForgeRock OpenDS/OpenDJ (derivatives)
4. Oracle Directory Enterprise Edition
5. All Oracle directory server variants

The client automatically detects and adapts to these Oracle directory servers
with their specific quirks, capabilities, and behaviors.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio
import os

from flext_core import FlextLogger
from flext_ldap import (
    FlextLdapClient,
    FlextLdapModels,
    FlextLdapSchema,
)


async def demonstrate_oracle_oud_opends_support() -> None:
    """Demonstrate Oracle OUD and Sun OpenDS support."""
    logger = FlextLogger(__name__)

    # Configuration for Oracle OUD/OpenDS servers
    server_uri = os.getenv(
        "LDAP_SERVER_URI", "ldap://localhost:1389"
    )  # Default OUD port
    bind_dn = os.getenv("LDAP_BIND_DN", "cn=Directory Manager")
    bind_password = os.getenv("LDAP_BIND_PASSWORD", "password")

    logger.info("Oracle OUD and Sun OpenDS Support Demonstration")
    logger.info("Server URI: %s", server_uri)
    logger.info("Bind DN: %s", bind_dn)

    # Create universal FLEXT LDAP client
    client = FlextLdapClient()

    try:
        # Connect with automatic schema discovery
        logger.info("Connecting with automatic Oracle OUD/OpenDS detection...")
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

        # Demonstrate Oracle OUD/OpenDS detection
        demonstrate_oracle_detection(client, logger)

        # Demonstrate Oracle-specific operations
        await demonstrate_oracle_operations(client, logger)

        # Demonstrate Oracle schema handling
        await demonstrate_oracle_schema(client, logger)

        # Demonstrate Oracle-specific quirks
        demonstrate_oracle_quirks(client, logger)

    except Exception:
        logger.exception("Error during demonstration")

    finally:
        # Disconnect
        if client.is_connected():
            await client.unbind()
            logger.info("Disconnected from LDAP server")


def demonstrate_oracle_detection(client: FlextLdapClient, logger: FlextLogger) -> None:
    """Demonstrate Oracle OUD/OpenDS server detection."""
    logger.info("\n=== Oracle OUD/OpenDS Detection ===")

    # Get server capabilities
    capabilities = client.get_server_capabilities()

    logger.info("Server Detection Results:")
    logger.info("  Connected: %s", capabilities["connected"])
    logger.info("  Schema Discovered: %s", capabilities["schema_discovered"])

    if capabilities["server_info"]:
        server_info_raw = capabilities["server_info"]
        if isinstance(server_info_raw, dict):
            server_info = server_info_raw
            logger.info("  Vendor: %s", server_info.get("vendorName", "Unknown"))
            logger.info("  Description: %s", server_info.get("description", "Unknown"))
            logger.info(
                "  LDAP Version: %s", server_info.get("supportedLDAPVersion", "Unknown")
            )
        else:
            logger.info("  Server info not available")

    if capabilities["server_type"]:
        server_type = capabilities["server_type"]
        if hasattr(server_type, "value"):
            logger.info("  Detected Server Type: %s", server_type.value)
            server_type_value = server_type.value
        else:
            logger.info("  Detected Server Type: %s", server_type)
            server_type_value = server_type

        if server_type in {
            FlextLdapModels.LdapServerType.ORACLE_OUD,
            FlextLdapModels.LdapServerType.SUN_OPENDS,
        }:
            logger.info("  ✅ Oracle OUD/OpenDS detected!")
        else:
            logger.info("  i  Other server type detected: %s", server_type_value)

    if capabilities["server_quirks"]:
        quirks = capabilities["server_quirks"]
        logger.info("  Server Quirks:")
        if hasattr(quirks, "case_sensitive_dns"):
            logger.info(
                "    Case Sensitive DNs: %s",
                getattr(quirks, "case_sensitive_dns", "unknown"),
            )
            logger.info(
                "    Case Sensitive Attributes: %s",
                getattr(quirks, "case_sensitive_attributes", "unknown"),
            )
            logger.info(
                "    Supports Paged Results: %s",
                getattr(quirks, "supports_paged_results", "unknown"),
            )
            logger.info(
                "    Supports VLV: %s", getattr(quirks, "supports_vlv", "unknown")
            )
            logger.info(
                "    Supports Sync: %s", getattr(quirks, "supports_sync", "unknown")
            )
        else:
            logger.info("    Server quirks not available")

        if hasattr(quirks, "max_page_size"):
            logger.info(
                "    Max Page Size: %s", getattr(quirks, "max_page_size", "unknown")
            )
            logger.info(
                "    Default Timeout: %s", getattr(quirks, "default_timeout", "unknown")
            )

            # Oracle-specific quirks
            if (
                hasattr(quirks, "filter_syntax_quirks")
                and "extended_matching_rules" in quirks.filter_syntax_quirks
            ):
                logger.info("    ✅ Supports Extended Matching Rules")
            if (
                hasattr(quirks, "modify_operation_quirks")
                and "atomic_modify" in quirks.modify_operation_quirks
            ):
                logger.info("    ✅ Supports Atomic Modify Operations")
            if (
                hasattr(quirks, "modify_operation_quirks")
                and "referential_integrity" in quirks.modify_operation_quirks
            ):
                logger.info("    ✅ Supports Referential Integrity")
            if (
                hasattr(quirks, "filter_syntax_quirks")
                and "virtual_attributes" in quirks.filter_syntax_quirks
            ):
                logger.info("    ✅ Supports Virtual Attributes")


async def demonstrate_oracle_operations(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate Oracle-specific operations."""
    logger.info("\n=== Oracle-Specific Operations ===")

    # Get server info for base DN
    server_info = client.get_server_info()
    if not server_info or not server_info.get("naming_contexts"):
        logger.warning("No naming contexts available for operations")
        return

    naming_contexts = server_info["naming_contexts"]
    if isinstance(naming_contexts, list) and len(naming_contexts) > 0:
        base_dn = naming_contexts[0]
    else:
        logger.warning("No naming contexts available")
        return
    logger.info("Using search base: %s", base_dn)

    # Oracle OUD/OpenDS specific search with extended matching rules
    logger.info("Performing Oracle-specific search...")
    search_result = await client.search_universal(
        base_dn=base_dn,
        search_filter="(objectClass=*)",
        attributes=["cn", "sn", "mail", "uid", "objectClass"],
        scope="subtree",
        size_limit=10,
        time_limit=30,
        deref_aliases="deref_always",
        types_only=False,
        controls=None,
    )

    if search_result.is_success:
        logger.info(
            "Oracle search successful: %d entries found", len(search_result.data)
        )
        for i, entry in enumerate(search_result.data[:3]):  # Show first 3
            logger.info("  Entry %d: %s", i + 1, entry.get("dn", "No DN"))
            if "cn" in entry:
                logger.info("    CN: %s", entry["cn"])
            if "uid" in entry:
                logger.info("    UID: %s", entry["uid"])
            if "objectClass" in entry:
                logger.info("    Object Classes: %s", entry["objectClass"])
    else:
        logger.error("Oracle search failed: %s", search_result.error)

    # Test Oracle-specific attribute mappings
    logger.info("Testing Oracle attribute mappings...")
    test_attributes = [
        "objectclass",
        "objectClass",
        "givenname",
        "givenName",
        "userpassword",
        "userPassword",
        "telephonenumber",
        "telephoneNumber",
        "facsimiletelephonenumber",
        "facsimileTelephoneNumber",
        "streetaddress",
        "streetAddress",
        "postalcode",
        "postalCode",
    ]

    for attr in test_attributes:
        normalized = client.normalize_attribute_name(attr)
        logger.info("  %s → %s", attr, normalized)


async def demonstrate_oracle_schema(
    client: FlextLdapClient, logger: FlextLogger
) -> None:
    """Demonstrate Oracle schema handling."""
    logger.info("\n=== Oracle Schema Handling ===")

    # Get discovered schema
    if client.is_schema_discovered():
        schema_result = await client.discover_schema()
        if schema_result.is_success:
            schema = schema_result.data
            logger.info("Oracle Schema Information:")
            logger.info("  Server Type: %s", schema.server_type.value)
            logger.info("  Discovered Attributes: %d", len(schema.attributes))
            logger.info("  Discovered Object Classes: %d", len(schema.object_classes))
            logger.info("  Naming Contexts: %s", schema.naming_contexts)
            logger.info("  Supported Controls: %d", len(schema.supported_controls))
            logger.info("  Supported Extensions: %d", len(schema.supported_extensions))

            # Show Oracle-specific attributes
            oracle_attrs = [
                attr
                for attr in schema.attributes
                if any(
                    keyword in attr.lower()
                    for keyword in ["oracle", "oud", "opends", "sun", "forgerock"]
                )
            ]
            if oracle_attrs:
                logger.info("  Oracle-Specific Attributes: %s", oracle_attrs[:5])

            # Show Oracle-specific object classes
            oracle_ocs = [
                oc
                for oc in schema.object_classes
                if any(
                    keyword in oc.lower()
                    for keyword in ["oracle", "oud", "opends", "sun", "forgerock"]
                )
            ]
            if oracle_ocs:
                logger.info("  Oracle-Specific Object Classes: %s", oracle_ocs[:5])
        else:
            logger.error("Schema discovery failed: %s", schema_result.error)
    else:
        logger.info("Schema not yet discovered")


def demonstrate_oracle_quirks(client: FlextLdapClient, logger: FlextLogger) -> None:
    """Demonstrate Oracle-specific quirks handling."""
    logger.info("\n=== Oracle-Specific Quirks Handling ===")

    # Test Oracle DN normalization
    logger.info("Oracle DN Normalization:")
    oracle_dns = [
        "cn=TestUser,ou=People,dc=example,dc=com",
        "CN=TESTUSER,OU=PEOPLE,DC=EXAMPLE,DC=COM",
        "uid=testuser,ou=People,dc=example,dc=com",
        "cn=Directory Manager",
        "cn=admin,cn=Administrators,cn=config",
    ]

    for dn in oracle_dns:
        normalized = client.normalize_dn(dn)
        logger.info("  %s → %s", dn, normalized)

    # Test Oracle object class normalization
    logger.info("Oracle Object Class Normalization:")
    oracle_ocs = [
        "person",
        "inetorgperson",
        "organizationalperson",
        "organizationalunit",
        "groupofnames",
        "groupofuniquenames",
        "posixaccount",
        "posixgroup",
        "shadowaccount",
    ]

    for oc in oracle_ocs:
        normalized = client.normalize_object_class(oc)
        logger.info("  %s → %s", oc, normalized)

    # Test Oracle attribute normalization
    logger.info("Oracle Attribute Normalization:")
    oracle_attrs = [
        "objectclass",
        "givenname",
        "userpassword",
        "telephonenumber",
        "facsimiletelephonenumber",
        "streetaddress",
        "postalcode",
    ]

    for attr in oracle_attrs:
        normalized = client.normalize_attribute_name(attr)
        logger.info("  %s → %s", attr, normalized)


def demonstrate_oracle_server_types() -> None:
    """Demonstrate Oracle server type detection."""
    logger = FlextLogger(__name__)

    logger.info("\n=== Oracle Server Type Detection ===")

    # Create quirks detector
    detector = FlextLdapSchema.GenericQuirksDetector()

    # Test various Oracle server types
    oracle_servers = [
        {
            "vendorName": "Oracle Corporation",
            "description": "Oracle Unified Directory Server 12.2.1.4.0",
        },
        {
            "vendorName": "Oracle Corporation",
            "description": "Oracle Directory Server Enterprise Edition 11.1.1.7.0",
        },
        {
            "vendorName": "Oracle Corporation",
            "description": "Oracle Internet Directory 11.1.1.7.0",
        },
        {"vendorName": "Sun Microsystems", "description": "Sun OpenDS Server 2.2.0"},
        {"vendorName": "ForgeRock", "description": "ForgeRock OpenDS Server 2.6.0"},
        {"vendorName": "ForgeRock", "description": "ForgeRock OpenDJ Server 3.0.0"},
        {"vendorName": "Oracle Corporation", "description": "OUD Server 12.2.1.4.0"},
    ]

    for server_info in oracle_servers:
        server_type = detector.detect_server_type(server_info)
        quirks = detector.get_server_quirks(server_type)

        logger.info("Oracle Server: %s", server_info["description"])
        if hasattr(server_type, "value"):
            logger.info("  Detected Type: %s", server_type.value)
        else:
            logger.info("  Detected Type: %s", server_type or "unknown")

        if hasattr(quirks, "case_sensitive_dns"):
            logger.info(
                "  Case Sensitive DNs: %s",
                getattr(quirks, "case_sensitive_dns", "unknown"),
            )
            logger.info(
                "  Case Sensitive Attributes: %s",
                getattr(quirks, "case_sensitive_attributes", "unknown"),
            )
            logger.info(
                "  Supports Paged Results: %s",
                getattr(quirks, "supports_paged_results", "unknown"),
            )
            logger.info(
                "  Supports VLV: %s", getattr(quirks, "supports_vlv", "unknown")
            )
        else:
            logger.info("  Server quirks not available")

        if hasattr(quirks, "supports_sync"):
            logger.info(
                "  Supports Sync: %s", getattr(quirks, "supports_sync", "unknown")
            )
            logger.info(
                "  Max Page Size: %s", getattr(quirks, "max_page_size", "unknown")
            )
            logger.info(
                "  Default Timeout: %s", getattr(quirks, "default_timeout", "unknown")
            )

        # Show Oracle-specific quirks
        if (
            hasattr(quirks, "filter_syntax_quirks")
            and "extended_matching_rules" in quirks.filter_syntax_quirks
        ):
            logger.info("  ✅ Extended Matching Rules Support")
        if (
            hasattr(quirks, "modify_operation_quirks")
            and "atomic_modify" in quirks.modify_operation_quirks
        ):
            logger.info("  ✅ Atomic Modify Operations")
        if (
            hasattr(quirks, "modify_operation_quirks")
            and "referential_integrity" in quirks.modify_operation_quirks
        ):
            logger.info("  ✅ Referential Integrity")
        if (
            hasattr(quirks, "filter_syntax_quirks")
            and "virtual_attributes" in quirks.filter_syntax_quirks
        ):
            logger.info("  ✅ Virtual Attributes Support")
        if (
            hasattr(quirks, "modify_operation_quirks")
            and "virtual_attribute_handling" in quirks.modify_operation_quirks
        ):
            logger.info("  ✅ Virtual Attribute Handling")

        logger.info("")


if __name__ == "__main__":
    """Run the Oracle OUD and Sun OpenDS support demonstration."""
    print("Oracle OUD and Sun OpenDS Support")
    print("=" * 50)
    print()
    print("This example demonstrates comprehensive support for:")
    print("1. Oracle OUD (Oracle Unified Directory)")
    print("2. Sun OpenDS (Sun Microsystems)")
    print("3. ForgeRock OpenDS/OpenDJ (derivatives)")
    print("4. Oracle Directory Enterprise Edition")
    print("5. All Oracle directory server variants")
    print()
    print("Features:")
    print("- Automatic server detection and adaptation")
    print("- Oracle-specific attribute and object class mappings")
    print("- Extended matching rules support")
    print("- Atomic modify operations")
    print("- Referential integrity handling")
    print("- Virtual attributes support")
    print()
    print("Environment Variables:")
    print("  LDAP_SERVER_URI - LDAP server URI (default: ldap://localhost:1389)")
    print("  LDAP_BIND_DN - Bind DN (default: cn=Directory Manager)")
    print("  LDAP_BIND_PASSWORD - Bind password (default: password)")
    print()

    # Run the demonstration
    asyncio.run(demonstrate_oracle_oud_opends_support())

    # Show server type detection
    demonstrate_oracle_server_types()

    print("\nOracle OUD and Sun OpenDS support demonstration completed!")
    print("The client now fully supports all Oracle directory server variants!")
