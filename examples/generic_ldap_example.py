#!/usr/bin/env python3
"""Generic LDAP Client Example - Universal Compatibility.

This example demonstrates how to use the FlextLDAPClients to work with
any LDAP server implementation, including:
- OpenLDAP
- Active Directory
- Oracle Directory Server
- Apache Directory Server
- 389 Directory Server
- Novell eDirectory
- object other LDAP3-compatible server

The client automatically:
1. Discovers server capabilities and schema
2. Detects server-specific quirks
3. Normalizes operations according to server behavior
4. Provides universal compatibility

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import os

from flext_ldap import FlextLDAPClients, FlextLDAPModels

from flext_core import FlextLogger, FlextTypes


def demonstrate_generic_ldap_client() -> None:
    """Demonstrate generic LDAP client with universal compatibility."""
    logger = FlextLogger(__name__)

    # Configuration - works with any LDAP server
    server_uri = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
    bind_password = os.getenv("LDAP_BIND_PASSWORD", "admin")

    logger.info("Starting Generic LDAP Client demonstration")
    logger.info("Server URI: %s", server_uri)
    logger.info("Bind DN: %s", bind_dn)

    # Create generic client
    client = FlextLDAPClients()

    try:
        # Connect with automatic schema discovery
        logger.info("Connecting to LDAP server with schema discovery...")
        connect_result = client.connect(
            server_uri=server_uri,
            bind_dn=bind_dn,
            password=bind_password,
            auto_discover_schema=True,
        )

        if connect_result.is_failure:
            logger.error("Failed to connect: %s", connect_result.error)
            return

        logger.info("Successfully connected to LDAP server")

        # Display discovered server information
        server_info = client.get_server_info()
        server_type = client.get_server_type()
        server_quirks = client.get_server_quirks()

        if server_info:
            logger.info("Server Information:")
            logger.info("  Vendor: %s", server_info.get("vendorName", "Unknown"))
            logger.info("  Description: %s", server_info.get("description", "Unknown"))
            logger.info(
                "  LDAP Version: %s", server_info.get("supportedLDAPVersion", "Unknown")
            )
            logger.info("  Naming Contexts: %s", server_info.get("namingContexts", []))

        if server_type:
            logger.info("Detected Server Type: %s", server_type)

        if server_quirks:
            logger.info("Server Quirks:")
            logger.info("  Case Sensitive DNs: %s", server_quirks.case_sensitive_dns)
            logger.info(
                "  Case Sensitive Attributes: %s",
                server_quirks.case_sensitive_attributes,
            )
            logger.info(
                "  Supports Paged Results: %s", server_quirks.supports_paged_results
            )
            logger.info("  Supports VLV: %s", server_quirks.supports_vlv)
            logger.info("  Max Page Size: %s", server_quirks.max_page_size)
            logger.info(
                "  Requires Explicit Bind: %s", server_quirks.requires_explicit_bind
            )

        # Demonstrate universal search operations
        demonstrate_universal_search(client, logger)

        # Demonstrate universal CRUD operations
        demonstrate_universal_crud(client, logger)

        # Demonstrate server-specific adaptations
        demonstrate_server_adaptations(client, logger)

    except Exception:
        logger.exception("Error during demonstration")

    finally:
        # Disconnect
        if client.is_connected():
            client.unbind()
            logger.info("Disconnected from LDAP server")


def demonstrate_universal_search(client: FlextLDAPClients, logger: FlextLogger) -> None:
    """Demonstrate universal search operations."""
    logger.info("\n=== Universal Search Operations ===")

    # Get naming contexts for search base
    server_info = client.get_server_info()
    if not server_info or not server_info.get("namingContexts"):
        logger.warning("No naming contexts available for search")
        return

    naming_contexts = server_info["namingContexts"]
    if isinstance(naming_contexts, list) and len(naming_contexts) > 0:
        base_dn = naming_contexts[0]
    else:
        logger.warning("No naming contexts available")
        return

    logger.info("Using search base: %s", base_dn)

    # Search for all entries (universal filter)
    logger.info("Searching for all entries...")
    search_result = client.search(
        base_dn=base_dn,
        filter_str="(objectClass=*)",
        attributes=["objectClass", "cn", "sn", "mail"],
    )

    if search_result.is_success:
        logger.info("Found %d entries", len(search_result.data))
        for i, entry in enumerate(search_result.data[:5]):  # Show first 5
            logger.info("  Entry %d: %s", i + 1, entry.dn)
            attrs = entry.attributes
            if "cn" in attrs:
                logger.info("    CN: %s", attrs["cn"])
            if "objectClass" in attrs:
                logger.info("    Object Classes: %s", attrs["objectClass"])
    else:
        logger.error("Search failed: %s", search_result.error)

    # Search for person entries (common across LDAP implementations)
    logger.info("\nSearching for person entries...")
    person_search = client.search(
        base_dn=base_dn,
        filter_str="(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=user))",
        attributes=["cn", "sn", "givenName", "mail", "objectClass"],
    )

    if person_search.is_success:
        logger.info("Found %d person entries", len(person_search.data))
        for entry in person_search.data[:3]:  # Show first 3
            dn = entry.dn
            attrs = entry.attributes
            logger.info("  Person: %s", dn)
            if "cn" in attrs:
                logger.info("    Name: %s", attrs["cn"])
            if "mail" in attrs:
                logger.info("    Email: %s", attrs["mail"])
    else:
        logger.error("Person search failed: %s", person_search.error)


def demonstrate_universal_crud(client: FlextLDAPClients, logger: FlextLogger) -> None:
    """Demonstrate universal CRUD operations."""
    logger.info("\n=== Universal CRUD Operations ===")

    # Get naming contexts for operations
    server_info = client.get_server_info()
    if not server_info or not server_info.get("namingContexts"):
        logger.warning("No naming contexts available for CRUD operations")
        return

    naming_contexts = server_info["namingContexts"]
    if isinstance(naming_contexts, list) and len(naming_contexts) > 0:
        base_dn = naming_contexts[0]
    else:
        logger.warning("No naming contexts available for test")
        return

    # Create a test entry (universal attributes)
    test_dn = f"cn=testuser,{base_dn}"
    test_attributes = {
        "cn": "testuser",
        "sn": "TestUser",
        "objectClass": ["person", "top"],
        "description": "Test user created by FlextLDAPClients",
    }

    logger.info("Creating test entry: %s", test_dn)
    create_result = client.add_entry_universal(test_dn, test_attributes)

    if create_result.is_success:
        logger.info("Successfully created test entry")

        # Modify the entry
        logger.info("Modifying test entry...")
        modify_changes: FlextTypes.Dict = {"description": "Modified test user"}
        modify_result = client.modify_entry_universal(test_dn, modify_changes)

        if modify_result.is_success:
            logger.info("Successfully modified test entry")
        else:
            logger.error("Modify failed: %s", modify_result.error)

        # Delete the test entry
        logger.info("Deleting test entry...")
        delete_result = client.delete_entry_universal(test_dn)

        if delete_result.is_success:
            logger.info("Successfully deleted test entry")
        else:
            logger.error("Delete failed: %s", delete_result.error)

    else:
        logger.error("Create failed: %s", create_result.error)


def demonstrate_server_adaptations(
    client: FlextLDAPClients, logger: FlextLogger
) -> None:
    """Demonstrate server-specific adaptations."""
    logger.info("\n=== Server-Specific Adaptations ===")

    server_type = client.get_server_type()
    server_quirks = client.get_server_quirks()

    if not server_type or not server_quirks:
        logger.warning("No server information available for adaptations")
        return

    logger.info("Server Type: %s", server_type)

    # Demonstrate case sensitivity adaptations
    if server_quirks.case_sensitive_dns:
        logger.info("Server uses case-sensitive DNs")
        logger.info(
            "  Example: cn=TestUser,dc=example,dc=com ≠ cn=testuser,dc=example,dc=com"
        )
    else:
        logger.info("Server uses case-insensitive DNs")
        logger.info(
            "  Example: cn=TestUser,dc=example,dc=com = cn=testuser,dc=example,dc=com"
        )

    if server_quirks.case_sensitive_attributes:
        logger.info("Server uses case-sensitive attribute names")
        logger.info("  Example: objectClass ≠ objectclass")
    else:
        logger.info("Server uses case-insensitive attribute names")
        logger.info("  Example: objectClass = objectclass")

    # Demonstrate capability adaptations
    if server_quirks.supports_paged_results:
        logger.info("Server supports paged search results")
        logger.info("  Large result sets will be automatically paginated")
    else:
        logger.info("Server does not support paged search results")
        logger.info("  Large result sets may be limited")

    if server_quirks.supports_vlv:
        logger.info("Server supports Virtual List View (VLV)")
        logger.info("  Efficient browsing of large result sets available")
    else:
        logger.info("Server does not support Virtual List View (VLV)")

    # Demonstrate attribute name mappings
    if server_quirks.attribute_name_mappings:
        logger.info("Server has attribute name mappings:")
        for original, mapped in server_quirks.attribute_name_mappings.items():
            logger.info("  %s → %s", original, mapped)
    else:
        logger.info("Server uses standard attribute names")

    # Demonstrate object class mappings
    if server_quirks.object_class_mappings:
        logger.info("Server has object class mappings:")
        for original, mapped in server_quirks.object_class_mappings.items():
            logger.info("  %s → %s", original, mapped)
    else:
        logger.info("Server uses standard object class names")


def demonstrate_different_server_types() -> None:
    """Demonstrate how the client adapts to different server types."""
    logger = FlextLogger(__name__)

    logger.info("\n=== Server Type Adaptations ===")

    # Simulate different server types and their quirks
    server_examples = [
        {
            "name": "OpenLDAP",
            "type": FlextLDAPModels.LdapServerType.OPENLDAP,
            "quirks": {
                "case_sensitive_dns": True,
                "case_sensitive_attributes": True,
                "supports_paged_results": True,
                "supports_vlv": True,
                "supports_sync": True,
            },
        },
        {
            "name": "Active Directory",
            "type": FlextLDAPModels.LdapServerType.ACTIVE_DIRECTORY,
            "quirks": {
                "case_sensitive_dns": False,
                "case_sensitive_attributes": False,
                "supports_paged_results": True,
                "supports_vlv": False,
                "requires_explicit_bind": True,
                "attribute_name_mappings": {
                    "objectclass": "objectClass",
                    "cn": "cn",
                    "sn": "sn",
                    "givenname": "givenName",
                    "userprincipalname": "userPrincipalName",
                },
            },
        },
        {
            "name": "Oracle Directory Server",
            "type": FlextLDAPModels.LdapServerType.ORACLE_DIRECTORY,
            "quirks": {
                "case_sensitive_dns": True,
                "case_sensitive_attributes": True,
                "supports_paged_results": True,
                "supports_vlv": True,
                "supports_sync": True,
            },
        },
    ]

    for server in server_examples:
        logger.info("\n%s Server:", server["name"])
        server_type = server["type"]
        if hasattr(server_type, "value"):
            logger.info("  Type: %s", server_type.value)
        else:
            logger.info("  Type: %s", server_type)

        quirks = server["quirks"]
        if isinstance(quirks, dict):
            logger.info(
                "  Case Sensitive DNs: %s", quirks.get("case_sensitive_dns", True)
            )
            logger.info(
                "  Case Sensitive Attributes: %s",
                quirks.get("case_sensitive_attributes", True),
            )
            logger.info(
                "  Supports Paged Results: %s",
                quirks.get("supports_paged_results", False),
            )
            logger.info("  Supports VLV: %s", quirks.get("supports_vlv", False))
            logger.info(
                "  Requires Explicit Bind: %s",
                quirks.get("requires_explicit_bind", False),
            )
        else:
            logger.info("  Server quirks not available")

        if isinstance(quirks, dict) and "attribute_name_mappings" in quirks:
            logger.info("  Attribute Mappings: %s", quirks["attribute_name_mappings"])


if __name__ == "__main__":
    """Run the generic LDAP client demonstration."""
    print("Generic LDAP Client - Universal Compatibility Example")
    print("=" * 60)
    print()
    print("This example demonstrates how to use FlextLDAPClients")
    print("to work with any LDAP server implementation.")
    print()
    print("Environment Variables:")
    print("  LDAP_SERVER_URI - LDAP server URI (default: ldap://localhost:389)")
    print("  LDAP_BIND_DN - Bind DN (default: cn=admin,dc=example,dc=com)")
    print("  LDAP_BIND_PASSWORD - Bind password (default: admin)")
    print()

    # Run the demonstration
    demonstrate_generic_ldap_client()

    # Show server type adaptations
    demonstrate_different_server_types()

    print("\nDemonstration completed!")
    print("The FlextLDAPClients provides universal compatibility")
    print("across all LDAP server implementations.")
