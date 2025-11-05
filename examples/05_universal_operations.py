#!/usr/bin/env python3
"""Universal LDAP Operations Example - flext-ldap API.

This example demonstrates server-agnostic LDAP operations:
- Server type detection (get_detected_server_type)
- Server operations access (get_server_operations)
- Server capabilities discovery (get_server_capabilities)
- Universal search with optimization (search_universal)
- Entry normalization for servers (normalize_entry_for_server)
- Entry format conversion (convert_entry_between_servers)
- Server type detection from entries (detect_entry_server_type)
- Entry validation for servers (validate_entry_for_server)
- Server-specific attributes (get_server_specific_attributes)
- Server quirks details and inspection
- ACL attribute names and formats per server
- Paging limits for different servers
- Timeout defaults per server type
- Operational attributes support
- Connection defaults optimization

Demonstrates the universal LDAP client that works with ANY LDAP server.

Uses ONLY api.py (FlextLdap) as the primary interface.
Demonstrates quirks_integration.py (FlextLdapQuirksIntegration) functionality.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=admin,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: admin)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/05_universal_operations.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
from typing import Final, cast

from flext_core import FlextLogger, FlextResult
from flext_ldif import FlextLdifModels
from pydantic import SecretStr

from flext_ldap import FlextLdap, FlextLdapConfig, FlextLdapModels
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.services.quirks_integration import FlextLdapQuirksIntegration

logger: FlextLogger = FlextLogger(__name__)

# Configuration from environment
LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "admin")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


def setup_api() -> FlextLdap | None:
    """Setup and connect FlextLdap API.

    Returns:
        Connected FlextLdap instance or None if connection failed.

    """
    FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap()

    # Use context manager for automatic connection/disconnection
    try:
        with api:
            return api
    except Exception:
        logger.exception("Connection failed")
        return None


def demonstrate_server_detection(api: FlextLdap) -> str | None:
    """Demonstrate automatic server type detection.

    Args:
        api: Connected FlextLdap instance

    Returns:
        Detected server type or None if detection failed.

    """
    logger.info("=== Server Type Detection ===")

    # Get detected server type
    result = api.get_detected_server_type()

    if result.is_failure:
        logger.error(f"❌ Server detection failed: {result.error}")
        return None

    server_type = result.unwrap()
    if server_type:
        logger.info(f"✅ Detected server type: {server_type}")
    else:
        logger.info("⚠️  Server type not detected (generic LDAP server)")

    return server_type


def demonstrate_server_capabilities(api: FlextLdap) -> None:
    """Demonstrate server capabilities discovery.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Server Capabilities ===")

    # Get comprehensive server capabilities
    result: FlextResult[FlextLdapModels.ServerCapabilities] = (
        api.get_server_capabilities()
    )

    if result.is_failure:
        logger.error(f"❌ Failed to get capabilities: {result.error}")
        return

    capabilities = result.unwrap()
    logger.info("✅ Server capabilities retrieved:")

    # Display capabilities
    logger.info(f"   Supports SSL: {capabilities.supports_ssl}")
    logger.info(f"   Supports StartTLS: {capabilities.supports_starttls}")
    logger.info(f"   Supports Paged Results: {capabilities.supports_paged_results}")
    logger.info(f"   Supports VLV: {capabilities.supports_vlv}")
    logger.info(f"   Supports SASL: {capabilities.supports_sasl}")
    logger.info(f"   Max Page Size: {capabilities.max_page_size}")


def demonstrate_server_operations(api: FlextLdap) -> None:
    """Demonstrate direct access to server operations.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Server Operations Access ===")

    # Get detected server type
    server_type = api.server_type
    if server_type:
        logger.info("✅ Server type detected")
        logger.info(f"   Server Type: {server_type}")
        logger.info("   Server type uses existing flext-ldif constants")
        logger.info(
            "   All server-specific configurations available in FlextLdifConstants"
        )
    else:
        logger.warning("⚠️  Server type not detected")
        return


def demonstrate_universal_search(api: FlextLdap) -> None:
    """Demonstrate universal search with automatic optimization.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Universal Search Operations ===")

    # Perform universal search (automatically uses server-specific optimizations)
    logger.info(f"Performing universal search on {BASE_DN}")
    result: FlextResult[list[FlextLdifModels.Entry]] = cast(
        "FlextResult[list[FlextLdifModels.Entry]]",
        api.search(
            base_dn=BASE_DN,
            search_filter="(objectClass=*)",
            attributes=["dn", "objectClass"],
        ),
    )

    if result.is_failure:
        logger.error(f"❌ Universal search failed: {result.error}")
        return

    search_results = result.unwrap()
    logger.info(f"✅ Universal search found {len(search_results)} entries")
    logger.info("   (Used server-specific optimizations automatically)")

    # Show first few entries
    for i, search_entry in enumerate(search_results[:3], 1):
        dn = search_entry.dn
        logger.info(f"   {i}. {dn}")


def demonstrate_entry_normalization() -> None:
    """Demonstrate entry normalization for target servers."""
    logger.info("\n=== Entry Normalization ===")

    # Create a sample entry
    sample_entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": FlextLdifModels.AttributeValues(
                    values=["person", "inetOrgPerson"]
                ),
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
                "sn": FlextLdifModels.AttributeValues(values=["Test"]),
                "mail": FlextLdifModels.AttributeValues(values=["test@example.com"]),
            }
        ),
        version=1,
    )

    logger.info("Normalizing entry for current server...")
    # Convert LDIF entry to LDAP entry for normalization
    ldap_entry = FlextLdifModels.Entry.from_ldif(sample_entry)
    ldif_entry_for_adapter = ldap_entry.to_ldif()

    adapter = FlextLdapEntryAdapter()
    result = adapter.normalize_entry_for_server(ldif_entry_for_adapter, "generic")
    # result is already typed as FlextResult[FlextLdifModels.Entry] from the method signature

    if result.is_success:
        normalized_entry = result.unwrap()
        logger.info("✅ Entry normalized successfully")
        logger.info(f"   DN: {normalized_entry.dn}")
        attrs = list(normalized_entry.attributes.attributes.keys())
        logger.info(f"   Attributes: {attrs}")
    else:
        logger.error(f"❌ Normalization failed: {result.error}")


def demonstrate_entry_conversion() -> None:
    """Demonstrate entry format conversion between servers (no connection needed)."""
    logger.info("\n=== Entry Format Conversion ===")

    # Create FlextLdap API for conversion
    FlextLdap()

    # Create a sample entry with OpenLDAP 1.x ACL
    sample_entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
                "sn": FlextLdifModels.AttributeValues(values=["Test"]),
                # OpenLDAP 1.x ACL format
                "access": FlextLdifModels.AttributeValues(
                    values=["to * by self write by * read"]
                ),
            }
        ),
    )

    logger.info("Converting entry: OpenLDAP 1.x → OpenLDAP 2.x")
    src_attrs = list(sample_entry.attributes.attributes.keys())
    logger.info(f"   Source attributes: {src_attrs}")

    # Convert LDIF entry to LDAP entry for server conversion
    ldap_entry = FlextLdifModels.Entry.from_ldif(sample_entry)
    ldif_entry_for_adapter = ldap_entry.to_ldif()

    adapter = FlextLdapEntryAdapter()
    result = adapter.convert_entry_format(
        entry=ldif_entry_for_adapter,
        source_server_type="openldap1",
        target_server_type="openldap2",
    )

    if result.is_success:
        converted_entry = result.unwrap()
        logger.info("✅ Entry converted successfully")
        tgt_attrs = list(converted_entry.attributes.attributes.keys())
        logger.info(f"   Target attributes: {tgt_attrs}")
        logger.info("   (ACL format converted: 'access' → 'olcAccess')")
    else:
        logger.error(f"❌ Conversion failed: {result.error}")


def demonstrate_server_detection_from_entry() -> None:
    """Demonstrate server type detection from entry attributes.

    No connection needed for this demonstration.
    """
    logger.info("\n=== Server Type Detection from Entry ===")

    # Create FlextLdap API for detection
    FlextLdap()

    # Create sample entries with server-specific attributes
    test_entries: list[dict[str, str | FlextLdifModels.Entry]] = [
        {
            "name": "OpenLDAP 2.x entry",
            "entry": FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=config,dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["olcGlobal"]
                        ),
                        "olcAccess": FlextLdifModels.AttributeValues(
                            values=["to * by * read"]
                        ),
                    }
                ),
            ),
        },
        {
            "name": "Oracle OID entry",
            "entry": FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                        "orclaci": FlextLdifModels.AttributeValues(
                            values=["access to entry by * (read)"]
                        ),
                    }
                ),
            ),
        },
    ]

    for test_case in test_entries:
        logger.info(f"\nDetecting server type for: {test_case['name']}")
        entry = test_case["entry"]
        if isinstance(entry, FlextLdifModels.Entry):
            # Convert LDIF entry to LDAP entry for server type detection
            ldap_entry = FlextLdifModels.Entry.from_ldif(entry)
            ldif_entry_for_adapter = ldap_entry.to_ldif()

            adapter = FlextLdapEntryAdapter()
            result = adapter.detect_entry_server_type(ldif_entry_for_adapter)
        else:
            logger.warning(f"   ⚠️  Skipping invalid entry type: {type(entry)}")
            continue

        if result.is_success:
            detected_type = result.unwrap()
            logger.info(f"   ✅ Detected: {detected_type}")
        else:
            logger.error(f"   ❌ Detection failed: {result.error}")


def demonstrate_entry_validation() -> None:
    """Demonstrate entry validation for target servers."""
    logger.info("\n=== Entry Validation ===")

    # Create a sample entry
    sample_entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": FlextLdifModels.AttributeValues(
                    values=["person", "inetOrgPerson"]
                ),
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
                "sn": FlextLdifModels.AttributeValues(values=["Test"]),
                "mail": FlextLdifModels.AttributeValues(values=["test@example.com"]),
            }
        ),
    )

    logger.info("Validating entry for current server...")
    # Convert LDIF entry to LDAP entry for validation
    ldap_entry = FlextLdifModels.Entry.from_ldif(sample_entry)
    ldif_entry_for_adapter = ldap_entry.to_ldif()

    adapter = FlextLdapEntryAdapter()
    result = adapter.validate_entry_for_server(ldif_entry_for_adapter, "generic")

    if result.is_success:
        is_valid = result.unwrap()
        if is_valid:
            logger.info("✅ Entry is valid for current server")
        else:
            logger.warning("⚠️  Entry validation failed (incompatible)")
    else:
        logger.error(f"❌ Validation error: {result.error}")


def demonstrate_server_specific_attributes(api: FlextLdap) -> None:
    """Demonstrate server-specific attribute information.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Server-Specific Attributes ===")

    # Get server-specific attributes
    attributes = api.get_server_specific_attributes("generic")
    logger.info("✅ Server-specific attributes retrieved:")
    logger.info(f"   Attributes: {attributes}")

    # Display attribute information
    for attr in attributes:
        logger.info(f"   • {attr}")


def demonstrate_servers_details(server_type: str | None) -> None:
    """Demonstrate detailed server quirks inspection.

    Args:
        server_type: Detected server type

    """
    logger.info("\n=== Server Quirks Details ===")

    quirks_integration = FlextLdapQuirksIntegration()

    logger.info(f"\n1. Getting quirks for server type: {server_type or 'generic'}")

    result = quirks_integration.get_servers(server_type)

    if result.is_success:
        quirks = result.unwrap()
        logger.info("   ✅ Server quirks retrieved:")
        logger.info(f"      Server type: {quirks.get('server_type', 'unknown')}")
        logger.info(
            f"      Case-sensitive DNs: {quirks.get('case_sensitive_dns', True)}"
        )
        logger.info(
            f"      Case-sensitive attrs: {quirks.get('case_sensitive_attributes', True)}"
        )
        logger.info(
            f"      Paged results: {quirks.get('supports_paged_results', True)}"
        )
        logger.info(f"      VLV support: {quirks.get('supports_vlv', False)}")
        logger.info(f"      Max page size: {quirks.get('max_page_size', 1000)}")
        logger.info(f"      Default timeout: {quirks.get('default_timeout', 30)}s")
        logger.info(f"      StartTLS: {quirks.get('supports_start_tls', True)}")
        logger.info(
            f"      Explicit bind required: {quirks.get('requires_explicit_bind', False)}"
        )
    else:
        logger.warning(f"   ⚠️  Failed to get quirks: {result.error}")


def demonstrate_acls(_server_type: str | None) -> None:
    """Demonstrate ACL-related quirks for different servers.

    Args:
        _server_type: Detected server type

    """
    logger.info("\n=== ACL Quirks for Different Servers ===")

    quirks_integration = FlextLdapQuirksIntegration()

    # Demonstrate ACL attribute names
    logger.info("\n1. ACL Attribute Names:")

    server_types = ["openldap1", "openldap2", "oid", "oud", "389ds", "ad"]

    for srv_type in server_types:
        result = quirks_integration.get_acl_attribute_name(srv_type)
        if result.is_success:
            acl_attr = result.unwrap()
            logger.info(f"   • {srv_type}: {acl_attr}")

    # Demonstrate ACL formats
    logger.info("\n2. ACL Formats:")

    for srv_type in server_types:
        result = quirks_integration.get_acl_format(srv_type)
        if result.is_success:
            acl_format = result.unwrap()
            logger.info(f"   • {srv_type}: {acl_format}")


def demonstrate_pagings(_server_type: str | None) -> None:
    """Demonstrate paging and pagination quirks.

    Args:
        _server_type: Detected server type

    """
    logger.info("\n=== Paging Quirks ===")

    quirks_integration = FlextLdapQuirksIntegration()

    logger.info("\n1. Max Page Sizes for Different Servers:")

    server_types = ["openldap1", "openldap2", "oid", "oud", "389ds", "ad"]

    for srv_type in server_types:
        result = quirks_integration.get_max_page_size(srv_type)
        if result.is_success:
            max_size = result.unwrap()
            logger.info(f"   • {srv_type}: {max_size} entries")


def demonstrate_timeouts(_server_type: str | None) -> None:
    """Demonstrate timeout quirks for different servers.

    Args:
        _server_type: Detected server type

    """
    logger.info("\n=== Timeout Quirks ===")

    quirks_integration = FlextLdapQuirksIntegration()

    logger.info("\n1. Default Timeouts for Different Servers:")

    server_types = ["openldap1", "openldap2", "oid", "oud", "389ds", "ad"]

    for srv_type in server_types:
        result = quirks_integration.get_default_timeout(srv_type)
        if result.is_success:
            timeout = result.unwrap()
            logger.info(f"   • {srv_type}: {timeout}s")


def demonstrate_operational_attributess(_server_type: str | None) -> None:
    """Demonstrate operational attributes support quirks.

    Args:
        _server_type: Detected server type

    """
    logger.info("\n=== Operational Attributes Quirks ===")

    quirks_integration = FlextLdapQuirksIntegration()

    logger.info("\n1. Operational Attributes Support:")

    server_types = ["openldap1", "openldap2", "oid", "oud", "389ds", "ad"]

    for srv_type in server_types:
        result = quirks_integration.supports_operational_attributes(srv_type)
        if result.is_success:
            supports = result.unwrap()
            status = "✅ Supported" if supports else "❌ Not supported"
            logger.info(f"   • {srv_type}: {status}")


def demonstrate_connection_defaultss(server_type: str | None) -> None:
    """Demonstrate connection defaults quirks.

    Args:
        server_type: Detected server type

    """
    logger.info("\n=== Connection Defaults Quirks ===")

    quirks_integration = FlextLdapQuirksIntegration()

    logger.info(f"\n1. Connection defaults for: {server_type or 'generic'}")

    result = quirks_integration.get_connection_defaults(server_type)

    if result.is_success:
        defaults = result.unwrap()
        logger.info("   ✅ Connection defaults:")
        for key, value in defaults.items():
            logger.info(f"      • {key}: {value}")
    else:
        logger.warning(f"   ⚠️  Failed to get defaults: {result.error}")


def main() -> int:
    """Run universal LDAP operations demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 60)
    logger.info("FLEXT-LDAP Universal Operations Example")
    logger.info("=" * 60)
    logger.info(f"Server: {LDAP_URI}")
    logger.info(f"Base DN: {BASE_DN}")
    logger.info("=" * 60)

    try:
        # Demonstrations without connection
        demonstrate_entry_conversion()
        demonstrate_server_detection_from_entry()

        # Connect to LDAP server
        api = setup_api()
        if not api:
            logger.error("Cannot proceed without connection")
            return 1

        try:
            # Server-specific demonstrations
            server_type = demonstrate_server_detection(api)
            demonstrate_server_capabilities(api)
            demonstrate_server_operations(api)
            demonstrate_universal_search(api)
            demonstrate_entry_normalization()
            demonstrate_entry_validation()
            demonstrate_server_specific_attributes(api)

            # Quirks demonstrations
            demonstrate_servers_details(server_type)
            demonstrate_acls(server_type)
            demonstrate_pagings(server_type)
            demonstrate_timeouts(server_type)
            demonstrate_operational_attributess(server_type)
            demonstrate_connection_defaultss(server_type)

            logger.info(f"\n{'=' * 60}")
            logger.info("✅ All universal operations completed successfully!")
            logger.info("=" * 60)
            if server_type:
                logger.info(f"Server Type: {server_type}")
            logger.info("The universal client adapts to ANY LDAP server automatically!")
            logger.info("=" * 60)

            logger.info("\nQuirks Integration Demonstrated:")
            logger.info("  • Server-specific quirks detection")
            logger.info("  • ACL attribute names and formats per server")
            logger.info("  • Paging limits for different servers")
            logger.info("  • Timeout defaults per server type")
            logger.info("  • Operational attributes support")
            logger.info("  • Connection defaults optimization")

        finally:
            # Always disconnect
            if api.client.is_connected:
                api.unbind()
                logger.info("Disconnected from LDAP server")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
