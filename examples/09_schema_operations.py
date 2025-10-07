#!/usr/bin/env python3
"""Schema Operations Example - flext-ldap API.

This example demonstrates LDAP schema discovery and introspection:
- Server type detection with quirks
- Schema subentry DN discovery
- Object class inspection
- Attribute type discovery
- Server-specific schema handling
- FlextLdapSchema for comprehensive schema operations
- FlextLdapQuirksIntegration for server adaptation

Demonstrates schema discovery workflow for LDAP server analysis.

Uses api.py (FlextLdap) and schema module classes.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=admin,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: admin)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/09_schema_operations.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
from typing import Final

from flext_core import FlextLogger, FlextResult

from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.quirks_integration import FlextLdapQuirksIntegration
from flext_ldap.schema import FlextLdapSchema

logger = FlextLogger(__name__)

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
    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=BIND_PASSWORD,
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap(config=config)

    connect_result = api.connect()
    if connect_result.is_failure:
        logger.error(f"Connection failed: {connect_result.error}")
        return None

    return api


def demonstrate_server_detection(api: FlextLdap) -> str | None:
    """Demonstrate automatic server type detection with schema awareness.

    Args:
        api: Connected FlextLdap instance

    Returns:
        Detected server type or None if detection failed.

    """
    logger.info("=== Server Type Detection ===")

    # Get detected server type
    result: FlextResult[str | None] = api.get_detected_server_type()

    if result.is_failure:
        logger.error(f"❌ Server detection failed: {result.error}")
        return None

    server_type = result.unwrap()

    if server_type:
        logger.info(f"✅ Detected server type: {server_type}")

        # Map server type to description
        server_descriptions = {
            "openldap1": "OpenLDAP 1.x (legacy)",
            "openldap2": "OpenLDAP 2.x (modern)",
            "oid": "Oracle Internet Directory (OID)",
            "oud": "Oracle Unified Directory (OUD)",
            "389ds": "389 Directory Server / Red Hat DS",
            "ad": "Microsoft Active Directory",
            "apacheds": "Apache Directory Server",
        }

        description = server_descriptions.get(server_type, "Unknown LDAP server")
        logger.info(f"   Description: {description}")

    else:
        logger.info("⚠️  Server type not detected (generic LDAP server)")
        server_type = "generic"

    return server_type


def demonstrate_schema_discovery(server_type: str | None) -> None:
    """Demonstrate schema discovery operations.

    Args:
        server_type: Detected server type for quirks handling

    """
    logger.info("\n=== Schema Discovery Operations ===")

    # Create schema discovery instance
    schema = FlextLdapSchema()
    discovery = schema.Discovery()

    logger.info("\n1. Schema Subentry DN Discovery:")

    # Get schema subentry DN based on server type
    result: FlextResult[str] = discovery.get_schema_subentry_dn(server_type)

    if result.is_success:
        schema_dn = result.unwrap()
        logger.info(f"   ✅ Schema subentry DN: {schema_dn}")

        # Explain server-specific schema locations
        schema_locations = {
            "openldap1": "cn=schema (OpenLDAP 1.x specific)",
            "openldap2": "cn=subschema (RFC 4512 compliant)",
            "oid": "cn=subschemasubentry (Oracle OID)",
            "oud": "cn=schema (Oracle OUD)",
            "389ds": "cn=schema (389 DS)",
            "ad": "CN=Aggregate,CN=Schema,CN=Configuration (AD)",
            "generic": "cn=subschema (RFC 4512 standard)",
        }

        expected = schema_locations.get(server_type or "generic", "cn=subschema")
        logger.info(f"   ℹ️  Expected for {server_type}: {expected}")

    else:
        logger.warning(f"   ⚠️  Schema subentry discovery: {result.error}")
        logger.info("   ℹ️  Using default: cn=subschema (RFC 4512)")


def demonstrate_quirks_detection(server_type: str | None) -> None:
    """Demonstrate server quirks detection and handling.

    Args:
        server_type: Detected server type

    """
    logger.info("\n=== Server Quirks Detection ===")

    # Create quirks detector
    schema = FlextLdapSchema()
    detector = schema.GenericQuirksDetector()

    logger.info(f"\n1. Detecting quirks for server type: {server_type or 'generic'}")

    # Get server quirks
    quirks = detector.get_server_quirks(server_type)

    if quirks:
        logger.info("   ✅ Server quirks detected:")
        logger.info(f"      Server type: {quirks.server_type}")
        logger.info(f"      Case-sensitive DNs: {quirks.case_sensitive_dns}")
        logger.info(f"      Case-sensitive attributes: {quirks.case_sensitive_attributes}")
        logger.info(f"      Paged results: {quirks.supports_paged_results}")
        logger.info(f"      VLV support: {quirks.supports_vlv}")
        logger.info(f"      Max page size: {quirks.max_page_size}")
        logger.info(f"      Default timeout: {quirks.default_timeout}s")
        logger.info(f"      StartTLS: {quirks.supports_start_tls}")
        logger.info(f"      Explicit bind required: {quirks.requires_explicit_bind}")
    else:
        logger.warning("   ⚠️  No quirks detected (using defaults)")


def demonstrate_quirks_integration(api: FlextLdap, server_type: str | None) -> None:
    """Demonstrate FlextLdapQuirksIntegration usage.

    Args:
        api: Connected FlextLdap instance
        server_type: Detected server type

    """
    logger.info("\n=== Quirks Integration ===")

    # Create quirks integration instance
    quirks = FlextLdapQuirksIntegration()

    logger.info("\n1. Getting schema subentry with quirks integration:")

    # Get schema subentry using quirks
    result = quirks.get_schema_subentry(server_type)

    if result.is_success:
        schema_dn = result.unwrap()
        logger.info(f"   ✅ Schema DN (quirks-aware): {schema_dn}")

        # Show how quirks affect schema discovery
        logger.info("\n2. Server-specific schema characteristics:")

        if server_type == "openldap2":
            logger.info("   • OpenLDAP 2.x uses RFC 4512 cn=subschema")
            logger.info("   • Schema attributes: objectClasses, attributeTypes")
            logger.info("   • Supports dynamic schema updates")

        elif server_type in {"oid", "oud"}:
            logger.info("   • Oracle servers use proprietary schema locations")
            logger.info("   • OID: cn=subschemasubentry")
            logger.info("   • OUD: cn=schema")
            logger.info("   • Extended schema metadata available")

        elif server_type == "389ds":
            logger.info("   • 389 DS uses cn=schema")
            logger.info("   • Schema replication supported")
            logger.info("   • Dynamic schema updates via LDAP")

        elif server_type == "ad":
            logger.info("   • Active Directory uses complex schema partition")
            logger.info("   • CN=Schema,CN=Configuration,DC=...")
            logger.info("   • Schema modifications require schema master role")

        else:
            logger.info("   • Generic LDAP server")
            logger.info("   • RFC 4512 compliant schema (cn=subschema)")
            logger.info("   • Standard objectClasses and attributeTypes")

    else:
        logger.warning(f"   ⚠️  Quirks integration: {result.error}")


def demonstrate_schema_search(api: FlextLdap, server_type: str | None) -> None:
    """Demonstrate schema search operations.

    Args:
        api: Connected FlextLdap instance
        server_type: Detected server type for schema DN

    """
    logger.info("\n=== Schema Search Operations ===")

    # Determine schema DN based on server type
    schema_dns = {
        "openldap1": "cn=schema",
        "openldap2": "cn=subschema",
        "oid": "cn=subschemasubentry",
        "oud": "cn=schema",
        "389ds": "cn=schema",
        "generic": "cn=subschema",
    }

    schema_dn = schema_dns.get(server_type or "generic", "cn=subschema")

    logger.info(f"\n1. Searching schema subentry: {schema_dn}")

    # Search for schema subentry
    result = api.search(
        search_base=schema_dn,
        filter_str="(objectClass=*)",
        attributes=["objectClasses", "attributeTypes", "ldapSyntaxes", "matchingRules"],
    )

    if result.is_success:
        entries = result.unwrap()

        if entries:
            entry = entries[0]
            logger.info(f"   ✅ Schema entry found: {entry.dn}")

            # Show available schema attributes
            attrs = entry.attributes
            logger.info("\n2. Available schema attributes:")

            if "objectClasses" in attrs:
                oc_count = len(attrs["objectClasses"]) if isinstance(attrs["objectClasses"], list) else 1
                logger.info(f"   • objectClasses: {oc_count} defined")

            if "attributeTypes" in attrs:
                at_count = len(attrs["attributeTypes"]) if isinstance(attrs["attributeTypes"], list) else 1
                logger.info(f"   • attributeTypes: {at_count} defined")

            if "ldapSyntaxes" in attrs:
                syntax_count = len(attrs["ldapSyntaxes"]) if isinstance(attrs["ldapSyntaxes"], list) else 1
                logger.info(f"   • ldapSyntaxes: {syntax_count} defined")

            if "matchingRules" in attrs:
                mr_count = len(attrs["matchingRules"]) if isinstance(attrs["matchingRules"], list) else 1
                logger.info(f"   • matchingRules: {mr_count} defined")

            logger.info("\n3. Schema discovery successful!")
            logger.info("   ℹ️  Schema contains complete directory metadata")

        else:
            logger.warning("   ⚠️  Schema entry not found")
            logger.info(f"   ℹ️  Server may not expose schema at {schema_dn}")

    else:
        logger.warning(f"   ⚠️  Schema search failed: {result.error}")
        logger.info("   ℹ️  Schema may not be accessible or different DN required")


def demonstrate_server_capabilities(api: FlextLdap) -> None:
    """Demonstrate server capabilities discovery.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Server Capabilities Discovery ===")

    # Get comprehensive server capabilities
    result = api.get_server_capabilities()

    if result.is_success:
        caps = result.unwrap()

        logger.info("\n✅ Server capabilities discovered:")
        logger.info(f"   Server type: {caps.get('server_type', 'unknown')}")
        logger.info(f"   ACL format: {caps.get('acl_format', 'N/A')}")
        logger.info(f"   ACL attribute: {caps.get('acl_attribute', 'N/A')}")
        logger.info(f"   Schema DN: {caps.get('schema_dn', 'N/A')}")
        logger.info(f"   Default port: {caps.get('default_port', 389)}")
        logger.info(f"   SSL port: {caps.get('default_ssl_port', 636)}")
        logger.info(f"   StartTLS support: {caps.get('supports_start_tls', False)}")
        logger.info(f"   Bind mechanisms: {caps.get('bind_mechanisms', [])}")
        logger.info(f"   Max page size: {caps.get('max_page_size', 'N/A')}")
        logger.info(f"   Paged results: {caps.get('supports_paged_results', False)}")
        logger.info(f"   VLV support: {caps.get('supports_vlv', False)}")

        logger.info("\n   ℹ️  Capabilities inform schema discovery strategy")

    else:
        logger.warning(f"   ⚠️  Capabilities discovery: {result.error}")


def main() -> int:
    """Run schema operations demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 70)
    logger.info("FLEXT-LDAP Schema Operations Example")
    logger.info("=" * 70)
    logger.info("Demonstrates: Schema discovery, server detection, quirks handling")
    logger.info("Modules: schema.py, quirks_integration.py")
    logger.info("=" * 70)

    try:
        # 1. Connect to LDAP server
        logger.info("\n1. Connecting to LDAP server...")
        api = setup_api()

        if not api:
            logger.error("Cannot proceed without connection")
            logger.info("\nℹ️  Schema operations require LDAP connection")
            return 1

        try:
            # 2. Server Type Detection
            server_type = demonstrate_server_detection(api)

            # 3. Schema Discovery
            demonstrate_schema_discovery(server_type)

            # 4. Quirks Detection
            demonstrate_quirks_detection(server_type)

            # 5. Quirks Integration
            demonstrate_quirks_integration(api, server_type)

            # 6. Schema Search
            demonstrate_schema_search(api, server_type)

            # 7. Server Capabilities
            demonstrate_server_capabilities(api)

            logger.info("\n" + "=" * 70)
            logger.info("✅ Schema operations demonstration completed!")
            logger.info("=" * 70)

            logger.info("\nKey Takeaways:")
            logger.info("  • FlextLdapSchema - Unified schema operations")
            logger.info("  • Server type detection - Automatic quirks handling")
            logger.info("  • Schema discovery - Server-specific DN resolution")
            logger.info("  • Quirks integration - Adaptation to any LDAP server")
            logger.info("  • Capabilities discovery - Complete server metadata")

            logger.info("\nSupported Server Types:")
            logger.info("  • OpenLDAP 1.x/2.x")
            logger.info("  • Oracle OID/OUD")
            logger.info("  • 389 Directory Server")
            logger.info("  • Microsoft Active Directory")
            logger.info("  • Apache Directory Server")
            logger.info("  • Generic RFC 4512 LDAP servers")

        finally:
            # Always disconnect
            if api.is_connected():
                api.unbind()
                logger.info("\nDisconnected from LDAP server")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
