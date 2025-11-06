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
    LDAP_BIND_DN: Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: REDACTED_LDAP_BIND_PASSWORD)
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
from pydantic import SecretStr

from flext_ldap import (
    FlextLdapConfig,
    FlextLdapQuirksIntegration,
    FlextLdapSchema,
)
from flext_ldap.services.clients import FlextLdapClients

logger: FlextLogger = FlextLogger(__name__)

# Configuration from environment
LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


def setup_client() -> FlextLdapClients | None:
    """Configure and connect a FlextLdapClients instance."""
    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )

    client = FlextLdapClients(config)
    connect_result = client.connect(
        server_uri=LDAP_URI,
        bind_dn=BIND_DN,
        password=BIND_PASSWORD,
    )

    if connect_result.is_failure:
        logger.error("❌ Connection failed: %s", connect_result.error)
        return None

    return client


def demonstrate_server_detection(client: FlextLdapClients) -> str | None:
    """Demonstrate automatic server type detection with schema awareness."""
    logger.info("=== Server Type Detection ===")

    server_type = client.server_type

    if server_type:
        logger.info(f"✅ Detected server type: {server_type}")

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
        logger.info(f"   ℹ Expected for {server_type}: {expected}")

    else:
        logger.warning(f"   ⚠️  Schema subentry discovery: {result.error}")
        logger.info("   ℹ Using default: cn=subschema (RFC 4512)")


def demonstrates_detection(server_type: str | None) -> None:
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
    servers = detector.get_servers(server_type)

    if servers:
        logger.info("   ✅ Server quirks detected:")
        logger.info(f"      Server type: {servers.server_type}")
        logger.info(f"      Case-sensitive DNs: {servers.case_sensitive_dns}")
        logger.info(
            f"      Case-sensitive attributes: {servers.case_sensitive_attributes}"
        )
        logger.info(f"      Paged results: {servers.supports_paged_results}")
        logger.info(f"      VLV support: {servers.supports_vlv}")
        logger.info(f"      Max page size: {servers.max_page_size}")
        logger.info(f"      Default timeout: {servers.default_timeout}s")
        logger.info(f"      StartTLS: {servers.supports_start_tls}")
        logger.info(f"      Explicit bind required: {servers.requires_explicit_bind}")
    else:
        logger.warning("   ⚠️  No quirks detected (using defaults)")


def demonstrates_integration(server_type: str | None) -> None:
    """Demonstrate FlextLdapQuirksIntegration usage.

    Args:
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


def demonstrate_schema_search(
    client: FlextLdapClients, server_type: str | None
) -> None:
    """Demonstrate schema search operations.

    Args:
        client: Connected FlextLdapClients instance
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

    # Search for schema subentry using clients API
    search_result = client.search(
        base_dn=schema_dn,
        filter_str="(objectClass=*)",
        attributes=[
            "objectClasses",
            "attributeTypes",
            "ldapSyntaxes",
            "matchingRules",
        ],
        scope="BASE",
    )

    if search_result.is_success:
        entries = search_result.unwrap()

        if entries:
            entry = entries[0]
            logger.info(f"   ✅ Schema entry found: {entry.dn}")

            # Show available schema attributes (use additional_attributes)
            attrs = entry.additional_attributes
            logger.info("\n2. Available schema attributes:")

            if "objectClasses" in attrs:
                oc_count = (
                    len(attrs["objectClasses"])
                    if isinstance(attrs["objectClasses"], list)
                    else 1
                )
                logger.info(f"   • objectClasses: {oc_count} defined")

            if "attributeTypes" in attrs:
                at_count = (
                    len(attrs["attributeTypes"])
                    if isinstance(attrs["attributeTypes"], list)
                    else 1
                )
                logger.info(f"   • attributeTypes: {at_count} defined")

            if "ldapSyntaxes" in attrs:
                syntax_count = (
                    len(attrs["ldapSyntaxes"])
                    if isinstance(attrs["ldapSyntaxes"], list)
                    else 1
                )
                logger.info(f"   • ldapSyntaxes: {syntax_count} defined")

            if "matchingRules" in attrs:
                mr_count = (
                    len(attrs["matchingRules"])
                    if isinstance(attrs["matchingRules"], list)
                    else 1
                )
                logger.info(f"   • matchingRules: {mr_count} defined")

            logger.info("\n3. Schema discovery successful!")
            logger.info("   ℹ Schema contains complete directory metadata")

        else:
            logger.warning("   ⚠️  Schema entry not found")
            logger.info(f"   ℹ Server may not expose schema at {schema_dn}")

    else:
        logger.warning(f"   ⚠️  Schema search failed: {search_result.error}")
        logger.info("   ℹ Schema may not be accessible or different DN required")


def demonstrate_server_capabilities(client: FlextLdapClients) -> None:
    """Demonstrate server capabilities discovery.

    Args:
        client: Connected FlextLdapClients instance

    """
    logger.info("\n=== Server Capabilities Discovery ===")

    # Get comprehensive server capabilities
    result = client.get_server_capabilities()

    if result.is_success:
        caps = result.unwrap()

        logger.info("\n✅ Server capabilities discovered:")
        # ServerCapabilities is a Pydantic model, access attributes directly

        logger.info(f"   SSL support: {caps.supports_ssl}")
        logger.info(f"   StartTLS support: {caps.supports_starttls}")
        logger.info(f"   Max page size: {caps.max_page_size}")
        logger.info(f"   Paged results: {caps.supports_paged_results}")
        logger.info(f"   VLV support: {caps.supports_vlv}")
        logger.info(f"   SASL support: {caps.supports_sasl}")

        logger.info("\n   ℹ Capabilities inform schema discovery strategy")

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
        client = setup_client()

        if not client:
            logger.error("Cannot proceed without connection")
            logger.info("\nℹ Schema operations require LDAP connection")
            return 1

        try:
            # 2. Server Type Detection
            server_type = demonstrate_server_detection(client)

            # 3. Schema Discovery
            demonstrate_schema_discovery(server_type)

            # 4. Quirks Detection
            demonstrates_detection(server_type)

            # 5. Quirks Integration
            demonstrates_integration(server_type)

            # 6. Schema Search
            demonstrate_schema_search(client, server_type)

            # 7. Server Capabilities
            demonstrate_server_capabilities(client)

            logger.info(f"\n{'=' * 70}")
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
            if client.is_connected:
                unbind_result = client.unbind()
                if hasattr(unbind_result, "is_failure") and unbind_result.is_failure:
                    logger.warning("Disconnect error: %s", unbind_result.error)
                else:
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
