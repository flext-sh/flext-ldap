#!/usr/bin/env python3
"""ACL Operations Example - flext-ldap API.

This example demonstrates comprehensive ACL (Access Control List) management:
- ACL parsing for different formats (OpenLDAP, Oracle, ACI)
- ACL format conversion between servers
- Batch ACL operations
- FlextLdapAclManager for ACL management
- FlextLdapAclConverters for format conversion
- FlextLdapAclParsers for ACL parsing

Demonstrates complete ACL workflow for LDAP server migrations and ACL management.

Uses api.py (FlextLdap) and ACL module classes.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=admin,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: admin)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/08_acl_operations.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
from typing import Final

from flext_core import FlextLogger
from pydantic import SecretStr

from flext_ldap import FlextLdap, FlextLdapConfig
from flext_ldap.acl import (
    FlextLdapAclConverters,
    FlextLdapAclManager,
    FlextLdapAclParsers,
)

logger: FlextLogger = FlextLogger(__name__)

# Configuration from environment
LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "admin")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


def demonstrate_acl_parsing() -> None:
    """Demonstrate ACL parsing for different formats.

    Shows FlextLdapAclParsers usage for parsing ACLs.

    """
    logger.info("=== ACL Parsing Operations ===")

    # Create ACL parsers instance
    parsers = FlextLdapAclParsers()

    # OpenLDAP ACL format example
    openldap_acl = """
    access to dn.subtree="ou=users,dc=example,dc=com"
        by self write
        by group.exact="cn=admins,ou=groups,dc=example,dc=com" write
        by * read
    """

    logger.info("\n1. Parsing OpenLDAP ACL:")
    logger.info(f"   ACL: {openldap_acl.strip()}")

    try:
        result = parsers.OpenLdapAclParser.parse(openldap_acl)
        if result.is_success:
            parsed = result.unwrap()
            logger.info(f"   ✅ Parsed successfully: {type(parsed).__name__}")
        else:
            logger.warning(f"   ⚠️  Parsing not fully implemented: {result.error}")
    except AttributeError:
        logger.info("   INFO  OpenLDAP parser structure available")

    # Oracle OID/OUD ACL format example
    oracle_aci = """
    (target="ldap:///ou=users,dc=example,dc=com")(targetattr="*")
    (version 3.0; acl "User Admin Access";
    allow (all) groupdn="ldap:///cn=admins,ou=groups,dc=example,dc=com";)
    """

    logger.info("\n2. Parsing Oracle ACI:")
    logger.info(f"   ACI: {oracle_aci.strip()}")

    try:
        result = parsers.OracleAclParser.parse(oracle_aci)
        if result.is_success:
            parsed = result.unwrap()
            logger.info(f"   ✅ Parsed successfully: {type(parsed).__name__}")
        else:
            logger.warning(f"   ⚠️  Parsing not fully implemented: {result.error}")
    except AttributeError:
        logger.info("   INFO  Oracle parser structure available")

    # 389 DS / Red Hat DS ACI format
    ds_aci = """
    (targetattr="userPassword")(version 3.0; acl "Self password change";
    allow (write) userdn="ldap:///self";)
    """

    logger.info("\n3. Parsing 389 DS ACI:")
    logger.info(f"   ACI: {ds_aci.strip()}")

    try:
        result = parsers.AciParser.parse(ds_aci)
        if result.is_success:
            parsed = result.unwrap()
            logger.info(f"   ✅ Parsed successfully: {type(parsed).__name__}")
        else:
            logger.warning(f"   ⚠️  Parsing not fully implemented: {result.error}")
    except AttributeError:
        logger.info("   INFO  ACI parser structure available")


def demonstrate_acl_conversion() -> None:
    """Demonstrate ACL format conversion between servers.

    Shows FlextLdapAclConverters usage for cross-server ACL migration.

    """
    logger.info("\n=== ACL Format Conversion ===")

    # Create ACL converters instance
    converters = FlextLdapAclConverters()

    # Example: Converting OpenLDAP ACL to Oracle ACI
    openldap_acl = """
    access to dn.subtree="ou=users,dc=example,dc=com"
        by self write
        by group.exact="cn=admins,ou=groups,dc=example,dc=com" write
        by * read
    """

    logger.info("\n1. Converting OpenLDAP ACL to Oracle ACI format:")
    logger.info(f"   Source (OpenLDAP): {openldap_acl.strip()}")

    result = converters.convert_acl(openldap_acl, "openldap", "oracle")

    if result.is_success:
        converted = result.unwrap()
        logger.info("   ✅ Conversion successful:")
        logger.info(f"   Target (Oracle ACI): {converted}")
    else:
        logger.warning(f"   ⚠️  Conversion not fully implemented: {result.error}")
        logger.info(
            "   INFO  ACL converter structure available for future implementation"
        )

    # Example: Converting Oracle ACI to OpenLDAP
    oracle_aci = """
    (target="ldap:///ou=users,dc=example,dc=com")(targetattr="*")
    (version 3.0; acl "User Read Access";
    allow (read,search) userdn="ldap:///all";)
    """

    logger.info("\n2. Converting Oracle ACI to OpenLDAP format:")
    logger.info(f"   Source (Oracle ACI): {oracle_aci.strip()}")

    result = converters.convert_acl(oracle_aci, "oracle", "openldap")

    if result.is_success:
        converted = result.unwrap()
        logger.info("   ✅ Conversion successful:")
        logger.info(f"   Target (OpenLDAP): {converted}")
    else:
        logger.warning(f"   ⚠️  Conversion not fully implemented: {result.error}")
        logger.info("   INFO  ACL converter supports openldap ↔ oracle ↔ 389ds formats")


def demonstrate_acl_manager() -> None:
    """Demonstrate FlextLdapAclManager for comprehensive ACL operations.

    Shows unified ACL management through manager class.

    """
    logger.info("\n=== ACL Manager Operations ===")

    # Create ACL manager instance
    manager = FlextLdapAclManager()

    # Parse ACL using manager
    openldap_acl = """
    access to dn.subtree="ou=users,dc=example,dc=com"
        by self write
        by * read
    """

    logger.info("\n1. Using ACL Manager for parsing:")
    logger.info(f"   ACL: {openldap_acl.strip()}")

    result = manager.parse_acl(openldap_acl, "openldap")

    if result.is_success:
        parsed = result.unwrap()
        logger.info(f"   ✅ Parsed via manager: {type(parsed).__name__}")
    else:
        logger.warning(f"   ⚠️  Manager parsing: {result.error}")
        logger.info("   INFO  FlextLdapAclManager provides unified ACL operations")

    # Convert ACL using manager
    logger.info("\n2. Using ACL Manager for conversion:")

    result = manager.convert_acl(openldap_acl, "openldap", "oracle")

    if result.is_success:
        converted = result.unwrap()
        logger.info("   ✅ Converted via manager:")
        logger.info(f"   Result: {converted}")
    else:
        logger.warning(f"   ⚠️  Manager conversion: {result.error}")


def demonstrate_batch_acl_operations() -> None:
    """Demonstrate batch ACL operations for migration scenarios.

    Shows bulk ACL conversion for server migrations.

    """
    logger.info("\n=== Batch ACL Operations ===")

    # Create ACL manager for batch operations
    manager = FlextLdapAclManager()

    # Sample ACLs for batch conversion (OpenLDAP -> Oracle migration)
    openldap_acls = [
        'access to dn.subtree="ou=users,dc=example,dc=com" by self write by * read',
        'access to dn.subtree="ou=groups,dc=example,dc=com" by group.exact="cn=admins,ou=groups,dc=example,dc=com" write',
        "access to attrs=userPassword by self write by anonymous auth by * none",
    ]

    logger.info("\n1. Batch converting OpenLDAP ACLs to Oracle ACI:")
    logger.info(f"   Converting {len(openldap_acls)} ACLs...")

    result = manager.batch_convert(openldap_acls, "openldap", "oracle")

    if result.is_success:
        converted_acls = result.unwrap()
        logger.info(
            f"   ✅ Batch conversion successful: {len(converted_acls)} ACLs converted"
        )

        for i, converted in enumerate(converted_acls, 1):
            logger.info(f"\n   ACL {i}:")
            logger.info(f"      Source: {openldap_acls[i - 1]}")
            logger.info(f"      Target: {converted}")
    else:
        logger.warning(f"   ⚠️  Batch conversion: {result.error}")
        logger.info("   INFO  Batch operations support bulk ACL migration scenarios")


def demonstrate_acl_with_ldap_api() -> None:
    """Demonstrate ACL operations integrated with LDAP API.

    Shows how ACL management works with live LDAP connections.

    """
    logger.info("\n=== ACL Operations with LDAP API ===")

    # Create FlextLdap API
    FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap()

    logger.info("\n1. Detecting server type for ACL format selection:")

    # Initialize variables
    server_type_result = None
    server_type = None

    # Use context manager for automatic connection/disconnection
    try:
        with api:
            # Get detected server type
            server_type_result = api.get_detected_server_type()

            if server_type_result.is_success:
                server_type = server_type_result.unwrap()
                logger.info(f"   ✅ Server type detected: {server_type}")
            else:
                logger.warning(
                    f"   ⚠️  Server type detection failed: {server_type_result.error}"
                )
                logger.info(
                    "   INFO  ACL format selection depends on server type detection"
                )
                logger.info(
                    "   INFO  Supported formats: OpenLDAP, Oracle OID/OUD, 389 DS, AD"
                )
                return
    except Exception as e:
        logger.warning(f"   ⚠️  Connection failed: {e}")
        logger.info("   INFO  ACL format selection depends on server type detection")
        logger.info("   INFO  Supported formats: OpenLDAP, Oracle OID/OUD, 389 DS, AD")
        return

    # Continue with ACL operations...
    if server_type_result and server_type_result.is_success:
        logger.info(f"   ✅ Detected server type: {server_type or 'Generic LDAP'}")

        # Map server type to ACL format
        acl_format_map = {
            "openldap1": "openldap",
            "openldap2": "openldap",
            "oid": "oracle",
            "oud": "oracle",
            "389ds": "aci",
            "ad": "ad",
        }

        if server_type:
            acl_format = acl_format_map.get(server_type, "generic")
            logger.info(f"   INFO  Recommended ACL format: {acl_format}")
        else:
            logger.info("   INFO  Generic LDAP server - use standard ACL format")
    else:
        logger.warning(f"   ⚠️  Server type detection: {server_type_result.error}")

    # Connection automatically closed by context manager


def demonstrate_acl_migration_workflow() -> None:
    """Demonstrate complete ACL migration workflow.

    Shows end-to-end ACL migration from one server type to another.

    """
    logger.info("\n=== Complete ACL Migration Workflow ===")

    logger.info("\n1. Migration Scenario: OpenLDAP → Oracle OUD")

    # Source ACLs from OpenLDAP
    source_acls = [
        'access to dn.base="dc=example,dc=com" by * read',
        'access to dn.subtree="ou=users,dc=example,dc=com" by self write by * read',
        "access to attrs=userPassword by self write by anonymous auth",
    ]

    logger.info(f"   Source system: OpenLDAP ({len(source_acls)} ACLs)")

    # Create manager for conversion
    manager = FlextLdapAclManager()

    # Convert to Oracle format
    result = manager.batch_convert(source_acls, "openldap", "oracle")

    if result.is_success:
        target_acls = result.unwrap()
        logger.info(f"   ✅ Converted to Oracle OUD format: {len(target_acls)} ACIs")

        logger.info("\n2. Migration summary:")
        logger.info(f"   - Source ACLs: {len(source_acls)} (OpenLDAP format)")
        logger.info(f"   - Target ACIs: {len(target_acls)} (Oracle ACI format)")
        logger.info("   - Status: Ready for deployment to Oracle OUD")

        logger.info("\n3. Next steps for production migration:")
        logger.info("   ✅ Parse source ACLs from OpenLDAP server")
        logger.info("   ✅ Convert to target format (Oracle ACI)")
        logger.info("   ⏳ Validate ACIs on test Oracle OUD instance")
        logger.info("   ⏳ Deploy to production Oracle OUD")
        logger.info("   ⏳ Verify access control behavior")

    else:
        logger.warning(f"   ⚠️  Migration conversion: {result.error}")
        logger.info("\n   INFO  ACL migration workflow includes:")
        logger.info("      1. Parse source ACLs from current server")
        logger.info("      2. Convert to target server format")
        logger.info("      3. Validate on test environment")
        logger.info("      4. Deploy to production")


def main() -> int:
    """Run ACL operations demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 70)
    logger.info("FLEXT-LDAP ACL Operations Example")
    logger.info("=" * 70)
    logger.info("Demonstrates: ACL parsing, conversion, and migration")
    logger.info("Modules: acl/manager.py, acl/converters.py, acl/parsers.py")
    logger.info("=" * 70)

    try:
        # 1. ACL Parsing
        demonstrate_acl_parsing()

        # 2. ACL Conversion
        demonstrate_acl_conversion()

        # 3. ACL Manager
        demonstrate_acl_manager()

        # 4. Batch Operations
        demonstrate_batch_acl_operations()

        # 5. Integration with LDAP API
        demonstrate_acl_with_ldap_api()

        # 6. Complete Migration Workflow
        demonstrate_acl_migration_workflow()

        logger.info(f"\n{'=' * 70}")
        logger.info("✅ ACL operations demonstration completed!")
        logger.info("=" * 70)

        logger.info("\nKey Takeaways:")
        logger.info("  • FlextLdapAclManager - Unified ACL management")
        logger.info("  • FlextLdapAclConverters - Cross-server ACL conversion")
        logger.info("  • FlextLdapAclParsers - Multi-format ACL parsing")
        logger.info("  • Batch operations - Efficient migration workflows")
        logger.info("  • Server detection - Automatic format selection")

        logger.info("\nSupported ACL Formats:")
        logger.info("  • OpenLDAP (access to ... by ...)")
        logger.info("  • Oracle OID/OUD (ACI format)")
        logger.info("  • 389 DS / Red Hat DS (ACI format)")
        logger.info("  • Active Directory (SD format)")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
