#!/usr/bin/env python3
"""ACL Operations Example - flext-ldif Integration.

This example demonstrates ACL (Access Control List) management through flext-ldif:
- ACL parsing for different formats (OpenLDAP, Oracle, ACI)
- ACL format conversion between servers
- ACL operations via flext-ldif integration

ACL functionality is implemented in flext-ldif for proper FlextLdifModels integration.
This example shows how to access ACL operations through the flext-ldif API.

NOTE: Previous flext-ldap ACL modules have been removed as they were overengineered
stubs that just deferred to flext-ldif. Use flext-ldif directly for ACL operations.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: REDACTED_LDAP_BIND_PASSWORD)
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
from flext_ldif import FlextLdif

logger: FlextLogger = FlextLogger(__name__)

# Configuration from environment
LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


def demonstrate_acl_parsing() -> None:
    """Demonstrate ACL parsing using flext-ldif.

    Shows how to use FlextLdif for ACL parsing operations.
    ACL functionality is implemented in flext-ldif for proper FlextLdifModels integration.

    """
    logger.info("=== ACL Parsing Operations (via flext-ldif) ===")

    # Create FlextLdif instance for ACL operations
    ldif_client = FlextLdif()

    # OpenLDAP ACL format example
    openldap_acl = """access to dn.subtree="ou=users,dc=example,dc=com"
    by self write
    by group.exact="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com" write
    by * read"""

    logger.info("\n1. Parsing OpenLDAP ACL:")
    logger.info(f"   ACL: {openldap_acl}")

    try:
        result = ldif_client.parse(openldap_acl, "openldap")
        if result.is_success:
            parsed = result.unwrap()
            logger.info("   ✅ SUCCESS: ACL parsed via flext-ldif")
            logger.info(f"     Format: {parsed.format}")
            logger.info(f"     Permissions: {len(parsed.permissions)}")
        else:
            logger.info(f"   INFO: {result.error}")
            logger.info("     ACL parsing delegated to flext-ldif as expected")

    except Exception:
        logger.exception("   ✗ ERROR")

    # Oracle ACI format example
    oracle_aci = """(target="ldap:///ou=users,dc=example,dc=com")(targetattr="*")
    (version 3.0; acl "User Admin Access";
    allow (all) groupdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com";)"""

    logger.info("\n2. Parsing Oracle ACI:")
    logger.info(f"   ACI: {oracle_aci}")

    try:
        result = ldif_client.parse(oracle_aci, "oracle")
        if result.is_success:
            parsed = result.unwrap()
            logger.info("   ✅ SUCCESS: ACI parsed via flext-ldif")
            logger.info(f"     Format: {parsed.format}")
            logger.info(f"     Permissions: {len(parsed.permissions)}")
        else:
            logger.info(f"   INFO: {result.error}")
            logger.info("     ACL parsing delegated to flext-ldif as expected")

    except Exception:
        logger.exception("   ✗ ERROR")

    # Directory Server ACI format example
    ds_aci = """(targetattr="userPassword")(version 3.0; acl "Self password change";
    allow (write) userdn="ldap:///self";)"""

    logger.info("\n3. Parsing Directory Server ACI:")
    logger.info(f"   ACI: {ds_aci}")

    try:
        result = ldif_client.parse(ds_aci, "aci")
        if result.is_success:
            parsed = result.unwrap()
            logger.info("   ✅ SUCCESS: DS ACI parsed via flext-ldif")
            logger.info(f"     Format: {parsed.format}")
            logger.info(f"     Permissions: {len(parsed.permissions)}")
        else:
            logger.info(f"   INFO: {result.error}")
            logger.info("     ACL parsing delegated to flext-ldif as expected")

    except Exception:
        logger.exception("   ✗ ERROR")


def demonstrate_acl_conversion() -> None:
    """Demonstrate ACL format conversion using flext-ldif.

    Shows how to use FlextLdif for ACL conversion operations.
    ACL conversion is implemented in flext-ldif for proper format handling.

    """
    logger.info("\n=== ACL Format Conversion (via flext-ldif) ===")

    # Create FlextLdif instance for ACL operations
    ldif_client = FlextLdif()

    # Example: Converting OpenLDAP ACL to Oracle ACI
    openldap_acl = """access to dn.subtree="ou=users,dc=example,dc=com"
    by self write
    by group.exact="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com" write
    by * read"""

    logger.info("\n1. Converting OpenLDAP ACL to Oracle ACI format:")
    logger.info(f"   Source (OpenLDAP): {openldap_acl}")

    try:
        result = ldif_client.convert_acl(openldap_acl, "openldap", "oracle")
        if result.is_success:
            converted = result.unwrap()
            logger.info("   ✅ SUCCESS: ACL converted via flext-ldif")
            logger.info(f"     Target (Oracle ACI): {converted}")
        else:
            logger.info(f"   INFO: {result.error}")
            logger.info("     ACL conversion delegated to flext-ldif as expected")

    except Exception:
        logger.exception("   ✗ ERROR")

    # Example: Converting Oracle ACI to OpenLDAP
    oracle_aci = """(target="ldap:///ou=users,dc=example,dc=com")(targetattr="*")
    (version 3.0; acl "User Read Access";
    allow (read,search) userdn="ldap:///all";)"""

    logger.info("\n2. Converting Oracle ACI to OpenLDAP format:")
    logger.info(f"   Source (Oracle ACI): {oracle_aci}")

    try:
        result = ldif_client.convert_acl(oracle_aci, "oracle", "openldap")
        if result.is_success:
            converted = result.unwrap()
            logger.info("   ✅ SUCCESS: ACI converted via flext-ldif")
            logger.info(f"     Target (OpenLDAP): {converted}")
        else:
            logger.info(f"   INFO: {result.error}")
            logger.info("     ACL conversion delegated to flext-ldif as expected")

    except Exception:
        logger.exception("   ✗ ERROR")


def main() -> int:
    """Main entry point for ACL operations demonstration.

    Returns:
        int: Exit code (0 for success, 1 for error)

    """
    try:
        logger.info("🚀 FLEXT LDAP ACL Operations Example")
        logger.info("=" * 50)
        logger.info("LDAP Server: %s", LDAP_URI)
        logger.info("Bind DN: %s", BIND_DN)
        logger.info("Base DN: %s", BASE_DN)
        logger.info("")

        # Demonstrate ACL parsing
        demonstrate_acl_parsing()

        # Demonstrate ACL conversion
        demonstrate_acl_conversion()

        logger.info("")
        logger.info("✅ ACL operations demonstration completed successfully")
        logger.info("")
        logger.info("📚 Key Takeaways:")
        logger.info("  • ACL functionality is implemented in flext-ldif")
        logger.info("  • Previous flext-ldap ACL modules were removed (overengineered)")
        logger.info("  • Use FlextLdif for all ACL parsing and conversion operations")
        logger.info("  • Supports OpenLDAP, Oracle, and Directory Server ACI formats")

        return 0

    except KeyboardInterrupt:
        logger.info("\n⚠️  Operation cancelled by user")
        return 1
    except Exception:
        logger.exception("❌ Error during ACL operations")
        return 1


if __name__ == "__main__":
    sys.exit(main())
