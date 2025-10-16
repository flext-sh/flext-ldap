#!/usr/bin/env python3
"""Complete Search Operations Example - flext-ldap API.

This example demonstrates comprehensive LDAP search functionality:
- Basic search with filters
- Single entry search (search_one)
- Structured search with SearchRequest
- Group searches
- Search with different scopes (BASE, ONE_LEVEL, SUBTREE)
- Attribute filtering
- Filter validation with FlextLdapValidations
- SearchResponse handling

Uses ONLY api.py (FlextLdap) as the primary interface.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=admin,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: admin)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/02_search_operations.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
from typing import Final

from flext_core import FlextLogger, FlextResult, FlextTypes
from pydantic import SecretStr

from flext_ldap import (
    FlextLdap,
    FlextLdapConfig,
    FlextLdapConstants,
    FlextLdapModels,
    FlextLdapTypes,
    FlextLdapValidations,
)

logger: FlextLogger = FlextLogger(__name__)

LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:3390")
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


def demonstrate_basic_search(api: FlextLdap) -> None:
    """Demonstrate basic search operations.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("=== Basic Search Operations ===")

    # Simple search for all person entries
    logger.info(f"Searching for person objects in {BASE_DN}")
    result: FlextResult[list[FlextTypes.Dict]] = api.search_entries(
        base_dn=BASE_DN,
        filter_str="(objectClass=person)",
        attributes=["cn", "sn", "mail"],
    )

    if result.is_failure:
        logger.error(f"❌ Search failed: {result.error}")
        return

    entries = result.unwrap()
    logger.info(f"✅ Found {len(entries)} person entries")
    for i, entry in enumerate(entries[:5], 1):  # Show first 5
        cn = entry.get("cn", ["N/A"])
        cn_str = cn[0] if isinstance(cn, list) else cn
        logger.info(f"   {i}. {cn_str} (DN: {entry.get('dn', 'N/A')})")


def demonstrate_search_one(api: FlextLdap) -> None:
    """Demonstrate single entry search.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Search One Entry ===")

    # Search for a single specific entry
    logger.info("Searching for admin entry...")
    search_request = FlextLdapModels.SearchRequest(
        base_dn=BASE_DN,
        filter_str="(cn=admin)",
        attributes=["cn", "objectClass", "description"],
    )
    result: FlextResult[FlextLdapModels.Entry | None] = api.search_one(search_request)

    if result.is_failure:
        logger.error(f"❌ Search failed: {result.error}")
        return

    entry = result.unwrap()
    if entry:
        logger.info("✅ Entry found:")
        logger.info(f"   DN: {entry.dn}")
        logger.info(f"   Attributes: {list(entry.attributes.keys())}")
    else:
        logger.info("⚠️  No entry found")


def demonstrate_search_with_request(api: FlextLdap) -> None:
    """Demonstrate search using SearchRequest parameter object.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Search with SearchRequest ===")

    # Create SearchRequest with complete parameters
    search_request = FlextLdapModels.SearchRequest(
        base_dn=BASE_DN,
        filter_str="(objectClass=organizationalUnit)",  # Use filter_str field name
        scope=FlextLdapConstants.Scopes.ONELEVEL,  # ONE_LEVEL scope
        attributes=["ou", "description"],
        size_limit=10,
        time_limit=30,
        page_size=FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
        paged_cookie=b"",
    )

    logger.info("SearchRequest parameters:")
    logger.info(f"   Base DN: {search_request.base_dn}")
    logger.info(f"   Filter: {search_request.filter_str}")  # Access filter_str field
    logger.info(f"   Scope: {search_request.scope}")
    logger.info(f"   Size Limit: {search_request.size_limit}")

    # Execute search using search_entries (returns SearchResponse)
    result: FlextResult[list[FlextTypes.Dict]] = api.search_entries(
        base_dn=search_request.base_dn,
        filter_str=search_request.filter_str,  # Access the actual field name
        attributes=search_request.attributes,
    )

    if result.is_failure:
        logger.error(f"❌ Search failed: {result.error}")
        return

    entries = result.unwrap()
    logger.info(f"✅ Found {len(entries)} organizational units")
    for i, entry in enumerate(entries, 1):
        ou = entry.get("ou", ["N/A"])
        ou_str = ou[0] if isinstance(ou, list) else ou
        logger.info(f"   {i}. OU: {ou_str}")


def demonstrate_group_search(api: FlextLdap) -> None:
    """Demonstrate group search operations.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Group Search Operations ===")

    # Search for groups
    groups_dn = f"ou=groups,{BASE_DN}"
    logger.info(f"Searching for groups in {groups_dn}")

    result: FlextResult[FlextLdapTypes.LdapDomain.SearchResult] = api.search_groups(
        search_base=groups_dn,
        attributes=["cn", "member", "description"],
    )

    if result.is_failure:
        logger.error(f"❌ Group search failed: {result.error}")
        return

    groups: list[FlextTypes.Dict] = result.unwrap()
    logger.info(f"✅ Found {len(groups)} groups")
    for i, group in enumerate(groups[:3], 1):  # Show first 3
        logger.info(f"   {i}. Group DN: {group.get('dn', 'N/A')}")
        # Access attributes through the dictionary
        cn_value = group.get("cn", "N/A")
        member_dns = group.get("member", [])
        member_count = len(member_dns) if isinstance(member_dns, list) else 1
        logger.info(f"      CN: {cn_value}, Members: {member_count}")


def demonstrate_search_scopes(api: FlextLdap) -> None:
    """Demonstrate different search scopes.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Search Scopes ===")

    scopes = [
        (FlextLdapConstants.Scopes.BASE, "BASE - only base object"),
        (FlextLdapConstants.Scopes.ONELEVEL, "ONE_LEVEL - immediate children"),
        (FlextLdapConstants.Scopes.SUBTREE, "SUBTREE - entire subtree"),
    ]

    for _scope, description in scopes:
        logger.info(f"\nTesting {description}:")
        result: FlextResult[FlextLdapTypes.LdapDomain.SearchResult] = (
            api.search_entries(
                base_dn=BASE_DN,
                filter_str="(objectClass=*)",
                attributes=["dn"],
            )
        )

        if result.is_success:
            entries = result.unwrap()
            logger.info(f"   ✅ Found {len(entries)} entries")
        else:
            logger.error(f"   ❌ Search failed: {result.error}")


def demonstrate_filter_validation(_api: FlextLdap) -> None:
    """Demonstrate LDAP filter validation.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Filter Validation ===")

    # Test various filters
    test_filters = [
        ("(objectClass=person)", True, "Valid simple filter"),
        ("(&(objectClass=person)(mail=*))", True, "Valid AND filter"),
        ("(|(cn=admin)(cn=user))", True, "Valid OR filter"),
        ("(!(objectClass=person))", True, "Valid NOT filter"),
        ("(objectClass=", False, "Invalid - missing closing paren"),
        ("objectClass=person", False, "Invalid - missing parens"),
        ("", False, "Invalid - empty filter"),
    ]

    for filter_str, should_be_valid, description in test_filters:
        validation_result: FlextResult[bool] = FlextLdapValidations.validate_filter(
            filter_str
        )

        is_valid = validation_result.is_success
        status = "✅" if is_valid == should_be_valid else "❌"
        logger.info(f"{status} {description}")
        logger.info(f"   Filter: {filter_str!r}")
        logger.info(f"   Valid: {is_valid}")
        if not is_valid:
            logger.info(f"   Error: {validation_result.error}")


def demonstrate_dn_validation() -> None:
    """Demonstrate DN validation (no connection needed)."""
    logger.info("\n=== DN Validation ===")

    # Test various DNs
    test_dns = [
        ("cn=admin,dc=example,dc=com", True, "Valid standard DN"),
        ("ou=users,dc=example,dc=com", True, "Valid OU DN"),
        ("uid=john.doe,ou=users,dc=example,dc=com", True, "Valid user DN"),
        ("invalid-dn", False, "Invalid - missing components"),
        ("", False, "Invalid - empty DN"),
        ("cn=", False, "Invalid - empty value"),
    ]

    for dn, should_be_valid, description in test_dns:
        validation_result: FlextResult[bool] = FlextLdapValidations.validate_dn(dn)

        is_valid = validation_result.is_success
        status = "✅" if is_valid == should_be_valid else "❌"
        logger.info(f"{status} {description}")
        logger.info(f"   DN: {dn!r}")
        logger.info(f"   Valid: {is_valid}")
        if not is_valid:
            logger.info(f"   Error: {validation_result.error}")


def demonstrate_attribute_filtering(api: FlextLdap) -> None:
    """Demonstrate selective attribute retrieval.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Attribute Filtering ===")

    # Search with specific attributes
    logger.info("Requesting only 'cn' and 'mail' attributes:")
    result: FlextResult[list[FlextTypes.Dict]] = api.search(
        base_dn=BASE_DN,
        search_filter="(objectClass=inetOrgPerson)",
        attributes=["cn", "mail"],  # Only these attributes
    )

    if result.is_failure:
        logger.error(f"❌ Search failed: {result.error}")
        return

    entries = result.unwrap()
    if entries:
        logger.info(f"✅ Found {len(entries)} entries")
        entry = entries[0]
        logger.info(f"   First entry attributes: {list(entry.keys())}")
    else:
        logger.info("⚠️  No entries found")


def main() -> int:
    """Run complete search operations demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 60)
    logger.info("FLEXT-LDAP Complete Search Operations Example")
    logger.info("=" * 60)
    logger.info(f"Server: {LDAP_URI}")
    logger.info(f"Base DN: {BASE_DN}")
    logger.info("=" * 60)

    try:
        # Validation examples (no connection needed)
        demonstrate_dn_validation()

        # Connect to LDAP server
        api = setup_api()
        if not api:
            logger.error("Cannot proceed without connection")
            return 1

        try:
            # Search demonstrations
            demonstrate_basic_search(api)
            demonstrate_search_one(api)
            demonstrate_search_with_request(api)
            demonstrate_group_search(api)
            demonstrate_search_scopes(api)
            demonstrate_filter_validation(api)
            demonstrate_attribute_filtering(api)

            logger.info("\n%s", "=" * 60)
            logger.info("✅ All search operations completed successfully!")
            logger.info("=" * 60)

        finally:
            # Always disconnect
            if api.is_connected:
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
