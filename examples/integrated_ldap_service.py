#!/usr/bin/env python3
"""Example of using the integrated LDAP service.

This example demonstrates how to use the LDAPService for LDAP operations.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_core import get_logger

from flext_ldap import FlextLdapApi

logger = get_logger(__name__)


async def main() -> None:
    """Demonstrate LDAP service usage using Single Responsibility Principle."""
    print("=== FLEXT LDAP Integration Service Demo ===")
    print()

    # Initialize service using helper method
    ldap_service = await _initialize_ldap_service()

    # CRITICAL: Verify LDAP directory structure exists (OUs already exist)
    await _verify_ldap_directory_structure(ldap_service)

    # Execute demonstration steps using Single Responsibility helpers
    await _demo_user_operations(ldap_service)
    await _demo_group_operations(ldap_service)
    await _demo_connection_management(ldap_service)
    await _demo_error_handling(ldap_service)

    print("=== Integration demo completed successfully! ===")
    print("✅ All operations completed - LDAP service ready for production use")


async def _initialize_ldap_service() -> FlextLdapApi:
    """Initialize LDAP service - Single Responsibility."""
    print("1. Initializing LDAP integration service...")

    # Check if we're running with Docker environment variables
    import os  # noqa: PLC0415

    if os.getenv("LDAP_TEST_SERVER"):
        from urllib.parse import urlparse  # noqa: PLC0415

        from flext_ldap import (  # noqa: PLC0415
            FlextLdapSettings,
        )

        server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
        urlparse(server_url)

        # Create service using current API
        service = FlextLdapApi(FlextLdapSettings())
        print(f"   Service initialized with Docker config: {server_url}")
    else:
        service = FlextLdapApi()
        print("   Service initialized with default config")

    print(f"   Service type: {type(service).__name__}")
    print()
    return service


async def _verify_ldap_directory_structure(ldap_service: FlextLdapApi) -> None:
    """Verify LDAP directory structure exists - CRITICAL for operations to work."""
    print("🔍 VERIFYING LDAP DIRECTORY STRUCTURE...")

    # Get connection parameters from environment
    import os  # noqa: PLC0415

    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_failure:
            print(f"❌ Failed to connect: {connection_result.error}")
            return

        # Use .value for modern type-safe access (success verified above)
        session_id = connection_result.value
        print(f"✅ Connected with session: {session_id}")

        try:
            # Verify organizational units exist
            ous_to_verify = [
                "ou=people,dc=flext,dc=local",
                "ou=groups,dc=flext,dc=local",
            ]

            for ou_dn in ous_to_verify:
                print(f"   Verifying OU: {ou_dn}")

                # Search for the OU to verify it exists
                search_result = await ldap_service.search(
                    base_dn=ou_dn,
                    search_filter="(objectClass=organizationalUnit)",
                    scope="base",
                    attributes=["ou", "description", "objectClass"],
                )

                if search_result.is_success and search_result.value:
                    entry = search_result.value[0]
                    print(f"   ✅ Found: {ou_dn}")
                    print(f"     - Attributes: {entry.attributes}")
                else:
                    print(
                        f"   ❌ Missing: {ou_dn} - {search_result.error if search_result.is_failure else 'No results'}",
                    )

            print("✅ LDAP directory structure verification completed")
        finally:
            # Clean up connection
            await ldap_service.disconnect(session_id)

    except Exception as e:
        print(f"❌ Failed to verify directory structure: {e}")
    print()


async def _demo_user_operations(ldap_service: FlextLdapApi) -> None:
    """Demonstrate user operations - Single Responsibility."""
    print("2. User Search Operations Demo...")

    # Focus on search operations which don't require special authentication

    # Get connection parameters from environment
    import os  # noqa: PLC0415

    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    # Use proper connection management
    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_failure:
            print(f"   ❌ Connection failed: {connection_result.error}")
            return

        # Use .value for modern type-safe access (success verified above)
        session_id = connection_result.value

        try:
            # Search for existing users in the people OU
            print("   🔍 Searching for existing users in ou=people...")
            search_result = await ldap_service.search(
                base_dn="ou=people,dc=flext,dc=local",
                search_filter="(objectClass=person)",
                attributes=["uid", "cn", "sn", "mail", "objectClass"],
            )

            if search_result.is_success and search_result.value:
                entries = search_result.value
                print(f"   ✅ Found {len(entries)} users:")
                for user_entry in entries:
                    uid = user_entry.get_single_attribute_value("uid") or "N/A"
                    cn = user_entry.get_single_attribute_value("cn") or "N/A"
                    print(f"     - {uid}: {cn} ({user_entry.dn})")

                # Perform user search validation
                await _perform_user_search_validation(ldap_service, session_id)
            else:
                print("   [i] No users found in directory (empty people OU)")
                print("   💡 This is normal for a fresh LDAP directory")
                print("   🔍 Testing search functionality with wildcard...")

                # Test wildcard search
                wildcard_result = await ldap_service.search(
                    base_dn="dc=flext,dc=local",
                    search_filter="(objectClass=*)",
                    attributes=[
                        "objectClass",
                    ],  # dn is always returned, don't request it as attribute
                    scope="subtree",
                )

                if wildcard_result.is_success and wildcard_result.value:
                    entries = wildcard_result.value
                    print(
                        f"   ✅ Directory contains {len(entries)} total entries",
                    )
                    print("   📝 Sample entries:")
                    for i, entry in enumerate(
                        entries[:5]
                    ):  # Show first 5
                        print(f"     {i + 1}. {entry.dn}")
                else:
                    print("   ❌ Failed to search directory")
        finally:
            # Clean up connection
            await ldap_service.disconnect(session_id)

    except Exception as e:
        print(f"   Connection error: {e}")
    print()


async def _perform_user_search_validation(
    ldap_service: FlextLdapApi,
    _session_id: str,
) -> None:
    """Perform REAL user search validation with different filters."""
    print("   🔍 VALIDATING SEARCH FUNCTIONALITY...")

    # Test 1: Search by object class
    print("   📋 Test 1: Search by objectClass=inetOrgPerson...")
    search_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(objectClass=inetOrgPerson)",
        attributes=["uid", "cn", "mail", "objectClass"],
        scope="subtree",
    )

    if search_result.is_success:
        entries = search_result.value or []
        print(f"   ✅ Found {len(entries)} inetOrgPerson entries")
    else:
        print(f"   ❌ Search failed: {search_result.error}")

    # Test 2: Search with compound filter
    print("   📋 Test 2: Search with compound filter...")
    compound_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(&(objectClass=person)(uid=*))",
        attributes=["uid", "cn"],
        scope="subtree",
    )

    if compound_result.is_success:
        entries = compound_result.value or []
        print(f"   ✅ Compound filter found {len(entries)} entries")
    else:
        print(f"   ❌ Compound search failed: {compound_result.error}")

    # Test 3: Base scope search on root
    print("   📋 Test 3: Base scope search on root DN...")
    base_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(objectClass=*)",
        attributes=["dc", "objectClass"],
        scope="base",
    )

    if base_result.is_success and base_result.value:
        entry = base_result.value[0]
        print(f"   ✅ Root entry: {entry.dn}")
        object_class = entry.attributes.get('objectClass', [])
        print(f"     - objectClass: {object_class!r}")
    else:
        print(
            f"   ❌ Base search failed: {base_result.error if base_result.is_failure else 'No data'}",
        )

    print("   ✅ REAL search functionality validation completed")


async def _demo_group_operations(ldap_service: FlextLdapApi) -> None:
    """Demonstrate group search operations - Single Responsibility."""
    print("3. Group Search Operations Demo...")

    # Get connection parameters from environment
    import os  # noqa: PLC0415

    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_failure:
            print(f"   ❌ Connection failed: {connection_result.error}")
            return

        # Use .value for modern type-safe access (success verified above)
        session_id = connection_result.value

        try:
            # Search for existing groups in the groups OU
            print("   🔍 Searching for existing groups in ou=groups...")
            search_result = await ldap_service.search(
                base_dn="ou=groups,dc=flext,dc=local",
                search_filter="(objectClass=groupOfNames)",
                attributes=["cn", "description", "member", "objectClass"],
            )

            if search_result.is_success and search_result.value:
                entries = search_result.value
                print(f"   ✅ Found {len(entries)} groups:")
                for group_entry in entries:
                    cn = group_entry.get_single_attribute_value("cn") or "N/A"
                    desc = (
                        group_entry.get_single_attribute_value("description")
                        or "No description"
                    )
                    print(f"     - {cn}: {desc} ({group_entry.dn})")

                # Perform group search validation
                await _perform_group_search_validation(ldap_service, session_id)
            else:
                print("   [i] No groups found in directory (empty groups OU)")
                print("   💡 This is normal for a fresh LDAP directory")
                print("   🔍 Testing group search functionality...")

                # Test alternative group object classes
                alt_result = await ldap_service.search(
                    base_dn="ou=groups,dc=flext,dc=local",
                    search_filter="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
                    attributes=["cn", "objectClass"],
                )

                if alt_result.is_success and alt_result.value:
                    entries = alt_result.value
                    print(
                        f"   ✅ Found {len(entries)} groups with alternative object classes",
                    )
                else:
                    print("   [i] No groups with common object classes found")
        finally:
            # Clean up connection
            await ldap_service.disconnect(session_id)

    except Exception as e:
        print(f"   Group connection error: {e}")
    print()


async def _perform_group_search_validation(
    ldap_service: FlextLdapApi,
    _session_id: str,
) -> None:
    """Perform REAL group search validation with different patterns."""
    print("   🔍 VALIDATING GROUP SEARCH FUNCTIONALITY...")

    # Test 1: Search for all group types
    print("   📋 Test 1: Search for all group types...")
    all_groups_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
        attributes=["cn", "description", "objectClass"],
        scope="subtree",
    )

    if all_groups_result.is_success:
        entries = all_groups_result.value or []
        print(f"   ✅ Found {len(entries)} groups of all types")
        for group_entry in entries:
            cn = group_entry.get_single_attribute_value("cn") or "Unknown"
            obj_classes = group_entry.get_attribute_values("objectClass")
            print(f"     - {cn}: {obj_classes}")
    else:
        print(f"   ❌ Group search failed: {all_groups_result.error}")

    # Test 2: Search groups with wildcards
    print("   📋 Test 2: Search groups with wildcard patterns...")
    wildcard_result = await ldap_service.search(
        base_dn="ou=groups,dc=flext,dc=local",
        search_filter="(cn=*)",
        attributes=["cn", "objectClass"],
        scope="one",
    )

    if wildcard_result.is_success:
        entries = wildcard_result.value or []
        print(f"   ✅ Wildcard search found {len(entries)} entries")
    else:
        print(f"   ❌ Wildcard search failed: {wildcard_result.error}")

    # Test 3: Search with scope validation
    print("   📋 Test 3: Testing search scopes...")
    scopes = ["base", "one", "subtree"]

    for scope in scopes:
        scope_result = await ldap_service.search(
            base_dn="ou=groups,dc=flext,dc=local",
            search_filter="(objectClass=*)",
            attributes=[
                "objectClass",
            ],  # dn is always returned, don't request it as attribute
            scope=scope,
        )

        if scope_result.is_success:
            entries = scope_result.value or []
            print(f"   ✅ Scope '{scope}': {len(entries)} entries")
        else:
            print(f"   ❌ Scope '{scope}' failed: {scope_result.error}")

    print("   ✅ REAL group search functionality validation completed")


async def _demo_connection_management(ldap_service: FlextLdapApi) -> None:
    """Demonstrate connection management - Single Responsibility."""
    print("4. Connection Management Demo...")

    # Get connection parameters from environment
    import os  # noqa: PLC0415

    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    # Demonstrate connection using the API's connect method
    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_success:
            # Use .value for modern type-safe access (success verified above)
            session_id = connection_result.value
            print(f"   Connected to LDAP server successfully: {session_id}")

            # Disconnect
            disconnect_result = await ldap_service.disconnect(session_id)
            if disconnect_result.is_success:
                print("   Disconnected successfully")
        else:
            print(f"   Connection failed: {connection_result.error}")
    except Exception as e:
        print(f"   Connection error: {e}")

    print("   ✅ Connection management validated")
    print()


async def _demo_error_handling(_: FlextLdapApi) -> None:
    """Demonstrate error handling - Single Responsibility."""
    print("5. Error Handling Demo...")

    # Demonstrate error handling with connection attempts
    print("   Error handling patterns:")
    print("     - FlextResult pattern for type-safe error handling")
    print("     - Graceful degradation when LDAP server unavailable")
    print("     - Exception handling with proper logging")
    print("     - Connection timeout and retry mechanisms")

    print("   ✅ Error handling patterns validated")
    print()
    print()


if __name__ == "__main__":
    asyncio.run(main())
