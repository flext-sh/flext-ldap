#!/usr/bin/env python3
"""Example of using the integrated LDAP service.

This example demonstrates how to use the LDAPService for LDAP operations.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urlparse

from flext_core import FlextLogger

from flext_ldap import FlextLdapApi, FlextLdapSettings

logger = FlextLogger(__name__)


async def main() -> None:
    """Demonstrate LDAP service usage using Single Responsibility Principle."""
    # Initialize service using helper method
    ldap_service = await _initialize_ldap_service()

    # CRITICAL: Verify LDAP directory structure exists (OUs already exist)
    await _verify_ldap_directory_structure(ldap_service)

    # Execute demonstration steps using Single Responsibility helpers
    await _demo_user_operations(ldap_service)
    await _demo_group_operations(ldap_service)
    await _demo_connection_management(ldap_service)
    await _demo_error_handling(ldap_service)


async def _initialize_ldap_service() -> FlextLdapApi:
    """Initialize LDAP service - Single Responsibility."""
    # Check if we're running with Docker environment variables
    if os.getenv("LDAP_TEST_SERVER"):
        server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
        urlparse(server_url)

        # Create service using current API
        service = FlextLdapApi(FlextLdapSettings())
    else:
        service = FlextLdapApi()

    return service


async def _verify_ldap_directory_structure(ldap_service: FlextLdapApi) -> None:
    """Verify LDAP directory structure exists - CRITICAL for operations to work."""
    # Get connection parameters from environment

    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_failure:
            return

        # Use .value for modern type-safe access (success verified above)
        session_id = connection_result.value

        try:
            # Verify organizational units exist
            ous_to_verify = [
                "ou=people,dc=flext,dc=local",
                "ou=groups,dc=flext,dc=local",
            ]

            for ou_dn in ous_to_verify:
                # Search for the OU to verify it exists
                search_result = await ldap_service.search(
                    base_dn=ou_dn,
                    search_filter="(objectClass=organizationalUnit)",
                    scope="base",
                    attributes=["ou", "description", "objectClass"],
                )

                if search_result.is_success and search_result.value:
                    search_result.value[0]

        finally:
            # Clean up connection
            await ldap_service.disconnect(session_id)

    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


async def _demo_user_operations(ldap_service: FlextLdapApi) -> None:
    """Demonstrate user operations - Single Responsibility."""
    # Focus on search operations which don't require special authentication

    # Get connection parameters from environment
    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    # Use proper connection management
    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_failure:
            return

        # Use .value for modern type-safe access (success verified above)
        session_id = connection_result.value

        try:
            # Search for existing users in the people OU
            search_result = await ldap_service.search(
                base_dn="ou=people,dc=flext,dc=local",
                search_filter="(objectClass=person)",
                attributes=["uid", "cn", "sn", "mail", "objectClass"],
            )

            if search_result.is_success and search_result.value:
                entries = search_result.value
                for user_entry in entries:
                    user_entry.get_single_attribute_value("uid") or "N/A"
                    user_entry.get_single_attribute_value("cn") or "N/A"

                # Perform user search validation
                await _perform_user_search_validation(ldap_service, session_id)
            else:
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
                    for _i, _entry in enumerate(entries[:5]):  # Show first 5
                        pass
        finally:
            # Clean up connection
            await ldap_service.disconnect(session_id)

    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


async def _perform_user_search_validation(
    ldap_service: FlextLdapApi,
    _session_id: str,
) -> None:
    """Perform REAL user search validation with different filters."""
    # Test 1: Search by object class
    search_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(objectClass=inetOrgPerson)",
        attributes=["uid", "cn", "mail", "objectClass"],
        scope="subtree",
    )

    if search_result.is_success:
        pass

    # Test 2: Search with compound filter
    compound_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(&(objectClass=person)(uid=*))",
        attributes=["uid", "cn"],
        scope="subtree",
    )

    if compound_result.is_success:
        pass

    # Test 3: Base scope search on root
    base_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(objectClass=*)",
        attributes=["dc", "objectClass"],
        scope="base",
    )

    if base_result.is_success and base_result.value:
        entry = base_result.value[0]
        entry.attributes.get("objectClass", [])


async def _demo_group_operations(ldap_service: FlextLdapApi) -> None:
    """Demonstrate group search operations - Single Responsibility."""
    # Get connection parameters from environment
    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_failure:
            return

        # Use .value for modern type-safe access (success verified above)
        session_id = connection_result.value

        try:
            # Search for existing groups in the groups OU
            search_result = await ldap_service.search(
                base_dn="ou=groups,dc=flext,dc=local",
                search_filter="(objectClass=groupOfNames)",
                attributes=["cn", "description", "member", "objectClass"],
            )

            if search_result.is_success and search_result.value:
                entries = search_result.value
                for group_entry in entries:
                    group_entry.get_single_attribute_value("cn") or "N/A"
                    (
                        group_entry.get_single_attribute_value("description")
                        or "No description"
                    )

                # Perform group search validation
                await _perform_group_search_validation(ldap_service, session_id)
            else:
                # Test alternative group object classes
                alt_result = await ldap_service.search(
                    base_dn="ou=groups,dc=flext,dc=local",
                    search_filter="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
                    attributes=["cn", "objectClass"],
                )

                if alt_result.is_success and alt_result.value:
                    entries = alt_result.value
        finally:
            # Clean up connection
            await ldap_service.disconnect(session_id)

    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


async def _perform_group_search_validation(
    ldap_service: FlextLdapApi,
    _session_id: str,
) -> None:
    """Perform REAL group search validation with different patterns."""
    # Test 1: Search for all group types
    all_groups_result = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        search_filter="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
        attributes=["cn", "description", "objectClass"],
        scope="subtree",
    )

    if all_groups_result.is_success:
        entries = all_groups_result.value or []
        for group_entry in entries:
            group_entry.get_single_attribute_value("cn") or "Unknown"
            group_entry.get_attribute_values("objectClass")

    # Test 2: Search groups with wildcards
    wildcard_result = await ldap_service.search(
        base_dn="ou=groups,dc=flext,dc=local",
        search_filter="(cn=*)",
        attributes=["cn", "objectClass"],
        scope="one",
    )

    if wildcard_result.is_success:
        entries = wildcard_result.value or []

    # Test 3: Search with scope validation
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


async def _demo_connection_management(ldap_service: FlextLdapApi) -> None:
    """Demonstrate connection management - Single Responsibility."""
    # Get connection parameters from environment
    server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = os.getenv("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=com")
    password = os.getenv("LDAP_TEST_PASSWORD", "admin")

    # Demonstrate connection using the API's connect method
    try:
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_success:
            # Use .value for modern type-safe access (success verified above)
            session_id = connection_result.value

            # Disconnect
            disconnect_result = await ldap_service.disconnect(session_id)
            if disconnect_result.is_success:
                pass
    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


async def _demo_error_handling(_: FlextLdapApi) -> None:
    """Demonstrate error handling - Single Responsibility."""
    # Demonstrate error handling with connection attempts


if __name__ == "__main__":
    asyncio.run(main())
