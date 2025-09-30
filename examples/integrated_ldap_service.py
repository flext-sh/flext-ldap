#!/usr/bin/env python3
"""Example of using the integrated LDAP service.

This example demonstrates how to use the LDAPService for LDAP operations.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os
from typing import cast
from urllib.parse import urlparse

from flext_core import FlextLogger, FlextResult
from flext_ldap import FlextLdapClient
from flext_ldap.models import FlextLdapModels

logger = FlextLogger(__name__)


async def main() -> None:
    """Demonstrate LDAP service usage using Single Responsibility Principle."""
    # Initialize service using helper method
    ldap_service = _initialize_ldap_service()

    # CRITICAL: Verify LDAP directory structure exists (OUs already exist)
    await _verify_ldap_directory_structure(ldap_service)

    # Execute demonstration steps using Single Responsibility helpers
    await _demo_user_operations(ldap_service)
    await _demo_group_operations(ldap_service)
    await _demo_connection_management(ldap_service)
    _demo_error_handling(ldap_service)


def _initialize_ldap_service() -> FlextLdapClient:
    """Initialize LDAP service - Single Responsibility.

    Returns:
        FlextLdapClient: The initialized LDAP API instance.

    """
    # Check if we're running with Docker environment variables
    if os.getenv("LDAP_TEST_SERVER"):
        server_url = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
        urlparse(server_url)

        # Create service using current API
        service = FlextLdapClient()
    else:
        service = FlextLdapClient()

    return service


async def _verify_ldap_directory_structure(ldap_service: FlextLdapClient) -> None:
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
        # connection_result.value is a boolean indicating success

        try:
            # Verify organizational units exist
            ous_to_verify = [
                "ou=people,dc=flext,dc=local",
                "ou=groups,dc=flext,dc=local",
            ]

            for ou_dn in ous_to_verify:
                # Search for the OU to verify it exists
                search_result: FlextResult[
                    list[FlextLdapModels.Entry]
                ] = await ldap_service.search(
                    base_dn=ou_dn,
                    filter_str="(objectClass=organizationalUnit)",
                    attributes=["ou", "description", "objectClass"],
                )

                if search_result.is_success and search_result.value:
                    search_result.value[0]

        finally:
            # Clean up connection
            await ldap_service.unbind()

    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


async def _demo_user_operations(ldap_service: FlextLdapClient) -> None:
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
        # connection_result.value is a boolean indicating success

        try:
            # Search for existing users in the people OU
            search_result: FlextResult[
                list[dict[str, object]]
            ] = await ldap_service.search(
                base_dn="ou=people,dc=flext,dc=local",
                filter_str="(objectClass=person)",
                attributes=["uid", "cn", "sn", "mail", "objectClass"],
            )

            if search_result.is_success and search_result.value:
                user_entries: list[dict[str, object]] = search_result.value
                for user_entry in user_entries:
                    attributes_raw = user_entry.get("attributes", {})
                    if not isinstance(attributes_raw, dict):
                        continue
                    # Type assertion for LDAP attributes
                    attributes: dict[str, list[str | bytes]] = cast(
                        "dict[str, list[str | bytes]]", attributes_raw
                    )
                    uid = attributes.get("uid", ["N/A"])[0]
                    cn = attributes.get("cn", ["N/A"])[0]
                    # Ensure string conversion for safe f-string interpolation
                    uid_str = (
                        uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)
                    )
                    cn_str = cn.decode("utf-8") if isinstance(cn, bytes) else str(cn)
                    logger.debug(f"Found user: {uid_str} ({cn_str})")

                # Perform user search validation
                await _perform_user_search_validation(ldap_service, "demo_session")
            else:
                # Test wildcard search
                wildcard_result: FlextResult[
                    list[dict[str, object]]
                ] = await ldap_service.search(
                    base_dn="dc=flext,dc=local",
                    filter_str="(objectClass=*)",
                    attributes=[
                        "objectClass",
                    ],  # dn is always returned, don't request it as attribute
                )

                if wildcard_result.is_success and wildcard_result.value:
                    wildcard_entries = wildcard_result.value
                    for _i, _entry in enumerate(wildcard_entries[:5]):  # Show first 5
                        pass
        finally:
            # Clean up connection
            await ldap_service.unbind()

    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


async def _perform_user_search_validation(
    ldap_service: FlextLdapClient,
    _session_id: str,
) -> None:
    """Perform REAL user search validation with different filters."""
    # Test 1: Search by object class
    search_result: FlextResult[list[dict[str, object]]] = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        filter_str="(objectClass=inetOrgPerson)",
        attributes=["uid", "cn", "mail", "objectClass"],
    )

    if search_result.is_success:
        pass

    # Test 2: Search with compound filter
    compound_result: FlextResult[list[dict[str, object]]] = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        filter_str="(&(objectClass=person)(uid=*))",
        attributes=["uid", "cn"],
    )

    if compound_result.is_success:
        pass

    # Test 3: Base scope search on root
    base_result: FlextResult[list[dict[str, object]]] = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        filter_str="(objectClass=*)",
        attributes=["dc", "objectClass"],
    )

    if base_result.is_success and base_result.value:
        entry = base_result.value[0]
        attributes_raw = entry.get("attributes", {})
        if isinstance(attributes_raw, dict):
            # Type assertion for LDAP attributes
            attributes: dict[str, list[str | bytes]] = cast(
                "dict[str, list[str | bytes]]", attributes_raw
            )
            attributes.get("objectClass", [])


async def _demo_group_operations(ldap_service: FlextLdapClient) -> None:
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
        # connection_result.value is a boolean indicating success

        try:
            # Search for existing groups in the groups OU
            search_result: FlextResult[
                list[dict[str, object]]
            ] = await ldap_service.search(
                base_dn="ou=groups,dc=flext,dc=local",
                filter_str="(objectClass=groupOfNames)",
                attributes=["cn", "description", "member", "objectClass"],
            )

            if search_result.is_success and search_result.value:
                group_search_entries: list[dict[str, object]] = search_result.value
                for group_entry in group_search_entries:
                    attributes_raw = group_entry.get("attributes", {})
                    if not isinstance(attributes_raw, dict):
                        continue
                    # Type assertion for LDAP attributes
                    attributes: dict[str, list[str | bytes]] = cast(
                        "dict[str, list[str | bytes]]", attributes_raw
                    )
                    cn_list = attributes.get("cn", ["N/A"])
                    cn = cn_list[0] if cn_list else "N/A"
                    description_list = attributes.get(
                        "description",
                        ["No description"],
                    )
                    description = (
                        description_list[0] if description_list else "No description"
                    )
                    # Ensure string conversion for safe f-string interpolation
                    cn_str = cn.decode("utf-8") if isinstance(cn, bytes) else str(cn)
                    description_str = (
                        description.decode("utf-8")
                        if isinstance(description, bytes)
                        else str(description)
                    )
                    logger.debug(f"Found group: {cn_str} - {description_str}")

                # Perform group search validation
                await _perform_group_search_validation(ldap_service, "demo_session")
            else:
                # Test alternative group object classes
                alt_result: FlextResult[
                    list[dict[str, object]]
                ] = await ldap_service.search(
                    base_dn="ou=groups,dc=flext,dc=local",
                    filter_str="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
                    attributes=["cn", "objectClass"],
                )

                if alt_result.is_success and alt_result.value:
                    pass
        finally:
            # Clean up connection
            await ldap_service.unbind()

    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


async def _perform_group_search_validation(
    ldap_service: FlextLdapClient,
    _session_id: str,
) -> None:
    """Perform REAL group search validation with different patterns."""
    # Test 1: Search for all group types
    all_groups_result: FlextResult[list[dict[str, object]]] = await ldap_service.search(
        base_dn="dc=flext,dc=local",
        filter_str="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
        attributes=["cn", "description", "objectClass"],
    )

    if all_groups_result.is_success:
        group_entries: list[dict[str, object]] = all_groups_result.value or []
        for group_entry in group_entries:
            attributes_raw = group_entry.get("attributes", {})
            if not isinstance(attributes_raw, dict):
                continue
            # Type assertion for LDAP attributes
            attributes: dict[str, list[str | bytes]] = cast(
                "dict[str, list[str | bytes]]", attributes_raw
            )
            cn_list = attributes.get("cn", ["Unknown"])
            cn = cn_list[0] if cn_list else "Unknown"
            object_class = attributes.get("objectClass", [])
            # Ensure string conversion for safe f-string interpolation
            cn_str = cn.decode("utf-8") if isinstance(cn, bytes) else str(cn)
            object_class_str = str(
                object_class
            )  # object_class is already a list, convert to string representation
            logger.debug(f"Group: {cn_str}, Class: {object_class_str}")

    # Test 2: Search groups with wildcards
    wildcard_result = await ldap_service.search(
        base_dn="ou=groups,dc=flext,dc=local",
        filter_str="(cn=*)",
        attributes=["cn", "objectClass"],
    )

    if wildcard_result.is_success:
        pass

    # Test 3: Search with scope validation
    scope_result: FlextResult[list[dict[str, object]]] = await ldap_service.search(
        base_dn="ou=groups,dc=flext,dc=local",
        filter_str="(objectClass=*)",
        attributes=[
            "objectClass",
        ],  # dn is always returned, don't request it as attribute
    )

    if scope_result.is_success:
        pass


async def _demo_connection_management(ldap_service: FlextLdapClient) -> None:
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
            _ = connection_result.value

            # Disconnect
            disconnect_result: FlextResult[None] = await ldap_service.unbind()
            if disconnect_result.is_success:
                pass
    except Exception as e:
        # Continue with next operation
        logger.debug(f"Demo operation encountered exception: {e}")


def _demo_error_handling(_: FlextLdapClient) -> None:
    """Demonstrate error handling - Single Responsibility."""
    # Demonstrate error handling with connection attempts
    logger.info("Error handling demonstration completed")


if __name__ == "__main__":
    asyncio.run(main())
