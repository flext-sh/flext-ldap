#!/usr/bin/env python3
"""Complete LDAP CRUD Operations Example using FLEXT-LDAP API.

This example demonstrates COMPLETE LDAP functionality using flext-ldap:
- CREATE users and groups with FlextLdapClients
- READ/SEARCH operations
- UPDATE user attributes
- DELETE operations

Uses current flext-ldap API without legacy patterns or direct ldap3 usage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import os
import sys
from typing import Final, cast

from flext_core import FlextConstants, FlextLogger, FlextResult

from flext_ldap.clients import FlextLdapClients
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes

logger = FlextLogger(__name__)

# LDAP connection settings
LDAP_URI: Final[str] = (
    f"ldap://{FlextConstants.Platform.DEFAULT_HOST}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
)
BASE_DN: Final[str] = "dc=example,dc=com"
USERS_DN: Final[str] = f"ou=users,{BASE_DN}"
GROUPS_DN: Final[str] = f"ou=groups,{BASE_DN}"
ADMIN_DN: Final[str] = "cn=admin,dc=example,dc=com"
ADMIN_PASSWORD: Final[str] = os.getenv("LDAP_ADMIN_PASSWORD") or ""


def create_sample_users(api: FlextLdapClients) -> None:
    """Create sample users using FlextLdapClients."""
    logger.info("Creating sample users...")

    users_to_create = [
        {
            "dn": f"cn=john.doe,{USERS_DN}",
            "uid": "john.doe",
            "cn": "John Doe",
            "sn": "Doe",
            "given_name": "John",
            "mail": "john.doe@example.com",
        },
        {
            "dn": f"cn=jane.smith,{USERS_DN}",
            "uid": "jane.smith",
            "cn": "Jane Smith",
            "sn": "Smith",
            "given_name": "Jane",
            "mail": "jane.smith@example.com",
        },
    ]

    for user_data in users_to_create:
        # Ensure mail is provided as required field
        mail_value = user_data.get("mail")
        if not mail_value:
            logger.warning(f"Skipping user {user_data['cn']} - no email provided")
            continue

        # Convert user data to LDAP attributes
        attributes = {
            "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
            "uid": [user_data["uid"]],
            "cn": [user_data["cn"]],
            "sn": [user_data["sn"]],
            "givenName": [user_data.get("given_name", "")],
            "mail": [mail_value],  # Now guaranteed to be str
        }

        create_result = api.add_entry(
            user_data["dn"],
            cast("dict[str, str | FlextLdapTypes.StringList]", attributes),
        )

        if create_result.is_success:
            logger.info(f"✅ Created user: {user_data['cn']}")
        else:
            logger.error(
                f"❌ Failed to create user {user_data['cn']}: {create_result.error}",
            )


def search_users(api: FlextLdapClients) -> None:
    """Search for users using FlextLdapClients."""
    logger.info("Searching for users...")

    result: FlextResult[list[FlextLdapModels.Entry]] = api.search(
        base_dn=USERS_DN,
        filter_str="(objectClass=inetOrgPerson)",
        attributes=["cn", "mail", "uid"],
    )

    if result.is_success:
        users: list[FlextLdapModels.Entry] = result.value or []
        logger.info(f"✅ Found {len(users)} users:")

        for user in users:
            cn_value: object = user.get("cn", ["Unknown"])
            mail_value: object = user.get("mail", ["No email"])

            # Helper function to safely convert to string
            def safe_str(value: str | bytes | None) -> str:
                if value is None:
                    return "Unknown"
                if isinstance(value, bytes):
                    return value.decode("utf-8")
                return str(value)

            # Handle cn value
            cn_str: str = "Unknown"
            if isinstance(cn_value, list) and cn_value:
                # Type-safe access to list element
                first_cn: str | bytes | None = cn_value[0]
                cn_str = safe_str(first_cn)
            elif cn_value is not None:
                cn_str = safe_str(cast("str | bytes | None", cn_value))

            # Handle mail value
            mail_str: str = "No email"
            if isinstance(mail_value, list) and mail_value:
                # Type-safe access to list element
                first_mail: str | bytes | None = mail_value[0]
                mail_str = safe_str(first_mail)
            elif mail_value is not None:
                mail_str = safe_str(cast("str | bytes | None", mail_value))

            logger.info(f"  - {cn_str} ({mail_str})")
    else:
        logger.error(f"❌ Search failed: {result.error}")


def update_user(api: FlextLdapClients, user_dn: str, new_mail: str) -> None:
    """Update user attributes using FlextLdapClients."""
    logger.info(f"Updating user {user_dn}...")

    # Connect to LDAP server
    connect_result = api.connect(LDAP_URI, ADMIN_DN, ADMIN_PASSWORD)
    if connect_result.is_success:
        try:
            # Use modify_entry method if available
            modify_method = getattr(api, "modify_entry", None)
            if modify_method:
                result = modify_method(user_dn, {"mail": [new_mail]})
                typed_result: FlextResult[object] = cast("FlextResult[object]", result)

                if typed_result.is_success:
                    logger.info(f"✅ Updated user email to: {new_mail}")
                else:
                    logger.error(f"❌ Failed to update user: {typed_result.error}")
            else:
                logger.error("❌ modify_entry method not available")
        finally:
            # Disconnect
            api.unbind()
    else:
        logger.error(f"❌ Failed to connect: {connect_result.error}")


def delete_user(api: FlextLdapClients, user_dn: str) -> None:
    """Delete user using FlextLdapClients."""
    logger.info(f"Deleting user {user_dn}...")

    # Connect to LDAP server
    connect_result = api.connect(LDAP_URI, ADMIN_DN, ADMIN_PASSWORD)
    if connect_result.is_success:
        try:
            # Use delete_entry method if available
            delete_method = getattr(api, "delete_entry", None)
            if delete_method:
                result = delete_method(user_dn)
                typed_result: FlextResult[object] = cast("FlextResult[object]", result)

                if typed_result.is_success:
                    logger.info("✅ User deleted successfully")
                else:
                    logger.error(f"❌ Failed to delete user: {typed_result.error}")
            else:
                logger.error("❌ delete_entry method not available")
        finally:
            # Disconnect
            api.unbind()
    else:
        logger.error(f"❌ Failed to connect: {connect_result.error}")


def demonstrate_crud_operations() -> None:
    """Demonstrate complete CRUD operations."""
    logger.info("🚀 Starting LDAP CRUD operations demo...")

    # Get FlextLdapClients instance
    api = FlextLdapClients()

    try:
        # CREATE: Add sample users
        create_sample_users(api)

        # READ: Search for users
        search_users(api)

        # UPDATE: Modify a user
        john_dn = f"cn=john.doe,{USERS_DN}"
        update_user(api, john_dn, "john.doe.updated@example.com")

        # READ again to verify update
        search_users(api)

        # DELETE: Remove a user
        delete_user(api, john_dn)

        # Final READ to verify deletion
        search_users(api)

        logger.info("✅ CRUD operations demo completed successfully!")

    except Exception:
        logger.exception("❌ Demo failed")
        raise


def main() -> int:
    """Main entry point.

    Returns:
        int: Exit code (0 for success).

    """
    logger.info("FLEXT-LDAP Complete CRUD Example")
    logger.info("=" * 50)
    logger.info(
        f"Ensure LDAP server is running on {FlextConstants.Platform.DEFAULT_HOST}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
    )
    logger.info("Base DN: dc=example,dc=com")
    logger.info("Admin DN: cn=admin,dc=example,dc=com")
    logger.info("=" * 50)

    try:
        demonstrate_crud_operations()
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
    except Exception:
        logger.exception("Demo failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
