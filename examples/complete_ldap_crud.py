#!/usr/bin/env python3
"""Complete LDAP CRUD Operations Example using FLEXT-LDAP API.

This example demonstrates COMPLETE LDAP functionality using flext-ldap:
- CREATE users and groups with FlextLdapApi
- READ/SEARCH operations
- UPDATE user attributes
- DELETE operations

Uses current flext-ldap API without legacy patterns or direct ldap3 usage.
"""

import asyncio
import os
import sys
from typing import Final, cast

from flext_core import FlextConstants, FlextLogger, FlextResult
from flext_ldap import (
    FlextLdapApi,
    FlextLdapModels,
)

logger = FlextLogger(__name__)

# LDAP connection settings
LDAP_URI: Final[str] = f"ldap://{FlextConstants.Platform.DEFAULT_HOST}:389"
BASE_DN: Final[str] = "dc=example,dc=com"
USERS_DN: Final[str] = f"ou=users,{BASE_DN}"
GROUPS_DN: Final[str] = f"ou=groups,{BASE_DN}"
ADMIN_DN: Final[str] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
ADMIN_PASSWORD: Final[str] = os.getenv("LDAP_ADMIN_PASSWORD") or ""


async def create_sample_users(api: FlextLdapApi) -> None:
    """Create sample users using FlextLdapApi."""
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
        request = FlextLdapModels.CreateUserRequest(
            dn=user_data["dn"],
            uid=user_data["uid"],
            cn=user_data["cn"],
            sn=user_data["sn"],
            given_name=user_data.get("given_name"),
            mail=user_data.get("mail"),
            description=None,
            telephone_number=None,
            user_password=None,
        )
        create_result: FlextResult[object] = cast(
            "FlextResult[object]",
            await api.create_user(request),
        )

        if create_result.is_success:
            logger.info(f"✅ Created user: {user_data['cn']}")
        else:
            logger.error(
                f"❌ Failed to create user {user_data['cn']}: {create_result.error}",
            )


async def search_users(api: FlextLdapApi) -> None:
    """Search for users using FlextLdapApi."""
    logger.info("Searching for users...")

    search_request = FlextLdapModels.SearchRequest(
        base_dn=USERS_DN,
        filter_str="(objectClass=inetOrgPerson)",
        attributes=["cn", "mail", "uid"],
        scope="subtree",
        size_limit=1000,
        time_limit=30,
    )
    result = await api.search(search_request)

    if result.is_success:
        users = result.value or []
        logger.info(f"✅ Found {len(users)} users:")

        for user in users:
            cn = user.attributes.get("cn", ["Unknown"])
            mail = user.attributes.get("mail", ["No email"])
            # get_attribute returns list[str] | None, so take first element
            cn_str = cn[0] if cn else "Unknown"
            mail_str = mail[0] if mail else "No email"
            # Ensure values are strings, not bytes
            cn_str = (
                cn_str.decode("utf-8") if isinstance(cn_str, bytes) else str(cn_str)
            )
            mail_str = (
                mail_str.decode("utf-8")
                if isinstance(mail_str, bytes)
                else str(mail_str)
            )
            logger.info(f"  - {cn_str} ({mail_str})")
    else:
        logger.error(f"❌ Search failed: {result.error}")


async def update_user(api: FlextLdapApi, user_dn: str, new_mail: str) -> None:
    """Update user attributes using FlextLdapApi."""
    logger.info(f"Updating user {user_dn}...")

    async with api.connection(LDAP_URI, ADMIN_DN, ADMIN_PASSWORD) as session:
        modify_method = getattr(api, "modify_entry", None)
        if modify_method:
            result = await modify_method(session, user_dn, {"mail": [new_mail]})
            typed_result: FlextResult[object] = cast("FlextResult[object]", result)

            if typed_result.is_success:
                logger.info(f"✅ Updated user email to: {new_mail}")
            else:
                logger.error(f"❌ Failed to update user: {typed_result.error}")
        else:
            logger.error("❌ modify_entry method not available")


async def delete_user(api: FlextLdapApi, user_dn: str) -> None:
    """Delete user using FlextLdapApi."""
    logger.info(f"Deleting user {user_dn}...")

    async with api.connection(LDAP_URI, ADMIN_DN, ADMIN_PASSWORD) as session:
        delete_method = getattr(api, "delete_entry", None)
        if delete_method:
            result = await delete_method(session, user_dn)
            typed_result: FlextResult[object] = cast("FlextResult[object]", result)

            if typed_result.is_success:
                logger.info("✅ User deleted successfully")
            else:
                logger.error(f"❌ Failed to delete user: {typed_result.error}")
        else:
            logger.error("❌ delete_entry method not available")


async def demonstrate_crud_operations() -> None:
    """Demonstrate complete CRUD operations."""
    logger.info("🚀 Starting LDAP CRUD operations demo...")

    # Get FlextLdapApi instance via explicit factory to ensure proper typing
    api = FlextLdapApi.create()

    try:
        # CREATE: Add sample users
        await create_sample_users(api)

        # READ: Search for users
        await search_users(api)

        # UPDATE: Modify a user
        john_dn = f"cn=john.doe,{USERS_DN}"
        await update_user(api, john_dn, "john.doe.updated@example.com")

        # READ again to verify update
        await search_users(api)

        # DELETE: Remove a user
        await delete_user(api, john_dn)

        # Final READ to verify deletion
        await search_users(api)

        logger.info("✅ CRUD operations demo completed successfully!")

    except Exception:
        logger.exception("❌ Demo failed")
        raise


def main() -> int:
    """Main entry point."""
    logger.info("FLEXT-LDAP Complete CRUD Example")
    logger.info("=" * 50)
    logger.info("Ensure LDAP server is running on localhost:389")
    logger.info("Base DN: dc=example,dc=com")
    logger.info("Admin DN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
    logger.info("=" * 50)

    try:
        asyncio.run(demonstrate_crud_operations())
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
    except Exception:
        logger.exception("Demo failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
