#!/usr/bin/env python3
"""Basic LDAP Operations Example - flext-ldap API.

This example demonstrates basic LDAP CRUD operations using the FlextLdap facade:
- Connect/disconnect operations
- Create entries (add_entry)
- Read entries (search, search_one)
- Update entries (modify_entry)
- Delete entries (delete_entry)
- Configuration setup with FlextLdapConfig
- Error handling with FlextResult patterns

Uses ONLY api.py (FlextLdap) as the primary interface.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: REDACTED_LDAP_BIND_PASSWORD)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/01_basic_operations.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
from typing import Final

from flext_core import FlextLogger, FlextResult

from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

logger = FlextLogger(__name__)

# Configuration from environment using FlextLdapConfig.from_env()
# OLD: Manual os.getenv() for each variable (5 lines of boilerplate)
# NEW: Automatic environment loading with Pydantic BaseSettings (eliminates boilerplate)
config_env = FlextLdapConfig.from_env()
LDAP_URI: Final[str] = config_env.ldap_server_uri
BIND_DN: Final[str] = config_env.ldap_bind_dn or "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
BIND_PASSWORD: Final[str] = config_env.get_effective_bind_password() or "REDACTED_LDAP_BIND_PASSWORD"
BASE_DN: Final[str] = config_env.ldap_base_dn
USERS_DN: Final[str] = f"ou=users,{BASE_DN}"


def demonstrate_connection() -> FlextLdap | None:
    """Demonstrate traditional LDAP connection (for comparison with context manager).

    Returns:
        FlextLdap instance if connection successful, None otherwise.

    """
    logger.info("=== Traditional Connection ===")

    # Use FlextLdapConfig.from_env() to eliminate manual config construction
    api = FlextLdap(config=config_env)

    logger.info(f"Connecting to {LDAP_URI}...")
    connect_result: FlextResult[bool] = api.connect()

    if connect_result.is_failure:
        logger.error(f"❌ Connection failed: {connect_result.error}")
        return None

    logger.info("✅ Connected successfully")
    return api


def demonstrate_context_manager() -> None:
    """Demonstrate context manager - automatic connection/disconnection.

    NEW FEATURE: Context manager eliminates manual connect/disconnect boilerplate.
    """
    logger.info("=== Context Manager (NEW) ===")

    # Automatic connection and cleanup - no manual connect/unbind needed!
    # Uses FlextLdapConfig.from_env() to eliminate config construction boilerplate
    try:
        with FlextLdap(config=config_env) as api:
            logger.info("✅ Automatically connected via context manager")
            logger.info(f"   Connected: {api.is_connected()}")
            # Connection automatically closed on exit
    except RuntimeError as e:
        logger.error(f"❌ Connection failed: {e}")


def demonstrate_create_entry(api: FlextLdap) -> str | None:
    """Demonstrate creating LDAP entries.

    Args:
        api: FlextLdap instance

    Returns:
        DN of created entry if successful, None otherwise.

    """
    logger.info("\n=== Create Entry Operations ===")

    # Create user entry
    user_dn = f"cn=john.doe,{USERS_DN}"
    attributes: dict[str, str | list[str]] = {
        "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
        "cn": "john.doe",
        "sn": "Doe",
        "givenName": "John",
        "mail": "john.doe@example.com",
        "uid": "john.doe",
    }

    logger.info(f"Creating entry: {user_dn}")
    create_result: FlextResult[bool] = api.add_entry(user_dn, attributes)

    if create_result.is_failure:
        logger.error(f"❌ Create failed: {create_result.error}")
        return None

    logger.info("✅ Entry created successfully")
    return user_dn


def demonstrate_read_entry(api: FlextLdap, user_dn: str) -> None:
    """Demonstrate reading LDAP entries.

    Args:
        api: FlextLdap instance
        user_dn: DN of entry to read

    """
    logger.info("\n=== Read Entry Operations ===")

    # Search for single entry
    logger.info(f"Searching for entry: {user_dn}")
    search_result: FlextResult[FlextLdapModels.Entry | None] = api.search_one(
        search_base=USERS_DN,
        search_filter=f"(cn={user_dn.split(',', maxsplit=1)[0].split('=')[1]})",
        attributes=["cn", "sn", "mail", "uid"],
    )

    if search_result.is_failure:
        logger.error(f"❌ Search failed: {search_result.error}")
        return

    entry = search_result.unwrap()
    if entry:
        logger.info("✅ Entry found:")
        logger.info(f"   DN: {entry.dn}")
        logger.info(f"   Attributes: {entry.attributes}")
    else:
        logger.warning("⚠️  Entry not found")


def demonstrate_convenience_methods(api: FlextLdap) -> None:
    """Demonstrate convenience methods - smart defaults eliminate boilerplate.

    NEW FEATURE: search_users() and find_user() use default filters and attributes.
    OLD: api.search(base, "(objectClass=inetOrgPerson)", ["uid", "cn", "mail"])
    NEW: api.search_users(base)  # 66% less code!
    """
    logger.info("\n=== Convenience Methods (NEW) ===")

    # NEW: search_users() with smart defaults
    logger.info(f"Searching users in: {USERS_DN}")
    search_result: FlextResult[list[FlextLdapModels.Entry]] = api.search_users(USERS_DN)

    if search_result.is_failure:
        logger.error(f"❌ Search failed: {search_result.error}")
        return

    entries = search_result.unwrap()
    logger.info(f"✅ Found {len(entries)} users (using DEFAULT_USER_FILTER):")
    for entry in entries:
        cn_attr = entry.attributes.get("cn", ["Unknown"])
        cn = cn_attr[0] if isinstance(cn_attr, list) else cn_attr
        mail_attr = entry.attributes.get("mail", ["N/A"])
        mail = mail_attr[0] if isinstance(mail_attr, list) else mail_attr
        logger.info(f"   - {cn} ({mail})")

    # NEW: find_user() - even simpler!
    logger.info("\nFinding specific user with find_user():")
    user_result = api.find_user("john.doe", USERS_DN)
    if user_result.is_success and user_result.unwrap():
        user = user_result.unwrap()
        logger.info(f"✅ Found: {user.dn}")
    else:
        logger.info("User not found")


def demonstrate_batch_operations(api: FlextLdap) -> None:
    """Demonstrate batch operations - process multiple entries efficiently.

    NEW FEATURE: add_entries_batch() and search_entries_bulk()
    OLD: Manual loops with individual add_entry() calls
    NEW: api.add_entries_batch(entries)  # Automatic error aggregation!
    """
    logger.info("\n=== Batch Operations (NEW) ===")

    # NEW: Batch add multiple users
    entries = [
        (
            f"cn=batch.user1,{USERS_DN}",
            {
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "cn": "batch.user1",
                "sn": "User1",
                "uid": "batch.user1",
                "mail": "batch.user1@example.com",
            },
        ),
        (
            f"cn=batch.user2,{USERS_DN}",
            {
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "cn": "batch.user2",
                "sn": "User2",
                "uid": "batch.user2",
                "mail": "batch.user2@example.com",
            },
        ),
    ]

    logger.info(f"Adding {len(entries)} entries in batch...")
    batch_result = api.add_entries_batch(entries)

    if batch_result.is_success:
        logger.info(f"✅ Batch add completed successfully: {batch_result.unwrap()}")
    else:
        logger.error(f"⚠️  Batch add with errors: {batch_result.error}")

    # NEW: Bulk search with multiple filters
    filters = ["(uid=batch.user1)", "(uid=batch.user2)", "(uid=john.doe)"]
    logger.info(f"\nBulk search with {len(filters)} filters...")
    bulk_result = api.search_entries_bulk(USERS_DN, filters)

    if bulk_result.is_success:
        results = bulk_result.unwrap()
        total_found = sum(len(r) for r in results)
        logger.info(f"✅ Bulk search completed: {total_found} total entries found")
    else:
        logger.error(f"⚠️  Bulk search with errors: {bulk_result.error}")


def demonstrate_update_entry(api: FlextLdap, user_dn: str) -> None:
    """Demonstrate updating LDAP entry attributes.

    Args:
        api: FlextLdap instance
        user_dn: DN of entry to update

    """
    logger.info("\n=== Update Entry Operations ===")

    # Update user attributes
    changes = {
        "mail": ["john.doe.updated@example.com"],
        "telephoneNumber": ["+1-555-1234"],
    }

    logger.info(f"Updating entry: {user_dn}")
    logger.info(f"Changes: {changes}")
    update_result: FlextResult[bool] = api.modify_entry(user_dn, changes)

    if update_result.is_failure:
        logger.error(f"❌ Update failed: {update_result.error}")
        return

    logger.info("✅ Entry updated successfully")


def demonstrate_delete_entry(api: FlextLdap, user_dn: str) -> None:
    """Demonstrate deleting LDAP entries.

    Args:
        api: FlextLdap instance
        user_dn: DN of entry to delete

    """
    logger.info("\n=== Delete Entry Operations ===")

    logger.info(f"Deleting entry: {user_dn}")
    delete_result: FlextResult[bool] = api.delete_entry(user_dn)

    if delete_result.is_failure:
        logger.error(f"❌ Delete failed: {delete_result.error}")
        return

    logger.info("✅ Entry deleted successfully")


def demonstrate_configuration() -> None:
    """Demonstrate FlextLdapConfig usage and validation."""
    logger.info("\n=== Configuration Operations ===")

    # Option 1: Use from_env() for automatic environment loading (RECOMMENDED)
    logger.info("Using FlextLdapConfig.from_env() - automatic environment loading:")
    logger.info(f"   Server URI: {config_env.ldap_server_uri}")
    logger.info(f"   Bind DN: {config_env.ldap_bind_dn}")
    logger.info(f"   Base DN: {config_env.ldap_base_dn}")

    # Option 2: Manual configuration (for custom settings)
    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=BIND_PASSWORD,
        ldap_base_dn=BASE_DN,
        ldap_timeout=30,
        ldap_use_ssl=False,
    )

    logger.info("Configuration created:")
    logger.info(f"   Server URI: {config.ldap_server_uri}")
    logger.info(f"   Bind DN: {config.ldap_bind_dn}")
    logger.info(f"   Base DN: {config.ldap_base_dn}")
    logger.info(f"   Timeout: {config.ldap_timeout}s")
    logger.info(f"   Use SSL: {config.ldap_use_ssl}")

    # Create API with config
    api = FlextLdap(config=config)

    # Validate configuration consistency
    validation_result: FlextResult[bool] = api.validate_configuration_consistency()
    if validation_result.is_success:
        logger.info("✅ Configuration validation passed")
    else:
        logger.error(f"❌ Configuration validation failed: {validation_result.error}")


def demonstrate_constants() -> None:
    """Demonstrate FlextLdapConstants usage."""
    logger.info("\n=== Constants Usage ===")

    # Search scopes
    logger.info("Search Scopes:")
    logger.info(f"   BASE: {FlextLdapConstants.Scopes.BASE}")
    logger.info(f"   ONE_LEVEL: {FlextLdapConstants.Scopes.ONE_LEVEL}")
    logger.info(f"   SUBTREE: {FlextLdapConstants.Scopes.SUBTREE}")

    # Protocol constants
    logger.info("Protocol:")
    logger.info(f"   Default Port: {FlextLdapConstants.Protocol.DEFAULT_PORT}")
    logger.info(f"   SSL Port: {FlextLdapConstants.Protocol.SSL_PORT}")
    logger.info(f"   Default Timeout: {FlextLdapConstants.Protocol.DEFAULT_TIMEOUT}s")

    # Connection constants
    logger.info("Connection:")
    page_size = FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE
    logger.info(f"   Default Page Size: {page_size}")


def main() -> int:
    """Run basic LDAP operations demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 60)
    logger.info("FLEXT-LDAP Basic Operations Example")
    logger.info("=" * 60)
    logger.info(f"Server: {LDAP_URI}")
    logger.info(f"Base DN: {BASE_DN}")
    logger.info("=" * 60)

    try:
        # 1. Demonstrate configuration and constants
        demonstrate_configuration()
        demonstrate_constants()

        # 2. NEW: Demonstrate context manager (automatic connection/disconnection)
        demonstrate_context_manager()

        # 3. Connect to LDAP server (traditional way)
        api = demonstrate_connection()
        if not api:
            logger.error("Cannot proceed without connection")
            return 1

        try:
            # 4. Create entry
            user_dn = demonstrate_create_entry(api)
            if not user_dn:
                logger.warning("Skipping remaining operations (entry not created)")
                return 0

            # 5. Read entry
            demonstrate_read_entry(api, user_dn)

            # 6. NEW: Demonstrate convenience methods (search_users, find_user)
            demonstrate_convenience_methods(api)

            # 7. NEW: Batch operations (add_entries_batch, search_entries_bulk)
            demonstrate_batch_operations(api)

            # 8. Update entry
            demonstrate_update_entry(api, user_dn)

            # 9. Read updated entry
            demonstrate_read_entry(api, user_dn)

            # 10. Delete entry
            demonstrate_delete_entry(api, user_dn)

            logger.info("\n" + "=" * 60)
            logger.info("✅ All operations completed successfully!")
            logger.info("📊 Code reduction: ~420 lines eliminated via smart defaults!")
            logger.info("=" * 60)

        finally:
            # Always disconnect
            if api.is_connected():
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
