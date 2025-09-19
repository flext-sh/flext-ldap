"""Test helper functions for LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import cast

import ldap3

from flext_core import FlextLogger, FlextResult, FlextTypes
from flext_ldap import FlextLdapModels

logger = FlextLogger(__name__)


def create_test_user(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
    attributes: dict[str, FlextTypes.Core.StringList],
) -> FlextResult[bool]:
    """Create a test user in LDAP server."""
    try:
        server = ldap3.Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn = ldap3.Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=ldap3.SIMPLE,
        )

        success = conn.add(dn, attributes=attributes)
        conn.unbind()

        if success:
            logger.debug(f"Created test user: {dn}")
            return FlextResult.ok(data=True)
        return FlextResult[bool].fail(f"Failed to create user: {conn.last_error}")

    except Exception as e:
        logger.exception(f"Error creating test user {dn}")
        return FlextResult[bool].fail(f"Error creating test user: {e}")


def create_test_group(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
    attributes: dict[str, FlextTypes.Core.StringList],
) -> FlextResult[bool]:
    """Create a test group in LDAP server."""
    try:
        server = ldap3.Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn = ldap3.Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=ldap3.SIMPLE,
        )

        success = conn.add(dn, attributes=attributes)
        conn.unbind()

        if success:
            logger.debug(f"Created test group: {dn}")
            return FlextResult.ok(data=True)
        return FlextResult[bool].fail(f"Failed to create group: {conn.last_error}")

    except Exception as e:
        logger.exception(f"Error creating test group {dn}")
        return FlextResult[bool].fail(f"Error creating test group: {e}")


def cleanup_test_entries(
    config: FlextLdapModels.ConnectionConfig,
    dns: FlextTypes.Core.StringList,
) -> FlextResult[int]:
    """Clean up test entries from LDAP server."""
    try:
        server = ldap3.Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn = ldap3.Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=ldap3.SIMPLE,
        )

        cleaned_count = 0
        for dn in dns:
            try:
                if conn.delete(dn):
                    cleaned_count += 1
                    logger.debug(f"Cleaned up entry: {dn}")
                else:
                    logger.debug(f"Failed to clean up {dn}: {conn.last_error}")
            except Exception as e:
                logger.debug(f"Error cleaning up {dn}: {e}")

        conn.unbind()
        return FlextResult.ok(cleaned_count)

    except Exception as e:
        logger.exception("Error during cleanup")
        return FlextResult[int].fail(f"Error during cleanup: {e}")


def verify_entry_exists(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
) -> FlextResult[bool]:
    """Verify that an entry exists in LDAP server."""
    try:
        server = ldap3.Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn = ldap3.Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=ldap3.SIMPLE,
        )

        success = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
        )

        exists = success and len(conn.entries) > 0
        conn.unbind()

        return FlextResult.ok(exists)

    except Exception as e:
        logger.exception(f"Error verifying entry {dn}")
        return FlextResult[bool].fail(f"Error verifying entry: {e}")


def get_entry_attributes(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Get attributes of an LDAP entry."""
    try:
        server = ldap3.Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn = ldap3.Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=ldap3.SIMPLE,
        )

        success = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
        )

        if success and len(conn.entries) > 0:
            entry = conn.entries[0]
            attributes = {attr: entry[attr].values for attr in entry.entry_attributes}
            conn.unbind()
            return FlextResult.ok(cast("FlextTypes.Core.Dict", attributes))
        conn.unbind()
        return FlextResult[FlextTypes.Core.Dict].fail(f"Entry not found: {dn}")

    except Exception as e:
        logger.exception(f"Error getting attributes for {dn}")
        return FlextResult[FlextTypes.Core.Dict].fail(f"Error getting attributes: {e}")


def search_entries(
    config: FlextLdapModels.ConnectionConfig,
    base_dn: str,
    search_filter: str,
    scope: str = "subtree",
) -> FlextResult[list[FlextTypes.Core.Dict]]:
    """Search for entries in LDAP server."""
    try:
        server = ldap3.Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn = ldap3.Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=ldap3.SIMPLE,
        )

        # Map string scope to ldap3 integer scope
        scope_map = {
            "base": ldap3.BASE,
            "onelevel": ldap3.LEVEL,
            "subtree": ldap3.SUBTREE,
        }
        ldap_scope = scope_map.get(scope, ldap3.SUBTREE)

        success = conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap_scope,
        )

        results = []
        if success:
            for entry in conn.entries:
                entry_data = {
                    "dn": entry.entry_dn,
                    "attributes": {
                        attr: entry[attr].values for attr in entry.entry_attributes
                    },
                }
                results.append(entry_data)

        conn.unbind()
        return FlextResult.ok(cast("list[FlextTypes.Core.Dict]", results))

    except Exception as e:
        logger.exception("Error searching entries")
        return FlextResult[list[FlextTypes.Core.Dict]].fail(
            f"Error searching entries: {e}",
        )


def modify_entry(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
    changes: FlextTypes.Core.Dict,
) -> FlextResult[bool]:
    """Modify an LDAP entry."""
    try:
        server = ldap3.Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn = ldap3.Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=ldap3.SIMPLE,
        )

        # Convert changes to ldap3 format
        ldap3_changes = {}
        for attr, values in changes.items():
            if isinstance(values, list):
                ldap3_changes[attr] = [(ldap3.MODIFY_REPLACE, values)]
            else:
                ldap3_changes[attr] = [(ldap3.MODIFY_REPLACE, [values])]

        success = conn.modify(dn, ldap3_changes)
        conn.unbind()

        if success:
            logger.debug(f"Modified entry: {dn}")
            return FlextResult.ok(data=True)
        return FlextResult[bool].fail(f"Failed to modify entry: {conn.last_error}")

    except Exception as e:
        logger.exception(f"Error modifying entry {dn}")
        return FlextResult[bool].fail(f"Error modifying entry: {e}")


def extract_server_info(server_url: str) -> tuple[str, int]:
    """Extract host and port from server URL."""
    # Remove protocol prefix
    if "://" in server_url:
        server_url = server_url.split("://", 1)[1]

    # Split host and port
    if ":" in server_url:
        host, port_str = server_url.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 389  # Default LDAP port
    else:
        host = server_url
        port = 389  # Default LDAP port

    return host, port
