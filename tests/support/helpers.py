"""Test helper functions for LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from typing import Literal, cast

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextTypes,
)
from ldap3 import BASE, LEVEL, MODIFY_REPLACE, SIMPLE, SUBTREE
from ldap3.core.connection import Connection
from ldap3.core.server import Server

from flext_ldap import FlextLdapModels

logger = FlextLogger(__name__)


# Type aliases for ldap3 Literal types
AuthType = Literal["ANONYMOUS", "SIMPLE", "SASL", "NTLM"]
ScopeType = Literal["BASE", "LEVEL", "SUBTREE"]


def create_test_user(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
    attributes: dict[str, FlextTypes.StringList],
) -> FlextResult[bool]:
    """Create a test user in LDAP server."""
    try:
        server: Server = Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn: Connection = Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=cast("AuthType", SIMPLE),
        )

        # Extract object_class from attributes (required by ldap3)
        object_class: list[str] = attributes.get("objectClass", ["top"])
        attrs_dict: dict[str, list[str]] = {
            k: v for k, v in attributes.items() if k != "objectClass"
        }

        success: bool = conn.add_entry(dn, object_class, attributes=attrs_dict or None)
        conn.unbind()

        if success:
            logger.debug("Created test user: %s", dn)
            return FlextResult[bool].ok(data=True)
        return FlextResult[bool].fail(f"Failed to create user: {conn.last_error}")

    except Exception as e:
        logger.exception(f"Error creating test user {dn}")
        return FlextResult[bool].fail(f"Error creating test user: {e}")


def create_test_group(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
    attributes: dict[str, FlextTypes.StringList],
) -> FlextResult[bool]:
    """Create a test group in LDAP server."""
    try:
        server: Server = Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn: Connection = Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=cast("AuthType", SIMPLE),
        )

        # Extract object_class from attributes (required by ldap3)
        object_class: list[str] = attributes.get("objectClass", ["top"])
        attrs_dict: dict[str, list[str]] = {
            k: v for k, v in attributes.items() if k != "objectClass"
        }

        success: bool = conn.add_entry(dn, object_class, attributes=attrs_dict or None)
        conn.unbind()

        if success:
            logger.debug("Created test group: %s", dn)
            return FlextResult[bool].ok(data=True)
        return FlextResult[bool].fail(f"Failed to create group: {conn.last_error}")

    except Exception as e:
        logger.exception(f"Error creating test group {dn}")
        return FlextResult[bool].fail(f"Error creating test group: {e}")


def cleanup_test_entries(
    config: FlextLdapModels.ConnectionConfig,
    dns: FlextTypes.StringList,
) -> FlextResult[int]:
    """Clean up test entries from LDAP server."""
    try:
        server: Server = Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn: Connection = Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=cast("AuthType", SIMPLE),
        )

        cleaned_count = 0
        for dn in dns:
            try:
                # ldap3.delete returns a boolean, but mypy doesn't know this
                if conn.delete_entry(dn):
                    cleaned_count += 1
                    logger.debug("Cleaned up entry: %s", dn)
                else:
                    logger.debug("Failed to clean up %s: %s", dn, conn.last_error)
            except Exception as e:
                logger.debug("Error cleaning up %s: %s", dn, e)

        conn.unbind()
        return FlextResult[int].ok(cleaned_count)

    except Exception as e:
        logger.exception("Error during cleanup")
        return FlextResult[int].fail(f"Error during cleanup: {e}")


def verify_entry_exists(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
) -> FlextResult[bool]:
    """Verify that an entry exists in LDAP server."""
    try:
        server: Server = Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn: Connection = Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=cast("AuthType", SIMPLE),
        )

        success: bool = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=cast("ScopeType", BASE),
        )

        exists: bool = success and len(conn.entries) > 0
        conn.unbind()

        return FlextResult[bool].ok(data=exists)

    except Exception as e:
        logger.exception(f"Error verifying entry {dn}")
        return FlextResult[bool].fail(f"Error verifying entry: {e}")


def get_entry_attributes(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
) -> FlextResult[FlextTypes.Dict]:
    """Get attributes of an LDAP entry."""
    try:
        server: Server = Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn: Connection = Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=cast("AuthType", SIMPLE),
        )

        success: bool = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=cast("ScopeType", BASE),
        )

        if success and len(conn.entries) > 0:
            entry = conn.entries[0]
            attributes: FlextTypes.Dict = {
                attr: entry[attr].value for attr in entry.entry_attributes
            }
            conn.unbind()
            return FlextResult[FlextTypes.Dict].ok(attributes)
        conn.unbind()
        return FlextResult[FlextTypes.Dict].fail(f"Entry not found: {dn}")

    except Exception as e:
        logger.exception(f"Error getting attributes for {dn}")
        return FlextResult[FlextTypes.Dict].fail(f"Error getting attributes: {e}")


def search_entries(
    config: FlextLdapModels.ConnectionConfig,
    base_dn: str,
    search_filter: str,
    scope: Literal["base", "onelevel", "subtree"] = "subtree",
) -> FlextResult[list[FlextTypes.Dict]]:
    """Search for entries in LDAP server."""
    try:
        server: Server = Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn: Connection = Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=cast("AuthType", SIMPLE),
        )

        ldap_scope: str
        if scope == "base":
            ldap_scope = BASE
        elif scope == "onelevel":
            ldap_scope = LEVEL
        else:
            ldap_scope = SUBTREE

        success: bool = conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap_scope,
        )

        results: list[FlextTypes.Dict] = []
        if success:
            for entry in conn.entries:
                entry_data: FlextTypes.Dict = {
                    "dn": entry.entry_dn,
                    "attributes": {
                        attr: entry[attr].value for attr in entry.entry_attributes
                    },
                }
                results.append(entry_data)

        conn.unbind()
        return FlextResult[list[FlextTypes.Dict]].ok(results)

    except Exception as e:
        logger.exception("Error searching entries")
        return FlextResult[list[FlextTypes.Dict]].fail(
            f"Error searching entries: {e}",
        )


def modify_entry(
    config: FlextLdapModels.ConnectionConfig,
    dn: str,
    changes: dict[str, str | list[str]],
) -> FlextResult[bool]:
    """Modify an LDAP entry."""
    try:
        server: Server = Server(
            host=config.server.replace("ldap://", "").replace("ldaps://", ""),
            port=config.port or 389,
            use_ssl=config.use_ssl,
        )

        conn: Connection = Connection(
            server=server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            authentication=cast("AuthType", SIMPLE),
        )

        # Convert changes to ldap3 format
        ldap3_changes: dict[str, list[tuple[Literal["MODIFY_REPLACE"], list[str]]]] = {}
        for attr, values in changes.items():
            if isinstance(values, list):
                ldap3_changes[attr] = [(MODIFY_REPLACE, values)]
            else:
                ldap3_changes[attr] = [(MODIFY_REPLACE, [values])]

        # ldap3.modify returns a boolean, but mypy doesn't know this
        success: bool = conn.modify(dn, ldap3_changes)
        conn.unbind()

        if success:
            logger.debug("Modified entry: %s", dn)
            return FlextResult[bool].ok(data=True)
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
