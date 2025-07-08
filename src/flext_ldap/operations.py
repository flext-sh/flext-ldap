# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""LDAP Operations following SOLID principles."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from flext_ldap.models import LDAPEntry, LDAPFilter, LDAPScope
from flext_ldap.result import Result

if TYPE_CHECKING:
    from ldap3 import Connection

SearchScopeType = Literal["BASE", "LEVEL", "SUBTREE"]


class LDAPOperation:
    """Base class for LDAP operations (SOLID - Single Responsibility)."""

    def __init__(self, connection: Connection) -> None:
        """Initialize operation with connection."""
        self.connection = connection

    def is_connected(self) -> bool:
        """Check if connection is active.

        Returns:
            bool: True if connected, False otherwise.

        """
        return bool(self.connection and self.connection.bound)

    def get_connection_info(self) -> dict[str, Any]:
        """Get connection information.

        Returns:
            dict[str, Any]: Connection details.

        """
        if not self.connection:
            return {"connected": False}
        return {
            "connected": self.connection.bound,
            "server": str(self.connection.server) if self.connection.server else None,
            "user": self.connection.user if hasattr(self.connection, "user") else None,
        }


class SearchOperation(LDAPOperation):
    """LDAP search operation."""

    async def execute(
        self,
        base_dn: str,
        filter_obj: LDAPFilter | str,
        scope: LDAPScope = LDAPScope.SUBTREE,
        attributes: list[str] | None = None,
    ) -> Result[list[LDAPEntry]]:
        """Execute search operation.

        Returns:
            Result[list[LDAPEntry]]: List of found entries on success.

        """
        try:
            if isinstance(filter_obj, LDAPFilter):
                filter_str = str(filter_obj)
            else:
                filter_str = filter_obj

            # Map scope enum to ldap3 string literals
            scope_mapping: dict[LDAPScope, SearchScopeType] = {
                LDAPScope.BASE: "BASE",
                LDAPScope.ONELEVEL: "LEVEL",
                LDAPScope.SUBTREE: "SUBTREE",
            }

            self.connection.search(
                search_base=base_dn,
                search_filter=filter_str,
                search_scope=scope_mapping[scope],
                attributes=attributes or [],
            )

            entries = []
            for entry in self.connection.entries:
                ldap_entry = LDAPEntry(
                    dn=entry.entry_dn,
                    attributes={
                        attr: entry[attr].values for attr in entry.entry_attributes
                    },
                )
                entries.append(ldap_entry)

            return Result.success(entries)
        except LDAPException as e:
            return Result.failure(f"Search failed: {e}")

    @staticmethod
    def get_size_limit() -> int:
        """Get the size limit for search results.

        Returns:
            int: Maximum number of entries to return.

        """
        return 1000  # Default LDAP size limit


class ModifyOperation(LDAPOperation):
    """LDAP modify operation."""

    async def execute(
        self,
        dn: str,
        changes: dict[str, list[tuple[str, Any]]],
    ) -> Result[None]:
        """Execute modify operation.

        Returns:
            Result[None]: Success result if modified, failure otherwise.

        """
        try:
            modify_dict: dict[str, list[tuple[int, Any]]] = {}
            for attr, modifications in changes.items():
                modify_dict[attr] = []
                for mod_type, values in modifications:
                    if mod_type == "add":
                        modify_dict[attr].append((cast("int", MODIFY_ADD), values))
                    elif mod_type == "delete":
                        modify_dict[attr].append((cast("int", MODIFY_DELETE), values))
                    elif mod_type == "replace":
                        modify_dict[attr].append((cast("int", MODIFY_REPLACE), values))

            self.connection.modify(dn, modify_dict)  # type: ignore[no-untyped-call]
            return Result.success(None)
        except LDAPException as e:
            return Result.failure(f"Modify failed: {e}")

    @staticmethod
    def validate_changes(changes: dict[str, list[tuple[str, Any]]]) -> bool:
        """Validate modification changes.

        Returns:
            bool: True if changes are valid.

        """
        valid_ops = {"add", "delete", "replace"}
        for modifications in changes.values():
            for mod_type, _ in modifications:
                if mod_type not in valid_ops:
                    return False
        return True
