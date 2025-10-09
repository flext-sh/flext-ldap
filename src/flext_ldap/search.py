"""LDAP search operations for flext-ldap.

This module provides unified search functionality for LDAP operations
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

from flext_core import (
    FlextResult,
    FlextService,
    FlextTypes,
)
from ldap3 import BASE, LEVEL, SUBTREE

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.validations import FlextLdapValidations

if TYPE_CHECKING:
    from ldap3 import Connection


class FlextLdapSearch(FlextService[None]):
    """Unified LDAP search operations class.

    This class provides comprehensive LDAP search functionality
    with Clean Architecture patterns and flext-core integration.

    **UNIFIED CLASS PATTERN**: One class per module with nested helpers only.
    **CLEAN ARCHITECTURE**: Application layer search services.
    **FLEXT INTEGRATION**: Full flext-core service integration.

    Provides LDAP search operations:
    - search: Perform LDAP search operations
    - search_one: Search for single entry
    - user_exists: Check if user exists
    - group_exists: Check if group exists
    - get_user: Get user by DN
    - get_group: Get group by DN
    """

    def __init__(self, parent: object = None) -> None:
        """Initialize LDAP search service with Phase 1 context enrichment.

        Args:
            parent: Optional parent client for shared state access

        """
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._parent = parent
        # These will be set by the client that uses this service
        self._connection: Connection | None = None

    @classmethod
    def create(cls) -> FlextLdapSearch:
        """Create a new FlextLdapSearch instance (factory method)."""
        return cls()

    def set_connection_context(self, connection: Connection) -> None:
        """Set the connection context for search operations.

        Args:
            connection: LDAP connection object

        """
        self._connection = connection

    def search_one(
        self,
        search_base: str,
        filter_str: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Perform LDAP search for single entry - implements LdapSearchProtocol.

        Args:
            search_base: LDAP search base DN
            filter_str: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[FlextLdapModels.Entry | None]: Single search result Entry model or None

        """
        # Use existing search method and return first result
        search_result = self.search(search_base, filter_str, attributes)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(
                search_result.error or "Search failed",
            )

        results = search_result.unwrap()
        if not results:
            return FlextResult[FlextLdapModels.Entry | None].ok(None)

        return FlextResult[FlextLdapModels.Entry | None].ok(results[0])

    def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: FlextTypes.StringList | None = None,
        scope: str = "subtree",
        page_size: int = 0,
        paged_cookie: bytes | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search operation.

        Args:
            base_dn: Base DN for search.
            filter_str: LDAP search filter.
            attributes: List of attributes to retrieve.
            scope: Search scope ("base", "level", or "subtree").
            page_size: Page size for paged search.
            paged_cookie: Cookie for paged search.

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    "LDAP connection not established",
                )

            # Convert scope string to ldap3 constant
            ldap3_scope = self._get_ldap3_scope(scope)

            # Perform search
            success: bool = self._connection.search(
                base_dn,
                filter_str,
                ldap3_scope,
                attributes=attributes,
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
            )

            if not success:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    f"Search failed: {self._connection.last_error}",
                )

            # Convert entries to Entry models
            entries: list[FlextLdapModels.Entry] = []
            for entry in self._connection.entries:  # ldap3 Entry objects
                # Build attributes dict from ldap3 entry
                entry_attributes_dict: FlextTypes.Dict = {}

                # Handle case where entry.attributes might be a list instead of dict
                entry_attrs: object = (
                    entry.attributes if hasattr(entry, "attributes") else {}
                )

                if isinstance(entry_attrs, dict):
                    for attr_name in entry_attrs:
                        attr_value: object = entry[attr_name].value
                        if isinstance(attr_value, list) and len(attr_value) == 1:
                            entry_attributes_dict[attr_name] = attr_value[0]
                        else:
                            entry_attributes_dict[attr_name] = attr_value
                elif isinstance(entry_attrs, list):
                    # Handle case where attributes is a list
                    # This might happen in error conditions or with certain LDAP servers
                    self.logger.warning(
                        f"entry.attributes is a list instead of dict for DN {entry.dn}",
                    )
                else:
                    self.logger.warning(
                        f"Unexpected type for entry.attributes: {type(entry_attrs)}",
                    )

                # Get object classes safely
                object_classes: FlextTypes.StringList = []
                if isinstance(entry_attrs, dict):
                    object_classes_raw = entry_attrs.get(
                        FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
                        [],
                    )
                    if isinstance(object_classes_raw, str):
                        object_classes = [object_classes_raw]
                    elif isinstance(object_classes_raw, list):
                        object_classes = object_classes_raw
                    else:
                        object_classes = []
                elif hasattr(entry, "attributes") and hasattr(entry.attributes, "get"):
                    # Fallback for dict-like objects
                    try:
                        object_classes = entry.attributes.get(
                            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
                            [],
                        )
                        if isinstance(object_classes, str):
                            object_classes = [object_classes]
                        elif not isinstance(object_classes, list):
                            object_classes = []
                    except AttributeError:
                        pass

                # Create Entry model instance
                entry_model = FlextLdapModels.Entry(
                    dn=str(entry.dn),
                    attributes=cast(
                        "dict[str, str | list[str]]",
                        entry_attributes_dict,
                    ),
                    object_classes=cast("FlextTypes.StringList", object_classes),
                )
                entries.append(entry_model)

            return FlextResult[list[FlextLdapModels.Entry]].ok(entries)

        except Exception as e:
            self.logger.exception("Search failed")
            return FlextResult[list[FlextLdapModels.Entry]].fail(f"Search failed: {e}")

    def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists in LDAP directory.

        Args:
            dn: User Distinguished Name.

        Returns:
            FlextResult containing True if user exists, False otherwise.

        """
        try:
            result = self.get_user(dn)
            if result.is_success:
                exists = result.unwrap() is not None
                return FlextResult[bool].ok(exists)
            # Propagate connection errors, return False for not found
            error_message = result.error or "Unknown error"
            if (
                "LDAP connection not established" in error_message
                or "DN cannot be empty" in error_message
            ):
                return FlextResult[bool].fail(error_message)
            return FlextResult[bool].ok(False)

        except Exception as e:
            return FlextResult[bool].fail(f"User existence check failed: {e}")

    def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists in LDAP directory.

        Args:
            dn: Group Distinguished Name.

        Returns:
            FlextResult containing True if group exists, False otherwise.

        """
        try:
            result = self.get_group(dn)
            if result.is_success:
                exists = result.unwrap() is not None
                return FlextResult[bool].ok(exists)
            return FlextResult[bool].ok(False)

        except Exception as e:
            return FlextResult[bool].fail(f"Group existence check failed: {e}")

    def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Get user by Distinguished Name.

        Args:
            dn: Distinguished Name of the user.

        Returns:
            FlextResult containing user or None if not found.

        """
        try:
            # Validate DN using centralized validation
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    dn_validation.error or "DN validation failed",
                )

            if not self._connection:
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    "LDAP connection not established",
                )

            success: bool = self._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                "BASE",
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self.logger.debug("Entry not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

                self.logger.warning("LDAP search failed for DN %s: %s", dn, error_msg)
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            entries = self._connection.entries
            if not entries:
                self.logger.debug("No entries found for DN: %s", dn)
                return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

            user = self._create_user_from_entry(entries[0])
            return FlextResult[FlextLdapModels.LdapUser | None].ok(user)

        except Exception as e:
            self.logger.exception(f"Get user failed for DN {dn}", exception=e)
            return FlextResult[FlextLdapModels.LdapUser | None].fail(
                f"Get user failed: {e}",
            )

    def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by Distinguished Name.

        Args:
            dn: Distinguished Name of the group.

        Returns:
            FlextResult containing group or None if not found.

        """
        try:
            # Validate DN using centralized validation
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    dn_validation.error or "DN validation failed",
                )

            if not self._connection:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    "LDAP connection not established",
                )

            success: bool = self._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                "BASE",
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self.logger.debug("Group not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.Group | None].ok(None)

                self.logger.warning("LDAP search failed for DN %s: %s", dn, error_msg)
                return FlextResult[FlextLdapModels.Group | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            entries = self._connection.entries
            if not entries:
                return FlextResult[FlextLdapModels.Group | None].ok(None)

            group = self._create_group_from_entry(entries[0])
            return FlextResult[FlextLdapModels.Group | None].ok(group)

        except Exception as e:
            self.logger.exception("Get group failed")
            return FlextResult[FlextLdapModels.Group | None].fail(
                f"Get group failed: {e}",
            )

    def _create_user_from_entry(self, entry: object) -> FlextLdapModels.LdapUser:
        """Create user from LDAP entry."""
        # Simplified user creation - in real implementation this would be more complex
        return FlextLdapModels.LdapUser(
            dn=str(getattr(entry, "dn", "")),
            uid=getattr(entry, "uid", [""])[0] if hasattr(entry, "uid") else "",
            cn=getattr(entry, "cn", [""])[0] if hasattr(entry, "cn") else "",
            sn=getattr(entry, "sn", [""])[0] if hasattr(entry, "sn") else "",
            mail=getattr(entry, "mail", [""])[0] if hasattr(entry, "mail") else "",
        )

    def _create_group_from_entry(self, entry: object) -> FlextLdapModels.Group:
        """Create group from LDAP entry."""
        # Simplified group creation - in real implementation this would be more complex
        return FlextLdapModels.Group(
            dn=str(getattr(entry, "dn", "")),
            cn=getattr(entry, "cn", [""])[0] if hasattr(entry, "cn") else "",
            description=getattr(entry, "description", [""])[0]
            if hasattr(entry, "description")
            else "",
            member_dns=getattr(entry, "member", []) if hasattr(entry, "member") else [],
        )

    def _get_ldap3_scope(self, scope: str) -> Literal["BASE", "LEVEL", "SUBTREE"]:
        """Convert scope string to ldap3 scope constant.

        Args:
            scope: Scope string ("base", "level", or "subtree").

        Returns:
            ldap3 scope constant (Literal["BASE", "LEVEL", "SUBTREE"]).

        Raises:
            ValueError: If scope is invalid.

        """
        scope_map: dict[str, Literal["BASE", "LEVEL", "SUBTREE"]] = {
            "base": BASE,
            "level": LEVEL,
            "subtree": SUBTREE,
        }
        if scope not in scope_map:
            msg = f"Invalid scope: {scope}. Must be one of: base, level, subtree"
            raise ValueError(msg)
        return scope_map[scope]

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    def execute_operation(
        self,
        operation: FlextLdapModels.OperationExecutionRequest,
    ) -> FlextResult[None]:
        """Execute operation using OperationExecutionRequest model (Domain.Service protocol).

        Args:
            operation: OperationExecutionRequest containing operation settings

        Returns:
            FlextResult[object]: Success with result or failure with error

        """
        # For search operations, we execute the base service operation
        # The operation parameter could be used for more specific operation handling
        # Use operation parameter to satisfy protocol requirements
        _ = operation
        return self.execute()


__all__ = [
    "FlextLdapSearch",
]
