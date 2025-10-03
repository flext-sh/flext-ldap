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

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextService,
    FlextTypes,
)

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapSearch(FlextService[None], FlextLdapProtocols.LdapSearchProtocol):
    """Unified LDAP search operations class.

    This class provides comprehensive LDAP search functionality
    with Clean Architecture patterns and flext-core integration.

    **UNIFIED CLASS PATTERN**: One class per module with nested helpers only.
    **CLEAN ARCHITECTURE**: Application layer search services.
    **FLEXT INTEGRATION**: Full flext-core service integration with protocols.

    Implements FlextLdapProtocols.LdapSearchProtocol:
    - search: Perform LDAP search operations
    - search_one: Search for single entry
    """

    def __init__(self) -> None:
        """Initialize LDAP search service."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        # These will be set by the client that uses this service
        self._connection = None

    @classmethod
    def create(cls) -> FlextLdapSearch:
        """Create a new FlextLdapSearch instance (factory method)."""
        return cls()

    def set_connection_context(self, connection: object) -> None:
        """Set the connection context for search operations.

        Args:
            connection: LDAP connection object
        """
        self._connection = connection

    def search_one(
        self,
        search_base: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Perform LDAP search for single entry - implements LdapSearchProtocol.

        Args:
            search_base: LDAP search base DN
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[FlextLdapModels.Entry | None]: Single search result Entry model or None

        """
        # Use existing search method and return first result
        search_result = self.search(search_base, search_filter, attributes)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(
                search_result.error or "Search failed"
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
        page_size: int = 0,
        paged_cookie: bytes | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search operation.

        Args:
            base_dn: Base DN for search.
            filter_str: LDAP search filter.
            attributes: List of attributes to retrieve.
            page_size: Page size for paged search.
            paged_cookie: Cookie for paged search.

        Returns:
            FlextResult containing Entry models or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    "LDAP connection not established",
                )

            # Perform search
            success = self._connection.search(
                base_dn,
                filter_str,
                FlextLdapTypes.SUBTREE,
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
            for entry in self._connection.entries:
                # Build attributes dict from ldap3 entry
                entry_attributes_dict: FlextTypes.Dict = {}

                # Handle case where entry.attributes might be a list instead of dict
                entry_attrs = (
                    entry.attributes if hasattr(entry, "attributes") else {}
                )

                if isinstance(entry_attrs, dict):
                    for attr_name in entry_attrs:
                        attr_value = entry[attr_name].value
                        if isinstance(attr_value, list) and len(attr_value) == 1:
                            entry_attributes_dict[attr_name] = attr_value[0]
                        else:
                            entry_attributes_dict[attr_name] = attr_value
                elif isinstance(entry_attrs, list):
                    # Handle case where attributes is a list
                    # This might happen in error conditions or with certain LDAP servers
                    self._logger.warning(
                        f"entry.attributes is a list instead of dict for DN {entry.dn}"
                    )
                else:
                    self._logger.warning(
                        f"Unexpected type for entry.attributes: {type(entry_attrs)}"
                    )

                # Get object classes safely
                object_classes: FlextTypes.StringList = []
                if isinstance(entry_attrs, dict):
                    object_classes = entry_attrs.get("objectClass", [])
                    if isinstance(object_classes, str):
                        object_classes = [object_classes]
                    elif not isinstance(object_classes, list):
                        object_classes = []
                elif hasattr(entry, "attributes") and hasattr(
                    entry.attributes, "get"
                ):
                    # Fallback for dict-like objects
                    try:
                        object_classes = entry.attributes.get("objectClass", [])
                        if isinstance(object_classes, str):
                            object_classes = [object_classes]
                        elif not isinstance(object_classes, list):
                            object_classes = []
                    except AttributeError:
                        pass

                # Create Entry model instance
                entry_model = FlextLdapModels.Entry(
                    dn=str(entry.dn),
                    attributes=entry_attributes_dict,
                    object_classes=object_classes,
                )
                entries.append(entry_model)

            return FlextResult[list[FlextLdapModels.Entry]].ok(entries)

        except Exception as e:
            self._logger.exception("Search failed")
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"Search failed: {e}"
            )

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
                    dn_validation.error or "DN validation failed"
                )

            if not self._connection:
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    "LDAP connection not established",
                )

            success = self._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._logger.debug("Entry not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

                self._logger.warning(
                    "LDAP search failed for DN %s: %s", dn, error_msg
                )
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._connection.entries:
                self._logger.debug("No entries found for DN: %s", dn)
                return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

            user = self._create_user_from_entry(
                self._connection.entries[0]
            )
            return FlextResult[FlextLdapModels.LdapUser | None].ok(user)

        except Exception as e:
            self._logger.exception("Get user failed for DN %s", dn)
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
                    dn_validation.error or "DN validation failed"
                )

            if not self._connection:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    "LDAP connection not established",
                )

            success = self._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._logger.debug("Group not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.Group | None].ok(None)

                self._logger.warning(
                    "LDAP search failed for DN %s: %s", dn, error_msg
                )
                return FlextResult[FlextLdapModels.Group | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._connection.entries:
                return FlextResult[FlextLdapModels.Group | None].ok(None)

            group = self._create_group_from_entry(
                self._connection.entries[0]
            )
            return FlextResult[FlextLdapModels.Group | None].ok(group)

        except Exception as e:
            self._logger.exception("Get group failed")
            return FlextResult[FlextLdapModels.Group | None].fail(
                f"Get group failed: {e}",
            )

    def _create_user_from_entry(self, entry: object) -> FlextLdapModels.LdapUser:
        """Create user from LDAP entry."""
        # Simplified user creation - in real implementation this would be more complex
        return FlextLdapModels.LdapUser(
            dn=str(getattr(entry, 'dn', '')),
            uid=getattr(entry, 'uid', [''])[0] if hasattr(entry, 'uid') else "",
            cn=getattr(entry, 'cn', [''])[0] if hasattr(entry, 'cn') else "",
            sn=getattr(entry, 'sn', [''])[0] if hasattr(entry, 'sn') else "",
            mail=getattr(entry, 'mail', [''])[0] if hasattr(entry, 'mail') else "",
        )

    def _create_group_from_entry(self, entry: object) -> FlextLdapModels.Group:
        """Create group from LDAP entry."""
        # Simplified group creation - in real implementation this would be more complex
        return FlextLdapModels.Group(
            dn=str(getattr(entry, 'dn', '')),
            cn=getattr(entry, 'cn', [''])[0] if hasattr(entry, 'cn') else "",
            description=getattr(entry, 'description', [''])[0] if hasattr(entry, 'description') else "",
            members=getattr(entry, 'member', []) if hasattr(entry, 'member') else [],
        )


__all__ = [
    "FlextLdapSearch",
]