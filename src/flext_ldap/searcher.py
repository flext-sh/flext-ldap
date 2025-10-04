"""LDAP Searcher - Handles LDAP search operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextResult, FlextTypes
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

if TYPE_CHECKING:
    from flext_ldap.clients import FlextLdapClient


class FlextLdapSearcher:
    """LDAP Searcher - Handles LDAP search operations.

    **UNIFIED CLASS PATTERN**: Single class per module with nested helpers only.

    This class manages LDAP search operations including:
    - Basic and advanced search queries
    - Paged search support
    - Entry conversion to domain models
    - User and group existence checks
    - Railway pattern error handling

    **PROTOCOL COMPLIANCE**: Implements LdapSearchProtocol methods.
    """

    def __init__(self, parent: FlextLdapClient) -> None:
        """Initialize searcher with parent client reference.

        Args:
            parent: Parent FlextLdapClient instance for shared state access.
        """
        self._parent = parent

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
            if not self._parent._connection:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    "LDAP connection not established",
                )

            # Perform search
            success = self._parent._connection.search(
                base_dn,
                filter_str,
                FlextLdapTypes.SUBTREE,
                attributes=attributes,
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
            )

            if not success:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    f"Search failed: {self._parent._connection.last_error}",
                )

            # Convert entries to Entry models
            entries: list[FlextLdapModels.Entry] = []
            for entry in self._parent._connection.entries:
                # Build attributes dict from ldap3 entry
                entry_attributes_dict: FlextTypes.Dict = {}

                # Handle case where entry.attributes might be a list instead of dict
                entry_attrs = entry.attributes if hasattr(entry, "attributes") else {}

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
                    self._parent._logger.warning(
                        f"entry.attributes is a list instead of dict for DN {entry.dn}"
                    )
                else:
                    self._parent._logger.warning(
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
                elif hasattr(entry, "attributes") and hasattr(entry.attributes, "get"):
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
            self._parent._logger.exception("Search failed")
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
                    dn_validation.error or "DN validation failed"
                )

            if not self._parent._connection:
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    "LDAP connection not established",
                )

            success = self._parent._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._parent._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._parent._logger.debug("Entry not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

                self._parent._logger.warning(
                    "LDAP search failed for DN %s: %s", dn, error_msg
                )
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._parent._connection.entries:
                self._parent._logger.debug("No entries found for DN: %s", dn)
                return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

            # Create user from first entry
            entry = self._parent._connection.entries[0]
            user = self._parent._create_user_from_entry(entry)
            return FlextResult[FlextLdapModels.LdapUser | None].ok(user)

        except Exception as e:
            self._parent._logger.exception("Get user failed")
            return FlextResult[FlextLdapModels.LdapUser | None].fail(
                f"Get user failed: {e}"
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

            if not self._parent._connection:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    "LDAP connection not established",
                )

            success = self._parent._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._parent._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._parent._logger.debug("Entry not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.Group | None].ok(None)

                self._parent._logger.warning(
                    "LDAP search failed for DN %s: %s", dn, error_msg
                )
                return FlextResult[FlextLdapModels.Group | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._parent._connection.entries:
                self._parent._logger.debug("No entries found for DN: %s", dn)
                return FlextResult[FlextLdapModels.Group | None].ok(None)

            # Create group from first entry
            entry = self._parent._connection.entries[0]
            group = self._parent._create_group_from_entry(entry)
            return FlextResult[FlextLdapModels.Group | None].ok(group)

        except Exception as e:
            self._parent._logger.exception("Get group failed")
            return FlextResult[FlextLdapModels.Group | None].fail(
                f"Get group failed: {e}"
            )
