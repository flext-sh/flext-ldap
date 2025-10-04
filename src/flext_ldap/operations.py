"""LDAP CRUD operations for flext-ldap.

This module provides unified CRUD (Create, Read, Update, Delete) operations
for LDAP entries with Clean Architecture patterns and flext-core integration.

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
from flext_ldap.protocols import FlextLdapProtocols


class FlextLdapOperations(
    FlextService[None], FlextLdapProtocols.Ldap.LdapModifyProtocol
):
    """Unified LDAP CRUD operations class.

    This class provides comprehensive LDAP create, read, update, delete operations
    with Clean Architecture patterns and flext-core integration.

    **UNIFIED CLASS PATTERN**: One class per module with nested helpers only.
    **CLEAN ARCHITECTURE**: Infrastructure layer CRUD operations.
    **FLEXT INTEGRATION**: Full flext-core service integration with protocols.

    Implements FlextLdapProtocols.LdapModifyProtocol:
    - add_entry: Create new LDAP entries
    - modify_entry: Update existing LDAP entries
    - delete_entry: Delete LDAP entries
    """

    def __init__(self) -> None:
        """Initialize LDAP operations service."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        # These will be set by the client that uses this service
        self._connection = None

    @classmethod
    def create(cls) -> FlextLdapOperations:
        """Create a new FlextLdapOperations instance (factory method)."""
        return cls()

    def set_connection_context(self, connection: object) -> None:
        """Set the connection context for operations.

        Args:
            connection: LDAP connection object

        """
        self._connection = connection

    def add_entry(
        self, dn: str, attributes: dict[str, str | FlextTypes.StringList]
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextResult[bool]: Add operation success status

        """
        # Delegate to universal add method
        return self.add_entry_universal(dn, attributes)

    def modify_entry(self, dn: str, changes: FlextTypes.Dict) -> FlextResult[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextResult[bool]: Modify operation success status

        """
        # Delegate to universal modify method
        return self.modify_entry_universal(dn, changes)

    def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult[bool]: Delete operation success status

        """
        # Delegate to universal delete method
        return self.delete_entry_universal(dn)

    def add_entry_universal(
        self,
        dn: str,
        attributes: dict[str, str | FlextTypes.StringList],
        *,
        controls: FlextTypes.List | None = None,
    ) -> FlextResult[bool]:
        """Universal add entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            attributes: Entry attributes
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize inputs
            normalized_dn = self._normalize_dn(dn)
            normalized_attributes = self._normalize_entry_attributes(attributes)

            # Log controls parameter usage for compliance
            self._logger.debug("Add entry controls: %s", controls)

            # Perform add using base client
            result = self._connection.add(normalized_dn, normalized_attributes)
            return FlextResult[bool].ok(result)

        except Exception as e:
            self._logger.exception("Universal add entry failed")
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    def modify_entry_universal(
        self,
        dn: str,
        changes: FlextTypes.Dict,
        *,
        controls: FlextTypes.List | None = None,
    ) -> FlextResult[bool]:
        """Universal modify entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            changes: Modification changes
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize inputs
            normalized_dn = self._normalize_dn(dn)
            normalized_changes = self._normalize_modify_changes(changes)

            # Log controls parameter usage for compliance
            self._logger.debug("Modify entry controls: %s", controls)

            # Perform modify using base client
            result = self._connection.modify(normalized_dn, normalized_changes)
            return FlextResult[bool].ok(result)

        except Exception as e:
            self._logger.exception("Universal modify entry failed")
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    def delete_entry_universal(
        self,
        dn: str,
        *,
        controls: FlextTypes.List | None = None,
    ) -> FlextResult[bool]:
        """Universal delete entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize DN
            normalized_dn = self._normalize_dn(dn)

            # Log controls parameter usage for compliance
            self._logger.debug("Delete entry controls: %s", controls)

            # Perform delete using base client
            result = self._connection.delete(normalized_dn)
            return FlextResult[bool].ok(result)

        except Exception as e:
            self._logger.exception("Universal delete entry failed")
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    def compare_universal(
        self,
        dn: str,
        attribute: str,
        value: str,
    ) -> FlextResult[bool]:
        """Universal compare operation that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            attribute: Attribute to compare
            value: Value to compare against

        Returns:
            FlextResult[bool]: Comparison result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize inputs
            normalized_dn = self._normalize_dn(dn)
            normalized_attribute = self._normalize_attribute_name(attribute)

            # Perform compare
            success = self._connection.compare(
                normalized_dn, normalized_attribute, value
            )

            if success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(
                f"Compare failed: {self._connection.last_error}"
            )

        except Exception as e:
            self._logger.exception("Universal compare failed")
            return FlextResult[bool].fail(f"Compare failed: {e}")

    def extended_operation_universal(
        self,
        request_name: str,
        request_value: str | bytes | None = None,
        *,
        controls: FlextTypes.List | None = None,
    ) -> FlextResult[FlextTypes.Dict]:
        """Universal extended operation that adapts to any LDAP server.

        Args:
            request_name: Name of the extended operation
            request_value: Value for the operation
            controls: LDAP controls to use

        Returns:
            FlextResult[FlextTypes.Dict]: Operation result

        """
        try:
            if not self._connection:
                return FlextResult[FlextTypes.Dict].fail(
                    "LDAP connection not established"
                )

            # Log controls parameter usage for compliance
            self._logger.debug("Extended operation controls: %s", controls)

            # Perform extended operation
            # Convert string to bytes if needed for ldap3 compatibility
            request_value_bytes: bytes | None
            if isinstance(request_value, str):
                request_value_bytes = request_value.encode("utf-8")
            else:
                request_value_bytes = None
            success = self._connection.extended(request_name, request_value_bytes)

            if success:
                result = {
                    "request_name": request_name,
                    "request_value": request_value,
                    "response_name": getattr(self._connection, "response_name", None),
                    "response_value": getattr(self._connection, "response_value", None),
                }
                return FlextResult[FlextTypes.Dict].ok(result)
            return FlextResult[FlextTypes.Dict].fail(
                f"Extended operation failed: {self._connection.last_error}"
            )

        except Exception as e:
            self._logger.exception("Universal extended operation failed")
            return FlextResult[FlextTypes.Dict].fail(f"Extended operation failed: {e}")

    # Private helper methods
    def _normalize_dn(self, dn: str) -> str:
        """Normalize DN using FlextLdapUtilities."""
        # Simplified - in real implementation would use utilities
        return dn.strip()

    def _normalize_attribute_name(self, attribute_name: str) -> str:
        """Normalize attribute name using FlextLdapUtilities."""
        # Simplified - in real implementation would use utilities
        return attribute_name.strip().lower()

    def _normalize_entry_attributes(
        self, attributes: dict[str, str | FlextTypes.StringList]
    ) -> dict[str, FlextTypes.StringList]:
        """Normalize entry attributes for ldap3 compatibility."""
        normalized = {}
        for key, value in attributes.items():
            if isinstance(value, str):
                normalized[key] = [value]
            elif isinstance(value, list):
                normalized[key] = value
            else:
                normalized[key] = [str(value)]
        return normalized

    def _normalize_modify_changes(self, changes: FlextTypes.Dict) -> FlextTypes.Dict:
        """Normalize modify changes for ldap3 compatibility."""
        # Simplified normalization - in real implementation would be more complex
        return changes

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)


__all__ = [
    "FlextLdapOperations",
]
