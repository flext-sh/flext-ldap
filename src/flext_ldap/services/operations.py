"""LDAP Operations Service.

This service provides LDAP CRUD operations (search, add, modify, delete).
Delegates to Ldap3Adapter which already handles conversion to Entry models
using FlextLdifParser, maximizing code reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection


class FlextLdapOperations(FlextService[FlextLdapModels.SearchResult]):
    """LDAP operations service providing CRUD operations.

    Handles search, add, modify, and delete operations.
    Delegates to Ldap3Adapter which already uses FlextLdifParser for conversion.
    This maximizes code reuse - adapter handles all parsing logic.
    """

    _connection: FlextLdapConnection
    _logger: FlextLogger

    def __init__(
        self,
        connection: FlextLdapConnection,
    ) -> None:
        """Initialize operations service.

        Args:
            connection: FlextLdapConnection instance

        """
        super().__init__()
        self._connection = connection
        self._logger = FlextLogger(__name__)

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = "rfc",
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Delegates to Ldap3Adapter which already converts results to Entry models
        using FlextLdifParser.parse_ldap3_results(), maximizing code reuse.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: "rfc")

        Returns:
            FlextResult containing SearchResult with Entry models (reusing FlextLdifModels.Entry)

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                "Not connected to LDAP server"
            )

        # Normalize base_dn using FlextLdifUtilities.DN (FASE 2) - skip validation for performance
        # Validation is expensive and base_dn is usually already valid from SearchOptions model
        normalized_base_dn = FlextLdifUtilities.DN.norm_string(search_options.base_dn)

        # Perform search using adapter - it already returns Entry models
        adapter = self._connection.adapter
        search_result = adapter.search(
            base_dn=normalized_base_dn,
            filter_str=search_options.filter_str,
            scope=search_options.scope,
            attributes=search_options.attributes,
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
            server_type=server_type,
        )

        if not search_result.is_success:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                search_result.error or "Search failed"
            )

        # Adapter already returns Entry models (reusing FlextLdifModels.Entry)
        entries = search_result.unwrap()

        # Create search result
        result = FlextLdapModels.SearchResult(
            entries=entries,
            total_count=len(entries),
            search_options=search_options,
        )

        return FlextResult[FlextLdapModels.SearchResult].ok(result)

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Delegates to Ldap3Adapter which accepts Entry model directly,
        reusing FlextLdifModels.Entry for type safety.

        Args:
            entry: Entry model to add (reusing FlextLdifModels.Entry)

        Returns:
            FlextResult containing OperationResult

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                "Not connected to LDAP server"
            )

        # Normalize DN using FlextLdifUtilities.DN (FASE 2) - skip validation for performance
        # Entry.dn is already validated by Pydantic model
        dn_value = FlextLdifUtilities.DN.get_dn_value(entry.dn)
        normalized_dn = FlextLdifUtilities.DN.norm_string(dn_value)
        # Update entry with normalized DN for consistency
        entry.dn = FlextLdifModels.DistinguishedName(value=normalized_dn)

        # Perform add operation - adapter accepts Entry model directly
        adapter = self._connection.adapter
        add_result = adapter.add(entry)

        if add_result.is_success:
            operation_result = FlextLdapModels.OperationResult(
                success=True,
                operation_type="add",
                message="Entry added successfully",
                entries_affected=1,
            )
            return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = add_result.error or "Add failed"
        operation_result = FlextLdapModels.OperationResult(
            success=False,
            operation_type="add",
            message=error_msg,
            entries_affected=0,
        )
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                "Not connected to LDAP server"
            )

        # Normalize DN using FlextLdifUtilities.DN (FASE 2) - skip validation for performance
        # DN validation is expensive, normalize only
        dn_value = FlextLdifUtilities.DN.get_dn_value(dn)
        normalized_dn = FlextLdifUtilities.DN.norm_string(dn_value)

        # Perform modify operation
        adapter = self._connection.adapter
        modify_result = adapter.modify(normalized_dn, changes)

        if modify_result.is_success:
            operation_result = FlextLdapModels.OperationResult(
                success=True,
                operation_type="modify",
                message="Entry modified successfully",
                entries_affected=1,
            )
            return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = modify_result.error or "Modify failed"
        operation_result = FlextLdapModels.OperationResult(
            success=False,
            operation_type="modify",
            message=error_msg,
            entries_affected=0,
        )
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult containing OperationResult

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                "Not connected to LDAP server"
            )

        # Normalize DN using FlextLdifUtilities.DN (FASE 2) - skip validation for performance
        # DN validation is expensive, normalize only
        dn_value = FlextLdifUtilities.DN.get_dn_value(dn)
        normalized_dn = FlextLdifUtilities.DN.norm_string(dn_value)

        # Perform delete operation
        adapter = self._connection.adapter
        delete_result = adapter.delete(normalized_dn)

        if delete_result.is_success:
            operation_result = FlextLdapModels.OperationResult(
                success=True,
                operation_type="delete",
                message="Entry deleted successfully",
                entries_affected=1,
            )
            return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = delete_result.error or "Delete failed"
        operation_result = FlextLdapModels.OperationResult(
            success=False,
            operation_type="delete",
            message=error_msg,
            entries_affected=0,
        )
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    @property
    def is_connected(self) -> bool:
        """Check if operations service has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._connection.is_connected

    def execute(self) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns:
            FlextResult containing empty SearchResult

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                "Not connected to LDAP server"
            )

        # Return empty search result as health check
        empty_options = FlextLdapModels.SearchOptions(
            base_dn="",
            filter_str="(objectClass=*)",
        )
        result = FlextLdapModels.SearchResult(
            entries=[],
            total_count=0,
            search_options=empty_options,
        )
        return FlextResult[FlextLdapModels.SearchResult].ok(result)
