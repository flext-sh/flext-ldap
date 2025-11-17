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

from flext_ldap.constants import FlextLdapConstants
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
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Delegates to Ldap3Adapter which already converts results to Entry models
        using FlextLdifParser.parse_ldap3_results(), maximizing code reuse.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: "rfc")

        Returns:
            FlextResult containing SearchResult with Entry models
                (reusing FlextLdifModels.Entry)

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                "Not connected to LDAP server",
            )

        # Normalize base_dn using FlextLdifUtilities.DN
        # Skip validation for performance
        normalized_base_dn = FlextLdifUtilities.DN.norm_string(search_options.base_dn)
        # Update search_options with normalized DN for consistency
        normalized_options = FlextLdapModels.SearchOptions(
            base_dn=normalized_base_dn,
            filter_str=search_options.filter_str,
            scope=search_options.scope,
            attributes=search_options.attributes,
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
        )

        # Perform search using adapter - monadic pattern
        return self._connection.adapter.search(
            normalized_options,
            server_type=server_type,
        ).map(
            lambda entries: FlextLdapModels.SearchResult(
                entries=entries,
                total_count=len(entries),
                search_options=normalized_options,
            ),
        )

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
                "Not connected to LDAP server",
            )

        # Normalize DN using FlextLdifUtilities.DN - skip validation for performance
        dn_value = FlextLdifUtilities.DN.get_dn_value(entry.dn)
        normalized_dn = FlextLdifUtilities.DN.norm_string(dn_value)
        # Update entry with normalized DN for consistency
        entry.dn = FlextLdifModels.DistinguishedName(value=normalized_dn)

        # Perform add operation - monadic pattern, direct return
        return self._connection.adapter.add(entry)

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify (str or DistinguishedName)
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                "Not connected to LDAP server",
            )

        # Convert to DistinguishedName model - single form internally
        dn_model = (
            dn
            if isinstance(dn, FlextLdifModels.DistinguishedName)
            else FlextLdifModels.DistinguishedName(value=dn)
        )
        # Normalize DN using FlextLdifUtilities.DN
        normalized_dn_value = FlextLdifUtilities.DN.norm_string(dn_model.value)
        normalized_dn = FlextLdifModels.DistinguishedName(value=normalized_dn_value)

        # Perform modify operation - monadic pattern, direct return
        return self._connection.adapter.modify(normalized_dn, changes)

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete (str or DistinguishedName)

        Returns:
            FlextResult containing OperationResult

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                "Not connected to LDAP server",
            )

        # Convert to DistinguishedName model - single form internally
        dn_model = (
            dn
            if isinstance(dn, FlextLdifModels.DistinguishedName)
            else FlextLdifModels.DistinguishedName(value=dn)
        )
        # Normalize DN using FlextLdifUtilities.DN
        normalized_dn_value = FlextLdifUtilities.DN.norm_string(dn_model.value)
        normalized_dn = FlextLdifModels.DistinguishedName(value=normalized_dn_value)

        # Perform delete operation - monadic pattern, direct return
        return self._connection.adapter.delete(normalized_dn)

    @property
    def is_connected(self) -> bool:
        """Check if operations service has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._connection.is_connected

    def execute(self) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns health check result based on connection status.
        Fast fail if not connected - no fallback.

        Returns:
            FlextResult containing SearchResult if connected,
            or failure if not connected

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                "Not connected to LDAP server",
            )

        # Return empty search result as health check indicator
        empty_options = FlextLdapModels.SearchOptions(
            base_dn="",
            filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
        )
        result = FlextLdapModels.SearchResult(
            entries=[],
            total_count=0,
            search_options=empty_options,
        )
        return FlextResult[FlextLdapModels.SearchResult].ok(result)
