"""FLEXT-LDAP API - Unified Facade for LDAP Operations.

This module provides the primary entry point for all LDAP operations.
The FlextLdap class serves as the sole facade for the FLEXT LDAP library,
coordinating connection management and LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import types
from typing import Self, override

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif import FlextLdifModels, FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdap(FlextService[FlextLdapModels.SearchResult]):
    """Main API facade for LDAP operations.

    This is the sole entry point for all LDAP operations, coordinating
    connection management and LDAP CRUD operations. It inherits from
    FlextService to leverage dependency injection, logging, and event
    publishing capabilities.

    Capabilities:
        - Connect to LDAP servers using ldap3
        - Search LDAP directories
        - Add, modify, and delete LDAP entries
        - Automatic conversion between LDAP results and Entry models
        - Reuses FlextLdifParser for parsing operations

    Example:
        # Create instance
        ldap = FlextLdap()

        # Connect to server
        config = FlextLdapModels.ConnectionConfig(
            host="ldap.example.com",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password"
        )
        result = ldap.connect(config)
        if result.is_success:
            # Search entries
            search_options = FlextLdapModels.SearchOptions(
                base_dn="dc=example,dc=com",
                filter_str="(objectClass=person)"
            )
            search_result = ldap.search(search_options)
            if search_result.is_success:
                entries = search_result.unwrap().entries

        # Disconnect
        ldap.disconnect()

    """

    _connection: FlextLdapConnection
    _operations: FlextLdapOperations
    _config: FlextLdapConfig
    _logger: FlextLogger

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Initialize LDAP facade.

        Args:
            config: FlextLdapConfig instance (optional, creates default if not provided)
            parser: FlextLdifParser instance (optional, creates default if not provided)

        """
        super().__init__()
        self._config = config or FlextLdapConfig()
        self._logger = FlextLogger(__name__)
        self._connection = FlextLdapConnection(
            config=self._config, parser=parser or FlextLdifParser()
        )
        self._operations = FlextLdapOperations(connection=self._connection)

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> FlextResult[bool]:
        """Establish LDAP connection.

        Args:
            connection_config: Connection configuration (required, no fallback)

        Returns:
            FlextResult[bool] indicating connection success

        """
        # Fast fail - connection_config is required, no fallback
        return self._connection.connect(connection_config)

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self._connection.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if facade has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._connection.is_connected

    @property
    def client(self) -> FlextLdapOperations:
        """Get LDAP operations client.

        Returns:
            FlextLdapOperations instance for direct operations access

        """
        return self._operations

    def __enter__(self) -> Self:
        """Context manager entry.

        Returns:
            Self for use in 'with' statement

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit.

        Automatically disconnects when exiting 'with' block.

        Args:
            exc_type: Exception type if exception occurred
            exc_val: Exception value if exception occurred
            exc_tb: Exception traceback if exception occurred

        """
        self.disconnect()

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        return self._operations.search(search_options, server_type)

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Args:
            entry: Entry model to add

        Returns:
            FlextResult containing OperationResult

        """
        return self._operations.add(entry)

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
        return self._operations.modify(dn, changes)

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
        return self._operations.delete(dn)

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Upsert LDAP entry (add if doesn't exist, skip if exists).

        Generic method that handles both regular entries and schema modifications.
        For regular entries: tries add, returns "added" or "skipped" if already exists.
        For schema entries (changetype=modify): applies modify operation.

        Args:
            entry: Entry model to upsert

        Returns:
            FlextResult containing dict with "operation" key:
                - "added": Entry was added
                - "modified": Entry was modified (for schema)
                - "skipped": Entry already exists

        """
        return self._operations.upsert(entry)

    @override
    def execute(self, **kwargs: object) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns:
            FlextResult containing service status

        """
        # Fast fail - delegate to operations, no fallback
        return self._operations.execute()
