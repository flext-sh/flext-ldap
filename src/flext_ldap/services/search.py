"""LDAP search operations for flext-ldap.

Unified search functionality with Clean Architecture patterns and
FlextResult railway-oriented programming for composable operations.

Note: types-ldap3 has incomplete type stubs for search methods,
connection properties, and entry attributes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifModels
from ldap3 import Connection
from ldap3.core.exceptions import LDAPAttributeError
from pydantic import Field

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapSearch(FlextService[None]):
    """LDAP search operations service following SRP.

    Single responsibility: Execute LDAP search operations.
    - search: Perform LDAP search operations
    - search_one: Search for single entry

    Does NOT:
    - Handle entity-specific operations (user/group) - those belong in clients/api
    - Generate synthetic test data (testing concern)
    - Validate DNs (delegate to ValidationService via caller)
    """

    # Pydantic field declaration (required for validate_assignment=True)
    s_mode: FlextLdapConstants.Types.QuirksMode = Field(
        default=FlextLdapConstants.Types.QuirksMode.AUTOMATIC,
        description="Server-specific LDIF quirks handling mode for search operations",
    )

    def __init__(self) -> None:
        """Initialize LDAP search service with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
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

    def sets_mode(self, quirks_mode: FlextLdapConstants.Types.QuirksMode) -> None:
        """Set quirks mode for search operations.

        Args:
        quirks_mode: Quirks mode to set (automatic, server, rfc, relaxed)

        """
        # s_mode is managed as a Pydantic Field and is auto-initialized by Field default
        # This method is provided for protocol compliance and future extensibility
        # Future: implement quirks mode-specific search behavior if needed

    def search_one(
        self,
        search_base: str,
        filter_str: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Perform LDAP search for single entry.

        Args:
            search_base: LDAP search base DN
            filter_str: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[FlextLdifModels.Entry | None]: Single Entry or None

        """
        # Check if connection is available via context
        if not self._connection:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                "No LDAP connection available for search_one",
            )

        # Use existing search method and return first result
        search_result = self.search(
            search_base,
            filter_str,
            attributes,
            scope="base",
        )
        if search_result.is_failure:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                search_result.error or "Search failed",
            )

        results = search_result.unwrap()
        if not results:
            return FlextResult[FlextLdifModels.Entry | None].ok(None)

        return FlextResult[FlextLdifModels.Entry | None].ok(results[0])

    # Search Helper Methods

    def _validate_and_rebind_connection(
        self,
        connection: Connection,
    ) -> FlextResult[None]:
        """Validate connection and rebind if needed."""
        if not isinstance(connection, Connection):
            return FlextResult[None].fail(
                f"Invalid connection type: {type(connection).__name__}",
            )

        self.logger.debug(
            f"Connection check: exists={connection is not None}, bound={connection.bound if connection else 'N/A'}",
        )

        if not connection.bound:
            self.logger.debug("LDAP connection not bound, attempting to rebind")
            try:
                connection.bind()
                if not connection.bound:
                    return FlextResult[None].fail("LDAP connection rebind failed")
            except Exception as rebind_err:
                self.logger.exception("Rebind failed")
                return FlextResult[None].fail(
                    f"LDAP connection rebind error: {rebind_err}",
                )

        return FlextResult[None].ok(None)

    def _execute_search_with_retry(
        self,
        connection: Connection,
        base_dn: str,
        filter_str: str,
        ldap3_scope: str,
        attributes: list[str] | None,
        page_size: int,
        paged_cookie: bytes | None,
    ) -> bool:
        """Execute search with attribute error retry logic."""
        self.logger.debug(
            f"Before ldap3.search: bound={connection.bound}, "
            f"attributes={attributes}, filter={filter_str}",
        )

        try:
            scope_value: FlextLdapConstants.Types.Ldap3Scope = cast(
                "FlextLdapConstants.Types.Ldap3Scope",
                ldap3_scope,
            )
            search_result = connection.search(
                base_dn,
                filter_str,
                scope_value,
                attributes=attributes,
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
            )
            self.logger.debug(
                f"After ldap3.search: success={search_result}, "
                f"entries_count={len(connection.entries) if search_result else 'N/A'}, "
                f"last_error={connection.last_error}",
            )
            return bool(search_result)
        except LDAPAttributeError as e:
            # Retry with all attributes on attribute error
            attr_str = str(attributes)[:40] if attributes else "None"
            self.logger.debug(
                "Attribute error with %s, retrying with all attributes: %s",
                attr_str,
                e,
            )
            scope_value = cast("FlextLdapConstants.Types.Ldap3Scope", ldap3_scope)
            search_result = connection.search(
                base_dn,
                filter_str,
                scope_value,
                attributes=["*"],
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
            )
            self.logger.trace(f"Retry after exception: success={search_result}")
            return bool(search_result)

    def _handle_search_errors(
        self,
        connection: Connection,
        base_dn: str,
        filter_str: str,
        ldap3_scope: str,
        page_size: int,
        paged_cookie: bytes | None,
        *,
        success: bool,
    ) -> bool:
        """Handle search errors and retry if needed."""
        if success:
            return True

        if not connection.last_error:
            self.logger.trace("Search failed but no last_error available")
            return False

        error_msg = str(connection.last_error).lower()
        err_trunc = error_msg[:60]
        self.logger.trace(f"Search failed: success={success}, error='{err_trunc}'")

        if "invalid attribute" in error_msg or "no such attribute" in error_msg:
            self.logger.debug(
                f"Attribute validation failed, retrying: {str(connection.last_error)[:50]}",
            )
            scope_value = cast("FlextLdapConstants.Types.Ldap3Scope", ldap3_scope)
            search_result = connection.search(
                base_dn,
                filter_str,
                scope_value,
                attributes=["*"],
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
            )
            self.logger.trace(f"Retry after error check: success={search_result}")
            return bool(search_result)

        return False

    def _normalize_search_success(
        self,
        connection: Connection,
        scope: str,
        *,
        success: bool,
    ) -> bool:
        """Normalize search success for edge cases."""
        last_error_text = str(connection.last_error) if connection.last_error else ""

        # ldap3 returns False for zero results (not an error)
        if not success and connection.bound and not last_error_text:
            self.logger.debug(
                "ldap3 returned False with no error (zero results), treating as success",
            )
            return True

        # BASE scope with noSuchObject means base DN doesn't exist (zero results)
        if (
            not success
            and scope.lower() == "base"
            and "noSuchObject" in last_error_text
        ):
            self.logger.debug(
                "BASE scope search: noSuchObject means base DN doesn't exist (zero results), treating as success",
            )
            return True

        return success

    def _convert_ldap3_entries_to_models(
        self,
        connection: Connection,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Convert ldap3 entries to FlextLdifModels.Entry."""
        if not connection.entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        entries: list[FlextLdifModels.Entry] = []
        for ldap3_entry in connection.entries:
            entry_result = FlextLdifModels.Entry.from_ldap3(ldap3_entry)
            if entry_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Entry conversion failed: {entry_result.error}",
                )
            entries.append(entry_result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        scope: str = FlextLdapConstants.Scopes.SUBTREE,
        page_size: int = 0,
        paged_cookie: bytes | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
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
            # Step 1: Validate connection exists
            active_connection = self._connection
            if not active_connection:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "LDAP connection not established",
                )

            search_params = (
                f"base_dn={base_dn}, filter={filter_str}, attributes={attributes}"
            )
            self.logger.trace(f"Search called with {search_params}")

            # Step 2: Validate and rebind connection if needed
            validation_result = self._validate_and_rebind_connection(active_connection)
            if validation_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    validation_result.error,
                )

            # Step 3: Convert scope to ldap3 constant
            ldap3_scope = self._get_ldap3_scope(scope)

            # Step 4: Execute search with retry logic
            search_result = self._execute_search_with_retry(
                active_connection,
                base_dn,
                filter_str,
                ldap3_scope,
                attributes,
                page_size,
                paged_cookie,
            )

            # Step 5: Handle search errors and retry if needed
            success = self._handle_search_errors(
                active_connection,
                base_dn,
                filter_str,
                ldap3_scope,
                page_size,
                paged_cookie,
                success=search_result,
            )

            # Step 6: Normalize success for edge cases (zero results, etc)
            success = self._normalize_search_success(
                active_connection,
                scope,
                success=success,
            )

            # Step 7: Check final success status
            if not success:
                last_error_text = (
                    str(active_connection.last_error)
                    if active_connection.last_error
                    else ""
                )
                self.logger.warning(
                    f"Search operation failed: "
                    f"connection_bound={active_connection.bound}, "
                    f"last_error={last_error_text or FlextLdapConstants.ErrorStrings.NONE}",
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Search failed: {last_error_text or 'Connection not established'}",
                )

            # Step 8: Convert ldap3 entries to FlextLdifModels.Entry
            return self._convert_ldap3_entries_to_models(active_connection)

        except Exception as e:
            self.logger.exception("Search failed")
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Search failed: {e}")

    def _get_ldap3_scope(self, scope: str) -> str:
        """Convert scope string to ldap3 scope constant using FlextLdapConstants.

        Args:
            scope: Scope string ("base", "level", or "subtree") - case insensitive.

        Returns:
            ldap3 scope constant from FlextLdapConstants.Scopes.

        Raises:
            ValueError: If scope is invalid.

        """
        normalized_scope = scope.lower()

        # Use scope mapping from FlextLdapConstants
        if normalized_scope not in FlextLdapConstants.Scopes.SCOPE_TO_LDAP3:
            valid_scopes = f"{FlextLdapConstants.Scopes.BASE}, {FlextLdapConstants.Scopes.ONELEVEL}, {FlextLdapConstants.Scopes.SUBTREE}"
            msg = f"Invalid scope: {scope}. Must be: {valid_scopes}"
            raise ValueError(msg)
        return FlextLdapConstants.Scopes.SCOPE_TO_LDAP3[normalized_scope]

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    def execute_operation(
        self,
        request: FlextLdapModels.OperationExecutionRequest,
    ) -> FlextResult[None]:
        """Execute operation using OperationExecutionRequest model.

        Args:
        request: OperationExecutionRequest with operation settings

        Returns:
        FlextResult[object]: Success with result or failure with error

        """
        # For search operations, we execute the base service operation
        # The request parameter could be used for more specific operation handling
        # Use request parameter to satisfy protocol requirements
        _ = request
        return self.execute()


__all__ = [
    "FlextLdapSearch",
]
