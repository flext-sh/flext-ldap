"""LDAP search operations for flext-ldap.

Unified search functionality with Clean Architecture patterns and
FlextResult railway-oriented programming for composable operations.

Note: types-ldap3 has incomplete type stubs for search methods,
connection properties, and entry attributes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifModels
from ldap3 import Connection
from ldap3.core.exceptions import LDAPAttributeError
from pydantic import Field

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

if TYPE_CHECKING:
    from flext_ldap.services.clients import FlextLdapClients


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

    def __init__(self, parent: FlextLdapClients | None = None) -> None:
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
            # Use cached connection set via set_connection_context()
            active_connection = self._connection
            if not active_connection:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "LDAP connection not established",
                )

            search_params = (
                f"base_dn={base_dn}, filter={filter_str}, attributes={attributes}"
            )
            self.logger.trace(f"Search called with {search_params}")

            # CRITICAL: Verify connection is still bound and healthy
            if not isinstance(active_connection, Connection):
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Invalid connection type: {type(active_connection).__name__}",
                )
            self.logger.debug(
                f"Connection check: exists={active_connection is not None}, bound={active_connection.bound if active_connection else 'N/A'}",
            )
            if not active_connection.bound:
                self.logger.debug("LDAP connection not bound, attempting to rebind")
                try:
                    active_connection.bind()
                    if not active_connection.bound:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            "LDAP connection rebind failed",
                        )
                except Exception as rebind_err:
                    self.logger.exception("Rebind failed")
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"LDAP connection rebind error: {rebind_err}",
                    )

            # Convert scope string to ldap3 constant
            ldap3_scope = self._get_ldap3_scope(scope)

            # ROOT CAUSE FIX: Issue 4.1 - Connection state race condition
            # Removed redundant null check here (already validated at line 138 and rebound at 148)
            # Instead, wrap search call in try-except to handle race condition if connection
            # becomes None between this point and the actual search call

            # Perform search with attribute error handling
            # If specific attributes requested, retry with all if not found

            success: bool = False

            # DIAGNOSTIC: Log detailed connection state BEFORE ldap3 search call
            self.logger.debug(
                f"Before ldap3.search: bound={active_connection.bound}, "
                f"attributes={attributes}, filter={filter_str}",
            )

            try:
                # Cast to Ldap3Scope type for ldap3 compatibility
                scope_value: FlextLdapConstants.Types.Ldap3Scope = cast(
                    "FlextLdapConstants.Types.Ldap3Scope",
                    ldap3_scope,
                )
                search_result = active_connection.search(
                    base_dn,
                    filter_str,
                    scope_value,
                    attributes=attributes,
                    paged_size=page_size if page_size > 0 else None,
                    paged_cookie=paged_cookie,
                )
                # DIAGNOSTIC: Log search result immediately after call
                self.logger.debug(
                    f"After ldap3.search: success={success}, "
                    f"entries_count={len(active_connection.entries) if success else 'N/A'}, "
                    f"last_error={active_connection.last_error}",
                )
            except LDAPAttributeError as e:
                # If attribute error occurs, retry with all attributes
                attr_str = str(attributes)[:40] if attributes else "None"
                self.logger.debug(
                    "Attribute error with %s, retrying with all attributes: %s",
                    attr_str,
                    e,
                )
                scope_value = cast("FlextLdapConstants.Types.Ldap3Scope", ldap3_scope)
                search_result = active_connection.search(
                    base_dn,
                    filter_str,
                    scope_value,
                    attributes=["*"],
                    paged_size=page_size if page_size > 0 else None,
                    paged_cookie=paged_cookie,
                )
                self.logger.trace(f"Retry after exception: success={success}")

            # Check if search failed due to invalid attribute type
            if not success:
                if active_connection.last_error:
                    error_msg = str(active_connection.last_error).lower()
                    err_trunc = error_msg[:60]
                    self.logger.trace(
                        f"Search failed: success={success}, error='{err_trunc}'",
                    )
                    if (
                        "invalid attribute" in error_msg
                        or "no such attribute" in error_msg
                    ):
                        self.logger.debug(
                            f"Attribute validation failed, retrying: {str(active_connection.last_error)[:50]}",
                        )
                        scope_value = cast(
                            "FlextLdapConstants.Types.Ldap3Scope",
                            ldap3_scope,
                        )
                        search_result = active_connection.search(
                            base_dn,
                            filter_str,
                            scope_value,
                            attributes=["*"],
                            paged_size=page_size if page_size > 0 else None,
                            paged_cookie=paged_cookie,
                        )
                        self.logger.trace(f"Retry after error check: success={success}")
                else:
                    self.logger.trace("Search failed but no last_error available")

            last_error_text = ""
            if active_connection.last_error:
                last_error_text = str(active_connection.last_error)

            # ldap3 returns False when search matches zero results (not an error)
            if not search_result and active_connection.bound and not last_error_text:
                self.logger.debug(
                    "ldap3 returned False with no error (zero results), treating as success",
                )
                success = True

            # For BASE scope searches, noSuchObject means the base DN doesn't exist
            if (
                not success
                and scope.lower() == "base"
                and "noSuchObject" in last_error_text
            ):
                self.logger.debug(
                    "BASE scope search: noSuchObject means base DN doesn't exist (zero results), treating as success",
                )
                success = True

            # DIAGNOSTIC: Log connection state when search fails
            if not success:
                self.logger.warning(
                    f"Search operation failed: "
                    f"connection_bound={active_connection.bound}, "
                    f"last_error={last_error_text or FlextLdapConstants.ErrorStrings.NONE}",
                )

            if not success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Search failed: {last_error_text or 'Connection not established'}",
                )

            # Convert entries to Entry models using flext-ldif
            entries: list[FlextLdifModels.Entry] = []
            if not active_connection.entries:
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            for ldap3_entry in active_connection.entries:
                # Use flext-ldif Entry.from_ldap3 for conversion
                entry_result = FlextLdifModels.Entry.from_ldap3(ldap3_entry)
                if entry_result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Entry conversion failed: {entry_result.error}",
                    )
                entries.append(entry_result.unwrap())

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

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
