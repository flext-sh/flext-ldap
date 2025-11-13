"""LDAP authentication operations for flext-ldap.

Unified authentication functionality for LDAP operations with Clean
Architecture patterns and FlextResult[T] railway-oriented programming.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextDecorators, FlextModels, FlextResult, FlextService
from flext_ldif import FlextLdifModels
from ldap3 import SUBTREE, Connection, Entry as Ldap3Entry, Server
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPCommunicationError,
    LDAPInvalidDnError,
    LDAPInvalidFilterError,
    LDAPInvalidScopeError,
    LDAPPasswordIsMandatoryError,
    LDAPResponseTimeoutError,
    LDAPSocketOpenError,
    LDAPUserNameIsMandatoryError,
)

from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.typings import FlextLdapTypes


class FlextLdapAuthentication(FlextService[None]):
    """Unified LDAP authentication operations class.

    Provides LDAP authentication functionality with Clean Architecture
    patterns and flext-core integration for result handling and logging.

    Methods:
    - authenticate_user: Authenticate user with username/password
    - validate_credentials: Validate DN/password credentials

    """

    def __init__(self) -> None:
        """Initialize LDAP authentication service."""
        super().__init__()
        # Type annotation: FlextLogger is not Optional (override from FlextService)
        # These will be set by the client that uses this service
        # Type hints enable static type checking without runtime overhead
        self._connection: Connection | None = None
        self._server: Server | None = None
        self._ldap_config: FlextLdapConfig | None = None

    def set_connection_context(
        self,
        connection: Connection | None,
        server: Server | None,
        config: FlextLdapConfig | None,
    ) -> None:
        """Set the connection context for authentication operations.

        Args:
        connection: LDAP connection object (ldap3.Connection)
        server: LDAP server object (ldap3.Server)
        config: LDAP configuration object

        """
        self._connection = connection
        self._server = server
        self._ldap_config = config

    @FlextDecorators.log_operation("LDAP User Authentication")
    @FlextDecorators.track_performance("LDAP User Authentication")
    @FlextDecorators.timeout(timeout_seconds=15.0)
    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Authenticate user credentials using FlextResults railways pattern.

        Note: Protocol specifies FlextResult[bool], but this implementation returns
        FlextResult[FlextLdifModels.Entry] for richer authentication context.

        Args:
        username: Username to authenticate.
        password: User password.

        Returns:
        FlextResult containing authenticated user or error.

        """
        # Railway pattern: Chain validation -> search -> bind -> create user
        validation_result = self._validate_connection()
        if validation_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                validation_result.error or "Validation failed",
            )

        search_result = self._search_user_by_username(username)
        if search_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                search_result.error or "Search failed",
            )

        auth_result = self._authenticate_user_credentials(search_result.value, password)
        if auth_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                auth_result.error or "Authentication failed",
            )

        return self._create_user_from_entry_result(auth_result.value)

    def _safe_unbind(self, connection: Connection) -> None:
        """Safely unbind LDAP connection.

        # ldap3 library has incomplete type stubs; external library limitation
        This helper isolates the ldap3.Connection.unbind() call which lacks
        type stubs. The method is private infrastructure layer.

        Unbind failures during cleanup are logged for diagnostics but not
        propagated, as cleanup operations should not raise exceptions.

        Args:
        connection: ldap3 Connection to unbind

        """
        try:
            # Cast to Protocol type for proper type checking with ldap3
            typed_connection = cast(
                "FlextLdapTypes.Ldap3Protocols.Connection",
                connection,
            )
            typed_connection.unbind()
        except Exception as e:
            # Log for diagnostics, but don't propagate during cleanup
            self.logger.debug("Unbind during cleanup failed (non-critical): %s", e)

    @FlextDecorators.log_operation("LDAP Credential Validation")
    @FlextDecorators.track_performance("LDAP Credential Validation")
    @FlextDecorators.timeout(timeout_seconds=10.0)
    def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate user credentials against LDAP server.

        Args:
        dn: User distinguished name
        password: User password

        Returns:
        FlextResult[bool]: Validation success status

        """
        # Use existing authenticate_user logic adapted for DN-based validation
        try:
            # Use the existing connection context if available
            if self._connection is not None and self._server is not None:
                # Create test connection with alternate credentials
                # Use auto_bind=False to capture specific error messages
                test_connection = Connection(
                    self._server,
                    user=dn,
                    password=password,
                    auto_bind=False,
                    auto_range=True,
                )
                try:
                    # Test the connection by attempting to bind
                    bind_result = test_connection.bind()
                    if not bind_result:
                        return FlextResult[bool].fail(
                            f"Credential validation failed: {test_connection.last_error}"
                        )
                    is_valid = test_connection.bound
                    return FlextResult[bool].ok(is_valid)
                finally:
                    self._safe_unbind(test_connection)
            else:
                # Fallback: Create a minimal test connection if no context is available
                return FlextResult[bool].fail(
                    "No connection context available for credential validation",
                )
        except (
            LDAPSocketOpenError,
            LDAPCommunicationError,
            LDAPBindError,
            LDAPPasswordIsMandatoryError,
            LDAPUserNameIsMandatoryError,
        ) as e:
            return FlextResult[bool].fail(f"Credential validation failed: {e}")

    def _validate_connection(self) -> FlextResult[None]:
        """Validate connection is established."""
        if not self._connection:
            return FlextResult[None].fail("LDAP connection not established")
        return FlextResult[None].ok(None)

    def _search_user_by_username(
        self,
        username: str,
    ) -> FlextResult[FlextLdapTypes.Ldap3Protocols.Entry]:
        """Search for user by username using railway pattern (refactored from 6 returns to 4)."""
        try:
            # Early validation - return 1 (removed duplicate check at line 212-215)
            if not self._connection:
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    "LDAP connection not established",
                )

            # Determine search base from config or fallback
            search_filter = f"(|(uid={username})(cn={username}))"
            search_base = (
                self._ldap_config.ldap_base_dn
                if hasattr(self._ldap_config, "ldap_base_dn") and self._ldap_config
                else "dc=flext,dc=local"
            )

            # Perform search
            search_result = self._connection.search(
                search_base,
                search_filter,
                SUBTREE,
                attributes=["*"],
            )

            # Consolidated validation (merged search_result and entries checks)
            # return 2 for search failures, return 3 for success
            if not search_result:
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    f"User search failed: {self._connection.last_error}",
                )

            if not self._connection.entries:
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    "User not found",
                )

            # Success return - return 3
            return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].ok(
                cast(
                    "FlextLdapTypes.Ldap3Protocols.Entry",
                    self._connection.entries[0],
                ),
            )

        except (
            LDAPCommunicationError,
            LDAPResponseTimeoutError,
            LDAPInvalidFilterError,
            LDAPInvalidScopeError,
            LDAPInvalidDnError,
        ) as e:
            # Exception return - return 4
            return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                f"User search failed: {e}",
            )

    def _authenticate_user_credentials(
        self,
        user_entry: FlextLdapTypes.Ldap3Protocols.Entry,
        password: str,
    ) -> FlextResult[FlextLdapTypes.Ldap3Protocols.Entry]:
        """Authenticate user credentials using railway pattern."""
        try:
            if not self._server:
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    "No server connection established",
                )

            # ldap3 Entry uses entry_dn, not dn
            user_dn = str(user_entry.entry_dn)
            # Use ldap3 Connection for proper typing
            test_connection: Connection = Connection(
                self._server,
                user_dn,
                password,
                auto_bind=False,
            )

            if not test_connection.bind():
                self._safe_unbind(test_connection)
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    "Authentication failed",
                )

            self._safe_unbind(test_connection)
            return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].ok(user_entry)

        except (
            LDAPSocketOpenError,
            LDAPCommunicationError,
            LDAPBindError,
            LDAPPasswordIsMandatoryError,
        ) as e:
            return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                f"Authentication failed: {e}",
            )

    def _create_user_from_entry_result(
        self,
        user_entry: FlextLdapTypes.Ldap3Protocols.Entry | FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert user entry to FlextLdifModels.Entry using entry_adapter.

        Uses FlextLdapEntryAdapter for consistent ldap3 ↔ FlextLdif conversion.
        Accepts both ldap3 entries and FlextLdif entries.
        """
        # Handle both ldap3 Entry and FlextLdif Entry types
        if isinstance(user_entry, FlextLdifModels.Entry):
            # Modern Entry API: Already validated, just return it
            if not user_entry.dn or not user_entry.dn.value:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Entry must have a valid DN",
                )
            return FlextResult[FlextLdifModels.Entry].ok(user_entry)

        # Use FlextLdapEntryAdapter for ldap3 → FlextLdif conversion
        adapter = FlextLdapEntryAdapter()
        # Cast Protocol type to concrete ldap3.Entry for adapter compatibility
        concrete_entry = cast("Ldap3Entry", user_entry)
        return adapter.ldap3_to_ldif_entry(concrete_entry)

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    def execute_operation(
        self,
        request: FlextModels.OperationExecutionRequest,
    ) -> FlextResult[None]:
        """Execute operation from OperationExecutionRequest model.

        Args:
        request: OperationExecutionRequest containing operation settings

        Returns:
        FlextResult[object]: Success with result or failure with error

        """
        # Use request parameter to satisfy protocol requirements
        _ = request
        return self.execute()


__all__ = [
    "FlextLdapAuthentication",
]
