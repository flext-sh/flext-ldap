"""LDAP authentication operations for flext-ldap.

This module provides unified authentication functionality for LDAP operations
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This module uses proper type annotations with FlextResult[T] for railway-oriented programming.
All type annotations follow FLEXT standards with no hacks or workarounds.
"""

from __future__ import annotations

import contextlib
from typing import cast

from flext_core import FlextModels, FlextResult, FlextService
from ldap3 import SUBTREE, Connection, Server

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes


class FlextLdapAuthentication(FlextService[None]):
    """Unified LDAP authentication operations class.

    This class provides comprehensive LDAP authentication functionality
    with Clean Architecture patterns and flext-core integration.

    **UNIFIED CLASS PATTERN**: One class per module with nested helpers only.
    **CLEAN ARCHITECTURE**: Application layer authentication services.
    **FLEXT INTEGRATION**: Full flext-core service integration.

    Provides LDAP authentication methods:
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

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Authenticate user credentials using FlextResults railways pattern.

        Note: Protocol specifies FlextResult[bool], but this implementation returns
        FlextResult[FlextLdapModels.LdapUser] for richer authentication context.

        Args:
            username: Username to authenticate.
            password: User password.

        Returns:
            FlextResult containing authenticated user or error.

        """
        # Railway pattern: Chain validation -> search -> bind -> create user
        validation_result = self._validate_connection()
        if validation_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                validation_result.error or "Validation failed",
            )

        search_result = self._search_user_by_username(username)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                search_result.error or "Search failed",
            )

        auth_result = self._authenticate_user_credentials(search_result.value, password)
        if auth_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                auth_result.error or "Authentication failed",
            )

        return self._create_user_from_entry_result(auth_result.value)

    def _safe_unbind(self, connection: Connection) -> None:
        """Safely unbind LDAP connection.

            # ldap3 library has incomplete type stubs; external library limitation
        This helper isolates the ldap3.Connection.unbind() call which lacks
        type stubs. The method is private infrastructure layer.

        Args:
            connection: ldap3 Connection to unbind

        """
        with contextlib.suppress(Exception):
            # ldap3 library has incomplete type stubs; external library limitation
            connection.unbind()

    def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate user credentials against LDAP - implements LdapAuthenticationProtocol.

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
                # Create a test connection using the same server but different credentials
                test_connection = Connection(
                    self._server,
                    user=dn,
                    password=password,
                    auto_bind=True,
                    auto_range=True,
                )
                try:
                    # Test the connection by attempting to bind
                    test_connection.bind()
                    is_valid = test_connection.bound
                    return FlextResult[bool].ok(is_valid)
                finally:
                    self._safe_unbind(test_connection)
            else:
                # Fallback: Create a minimal test connection if no context is available
                return FlextResult[bool].fail(
                    "No connection context available for credential validation",
                )
        except Exception as e:
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
        """Search for user by username using railway pattern."""
        try:
            if not self._connection:
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    "LDAP connection not established",
                )

            search_filter = f"(|(uid={username})(cn={username}))"
            # Use config base_dn instead of hardcoded value
            if hasattr(self._ldap_config, "ldap_base_dn") and self._ldap_config:
                search_base = self._ldap_config.ldap_base_dn
            else:
                # Fallback to default if config not available
                search_base = "dc=flext,dc=local"

            if self._connection is None:
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    "LDAP connection not established"
                )

            self._connection.search(
                search_base,
                search_filter,
                SUBTREE,
                attributes=["*"],
            )

            if not self._connection.entries:
                return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                    "User not found",
                )

            return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].ok(
                cast(
                    "FlextLdapTypes.Ldap3Protocols.Entry", self._connection.entries[0]
                ),
            )

        except Exception as e:
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

        except Exception as e:
            return FlextResult[FlextLdapTypes.Ldap3Protocols.Entry].fail(
                f"Authentication failed: {e}",
            )

    def _create_user_from_entry_result(
        self,
        user_entry: FlextLdapTypes.Ldap3Protocols.Entry,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create user from LDAP entry using railway pattern."""
        try:
            # Create user from entry - simplified for now
            # ldap3 Entry uses entry_dn, not dn
            user = FlextLdapModels.LdapUser(
                dn=str(user_entry.entry_dn),
                uid=getattr(user_entry, "uid", [""])[0]
                if hasattr(user_entry, "uid")
                else "",
                cn=getattr(user_entry, "cn", [""])[0]
                if hasattr(user_entry, "cn")
                else "",
                sn=getattr(user_entry, "sn", [""])[0]
                if hasattr(user_entry, "sn")
                else "",
                mail=getattr(user_entry, "mail", [""])[0]
                if hasattr(user_entry, "mail")
                else "",
            )
            return FlextResult[FlextLdapModels.LdapUser].ok(user)
        except Exception as e:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"User creation failed: {e}",
            )

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    def execute_operation(
        self,
        request: FlextModels.OperationExecutionRequest,
    ) -> FlextResult[None]:
        """Execute operation using OperationExecutionRequest model (Domain.Service protocol).

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
