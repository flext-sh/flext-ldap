"""LDAP authentication operations for flext-ldap.

This module provides unified authentication functionality for LDAP operations
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
)

from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.typings import FlextLdapTypes


class FlextLdapAuthentication(FlextService[None], FlextLdapProtocols.LdapAuthenticationProtocol):
    """Unified LDAP authentication operations class.

    This class provides comprehensive LDAP authentication functionality
    with Clean Architecture patterns and flext-core integration.

    **UNIFIED CLASS PATTERN**: One class per module with nested helpers only.
    **CLEAN ARCHITECTURE**: Application layer authentication services.
    **FLEXT INTEGRATION**: Full flext-core service integration with protocols.

    Implements FlextLdapProtocols.LdapAuthenticationProtocol:
    - authenticate_user: Authenticate user with username/password
    - validate_credentials: Validate DN/password credentials
    """

    def __init__(self) -> None:
        """Initialize LDAP authentication service."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        # These will be set by the client that uses this service
        self._connection = None
        self._server = None
        self._config = None

    @classmethod
    def create(cls) -> FlextLdapAuthentication:
        """Create a new FlextLdapAuthentication instance (factory method)."""
        return cls()

    def set_connection_context(
        self,
        connection: object,
        server: object,
        config: object,
    ) -> None:
        """Set the connection context for authentication operations.

        Args:
            connection: LDAP connection object
            server: LDAP server object
            config: LDAP configuration object
        """
        self._connection = connection
        self._server = server
        self._config = config

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Authenticate user credentials using FlextResults railways pattern.

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
                validation_result.error or "Validation failed"
            )

        search_result = self._search_user_by_username(username)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                search_result.error or "Search failed"
            )

        auth_result = self._authenticate_user_credentials(
            search_result.value, password
        )
        if auth_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                auth_result.error or "Authentication failed"
            )

        return self._create_user_from_entry_result(auth_result.value)

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
            # Create a test connection with the provided credentials
            # Import here to avoid circular imports
            from flext_ldap.connection import FlextLdapConnection

            test_connection = FlextLdapConnection()
            connection_result = test_connection.bind(dn, password)
            test_connection.disconnect()
            return FlextResult[bool].ok(connection_result.is_success)
        except Exception as e:
            return FlextResult[bool].fail(f"Credential validation failed: {e}")

    def _validate_connection(self) -> FlextResult[None]:
        """Validate connection is established."""
        if not self._connection:
            return FlextResult[None].fail("LDAP connection not established")
        return FlextResult[None].ok(None)

    def _search_user_by_username(
        self, username: str
    ) -> FlextResult[FlextLdapProtocols.LdapEntry]:
        """Search for user by username using railway pattern."""
        try:
            if not self._connection:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "LDAP connection not established"
                )

            search_filter = f"(|(uid={username})(cn={username}))"
            search_base = "ou=users,dc=example,dc=com"  # Default base

            self._connection.search(
                search_base,
                search_filter,
                FlextLdapTypes.SUBTREE,
                attributes=["*"],
            )

            if not self._connection.entries:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "User not found"
                )

            return FlextResult[FlextLdapProtocols.LdapEntry].ok(
                self._connection.entries[0]
            )

        except Exception as e:
            return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                f"User search failed: {e}"
            )

    def _authenticate_user_credentials(
        self, user_entry: FlextLdapProtocols.LdapEntry, password: str
    ) -> FlextResult[FlextLdapProtocols.LdapEntry]:
        """Authenticate user credentials using railway pattern."""
        try:
            if not self._server:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "No server connection established"
                )

            from ldap3 import Connection
            user_dn = str(user_entry.dn)
            # Use concrete ldap3.Connection type
            test_connection: Connection = Connection(
                self._server,
                user_dn,
                password,
                auto_bind=False,
            )

            if not test_connection.bind():
                test_connection.unbind()
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "Authentication failed"
                )

            test_connection.unbind()
            return FlextResult[FlextLdapProtocols.LdapEntry].ok(user_entry)

        except Exception as e:
            return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                f"Authentication failed: {e}"
            )

    def _create_user_from_entry_result(
        self, user_entry: FlextLdapProtocols.LdapEntry
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create user from LDAP entry using railway pattern."""
        try:
            # Create user from entry - simplified for now
            user = FlextLdapModels.LdapUser(
                dn=str(user_entry.dn),
                uid=getattr(user_entry, "uid", [""])[0] if hasattr(user_entry, "uid") else "",
                cn=getattr(user_entry, "cn", [""])[0] if hasattr(user_entry, "cn") else "",
                sn=getattr(user_entry, "sn", [""])[0] if hasattr(user_entry, "sn") else "",
                mail=getattr(user_entry, "mail", [""])[0] if hasattr(user_entry, "mail") else "",
            )
            return FlextResult[FlextLdapModels.LdapUser].ok(user)
        except Exception as e:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"User creation failed: {e}"
            )


__all__ = [
    "FlextLdapAuthentication",
]