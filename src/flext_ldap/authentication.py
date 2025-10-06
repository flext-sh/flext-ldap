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
    FlextResult,
    FlextService,
)
from flext_ldap.models import FlextLDAPModels
from flext_ldap.protocols import FlextLDAPProtocols
from flext_ldap.typings import FlextLDAPTypes

from ldap3 import Connection, Server


class FlextLDAPAuthentication(FlextService[None]):
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
        self._ldap_config: object | None = None

    @classmethod
    def create(cls) -> FlextLDAPAuthentication:
        """Create a new FlextLDAPAuthentication instance (factory method)."""
        return cls()

    def set_connection_context(
        self,
        connection: Connection,
        server: Server,
        config: object,
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
    ) -> FlextResult[FlextLDAPModels.LdapUser]:
        """Authenticate user credentials using FlextResults railways pattern.

        Note: Protocol specifies FlextResult[bool], but this implementation returns
        FlextResult[FlextLDAPModels.LdapUser] for richer authentication context.

        Args:
            username: Username to authenticate.
            password: User password.

        Returns:
            FlextResult containing authenticated user or error.

        """
        # Railway pattern: Chain validation -> search -> bind -> create user
        validation_result = self._validate_connection()
        if validation_result.is_failure:
            return FlextResult[FlextLDAPModels.LdapUser].fail(
                validation_result.error or "Validation failed"
            )

        search_result = self._search_user_by_username(username)
        if search_result.is_failure:
            return FlextResult[FlextLDAPModels.LdapUser].fail(
                search_result.error or "Search failed"
            )

        auth_result = self._authenticate_user_credentials(search_result.value, password)
        if auth_result.is_failure:
            return FlextResult[FlextLDAPModels.LdapUser].fail(
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
            from flext_ldap.connection import FlextLDAPConnection

            test_connection = FlextLDAPConnection()
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
    ) -> FlextResult[FlextLDAPProtocols.Ldap.LdapEntry]:
        """Search for user by username using railway pattern."""
        try:
            if not self._connection:
                return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].fail(
                    "LDAP connection not established"
                )

            search_filter = f"(|(uid={username})(cn={username}))"
            search_base = "ou=users,dc=example,dc=com"  # Default base

            self._connection.search(
                search_base,
                search_filter,
                FlextLDAPTypes.SUBTREE,
                attributes=["*"],
            )

            if not self._connection.entries:
                return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].fail(
                    "User not found"
                )

            return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].ok(
                self._connection.entries[0]
            )

        except Exception as e:
            return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].fail(
                f"User search failed: {e}"
            )

    def _authenticate_user_credentials(
        self, user_entry: FlextLDAPProtocols.Ldap.LdapEntry, password: str
    ) -> FlextResult[FlextLDAPProtocols.Ldap.LdapEntry]:
        """Authenticate user credentials using railway pattern."""
        try:
            if not self._server:
                return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].fail(
                    "No server connection established"
                )

            user_dn = str(user_entry.dn)
            # Use FlextLDAPTypes.Connection for proper typing
            test_connection: FlextLDAPTypes.Connection = FlextLDAPTypes.Connection(
                self._server,
                user_dn,
                password,
                auto_bind=False,
            )

            if not test_connection.bind():
                test_connection.unbind()
                return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].fail(
                    "Authentication failed"
                )

            test_connection.unbind()
            return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].ok(user_entry)

        except Exception as e:
            return FlextResult[FlextLDAPProtocols.Ldap.LdapEntry].fail(
                f"Authentication failed: {e}"
            )

    def _create_user_from_entry_result(
        self, user_entry: FlextLDAPProtocols.Ldap.LdapEntry
    ) -> FlextResult[FlextLDAPModels.LdapUser]:
        """Create user from LDAP entry using railway pattern."""
        try:
            # Create user from entry - simplified for now
            user = FlextLDAPModels.LdapUser(
                dn=str(user_entry.dn),
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
            return FlextResult[FlextLDAPModels.LdapUser].ok(user)
        except Exception as e:
            return FlextResult[FlextLDAPModels.LdapUser].fail(
                f"User creation failed: {e}"
            )

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)


__all__ = [
    "FlextLDAPAuthentication",
]
