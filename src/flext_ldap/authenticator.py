"""LDAP Authenticator - Handles LDAP authentication operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from ldap3 import Connection

from flext_core import FlextResult
from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols


class FlextLdapAuthenticator:
    """LDAP Authenticator - Handles LDAP authentication operations.

    **UNIFIED CLASS PATTERN**: Single class per module with nested helpers only.

    This class manages LDAP authentication including:
    - User credential validation
    - Username-to-DN resolution
    - Bind/unbind operations for authentication
    - Railway pattern error handling

    **PROTOCOL COMPLIANCE**: Implements LdapAuthenticationProtocol methods.
    """

    def __init__(self, parent: FlextLdapClient) -> None:
        """Initialize authenticator with parent client reference.

        Args:
            parent: Parent FlextLdapClient instance for shared state access.
        """
        self._parent = parent

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

        auth_result = self._authenticate_user_credentials(search_result.value, password)
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
            # Validate by attempting a bind with the provided credentials
            # Use parent connection manager's server if available
            if not self._parent._connection_manager._server:
                return FlextResult[bool].fail("No LDAP server connection available")

            # Create a test connection with the user's credentials
            # Type ignore: ldap3.Connection attributes not fully typed in stubs
            test_conn = Connection(
                self._parent._connection_manager._server,
                dn,
                password,
                auto_bind=False,
            )

            # Attempt to bind
            if not test_conn.bind():
                test_conn.unbind()
                return FlextResult[bool].fail("Invalid credentials")

            # Successful bind - credentials are valid
            test_conn.unbind()
            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Credential validation failed: {e}")

    def _validate_connection(self) -> FlextResult[None]:
        """Validate connection is established."""
        if not self._parent._connection:
            return FlextResult[None].fail("LDAP connection not established")
        return FlextResult[None].ok(None)

    def _search_user_by_username(
        self, username: str
    ) -> FlextResult[FlextLdapProtocols.LdapEntry]:
        """Search for user by username using railway pattern."""
        try:
            if not self._parent._connection:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "LDAP connection not established"
                )

            search_filter = f"(|(uid={username})(cn={username}))"
            search_base = "ou=users,dc=example,dc=com"  # Default base

            self._parent._connection.search(
                search_base,
                search_filter,
                self._parent._search_scope,
                attributes=["*"],
            )

            if not self._parent._connection.entries:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail("User not found")

            return FlextResult[FlextLdapProtocols.LdapEntry].ok(
                self._parent._connection.entries[0]
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
            if not self._parent._server:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "No server connection established"
                )

            user_dn = str(user_entry.dn)
            # Use concrete ldap3.Connection type
            test_connection: Connection = Connection(
                self._parent._server,
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
            user = self._parent._create_user_from_entry(user_entry)
            return FlextResult[FlextLdapModels.LdapUser].ok(user)
        except Exception as e:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"User creation failed: {e}"
            )
