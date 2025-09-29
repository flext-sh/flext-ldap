"""LDAP protocol definitions for flext-ldap domain.

This module contains all protocol interfaces and abstract base classes
used throughout the flext-ldap domain. Following FLEXT standards, all
protocols are organized under a single FlextLdapProtocols class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult


class FlextLdapProtocols(FlextProtocols):
    """Unified LDAP protocols class extending FlextProtocols with LDAP-specific protocols.

    This class extends the base FlextProtocols with LDAP-specific protocol definitions,
    using Python's typing.Protocol for structural subtyping.
    """

    @runtime_checkable
    class LdapConnectionProtocol(FlextProtocols.Domain.Service, Protocol):
        """Protocol for LDAP connection operations."""

        def connect(
            self, server_uri: str, bind_dn: str, password: str
        ) -> FlextResult[bool]:
            """Establish LDAP connection.

            Args:
                server_uri: LDAP server URI
                bind_dn: Distinguished name for binding
                password: Authentication password

            Returns:
                FlextResult[bool]: Connection success status

            """
            ...

        def disconnect(self) -> FlextResult[None]:
            """Close LDAP connection.

            Returns:
                FlextResult[None]: Disconnect success status

            """
            ...

        def is_connected(self) -> FlextResult[bool]:
            """Check if LDAP connection is active.

            Returns:
                FlextResult[bool]: Connection status

            """
            ...

    @runtime_checkable
    class LdapSearchProtocol(FlextProtocols.Domain.Service, Protocol):
        """Protocol for LDAP search operations."""

        def search(
            self,
            search_base: str,
            search_filter: str,
            attributes: list[str] | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Perform LDAP search operation.

            Args:
                search_base: LDAP search base DN
                search_filter: LDAP search filter
                attributes: List of attributes to retrieve

            Returns:
                FlextResult[list[dict[str, object]]]: Search results

            """
            ...

        def search_one(
            self,
            search_base: str,
            search_filter: str,
            attributes: list[str] | None = None,
        ) -> FlextResult[dict[str, object] | None]:
            """Perform LDAP search for single entry.

            Args:
                search_base: LDAP search base DN
                search_filter: LDAP search filter
                attributes: List of attributes to retrieve

            Returns:
                FlextResult[dict[str, object] | None]: Single search result or None

            """
            ...

    @runtime_checkable
    class LdapModifyProtocol(FlextProtocols.Domain.Service, Protocol):
        """Protocol for LDAP modification operations."""

        def add_entry(
            self, dn: str, attributes: dict[str, list[str]]
        ) -> FlextResult[bool]:
            """Add new LDAP entry.

            Args:
                dn: Distinguished name for new entry
                attributes: Entry attributes

            Returns:
                FlextResult[bool]: Add operation success status

            """
            ...

        def modify_entry(
            self, dn: str, changes: dict[str, object]
        ) -> FlextResult[bool]:
            """Modify existing LDAP entry.

            Args:
                dn: Distinguished name of entry to modify
                changes: Attribute changes to apply

            Returns:
                FlextResult[bool]: Modify operation success status

            """
            ...

        def delete_entry(self, dn: str) -> FlextResult[bool]:
            """Delete LDAP entry.

            Args:
                dn: Distinguished name of entry to delete

            Returns:
                FlextResult[bool]: Delete operation success status

            """
            ...

    @runtime_checkable
    class LdapAuthenticationProtocol(FlextProtocols.Domain.Service, Protocol):
        """Protocol for LDAP authentication operations."""

        def authenticate_user(self, username: str, password: str) -> FlextResult[bool]:
            """Authenticate user against LDAP.

            Args:
                username: Username for authentication
                password: Password for authentication

            Returns:
                FlextResult[bool]: Authentication success status

            """
            ...

        def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
            """Validate user credentials against LDAP.

            Args:
                dn: User distinguished name
                password: User password

            Returns:
                FlextResult[bool]: Validation success status

            """
            ...

    @runtime_checkable
    class LdapValidationProtocol(FlextProtocols.Domain.Service, Protocol):
        """Protocol for LDAP validation operations."""

        def validate_dn(self, dn: str) -> FlextResult[bool]:
            """Validate distinguished name format.

            Args:
                dn: Distinguished name to validate

            Returns:
                FlextResult[bool]: Validation success status

            """
            ...

        def validate_entry(self, entry: dict[str, object]) -> FlextResult[bool]:
            """Validate LDAP entry structure.

            Args:
                entry: LDAP entry to validate

            Returns:
                FlextResult[bool]: Validation success status

            """
            ...


__all__ = [
    "FlextLdapProtocols",
]
