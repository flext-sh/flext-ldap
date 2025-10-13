"""LDAP protocol definitions for flext-ldap domain.

This module contains all protocol interfaces and abstract base classes
used throughout the flext-ldap domain. Following FLEXT standards, all
protocols are organized under a single FlextLdapProtocols class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from flext_core import FlextCore
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapProtocols(FlextCore.Protocols):
    """Unified LDAP protocols class extending FlextCore.Protocols with LDAP-specific protocols.

    This class extends the base FlextCore.Protocols with LDAP-specific protocol definitions,
    using Python's typing.Protocol for structural subtyping.

    Contains both high-level service protocols and low-level ldap3 protocols.
    """

    # =========================================================================
    # INHERIT FOUNDATION PROTOCOLS - Available through inheritance from FlextCore.Protocols
    # =========================================================================

    # Foundation, Domain, Application, Infrastructure, Extensions, Commands
    # are all inherited from FlextCore.Protocols - no need to re-export

    # =========================================================================
    # LDAP-SPECIFIC PROTOCOLS - Domain extension for LDAP operations
    # =========================================================================

    class Ldap:
        """LDAP domain-specific protocols."""

        # =====================================================================
        # LOW-LEVEL LDAP3 PROTOCOLS - Direct ldap3 library protocols
        # =====================================================================

        @runtime_checkable
        class LdifOperationsProtocol(Protocol):
            """Protocol for LDIF file operations."""

            def parse_ldif_file(
                self,
                file_path: Path,
                server_type: str = "rfc",
            ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
                """Parse LDIF file and return entries."""
                ...

            def write_file(
                self,
                entries: list[FlextLdifModels.Entry],
                output_path: Path,
            ) -> FlextCore.Result[str]:
                """Write entries to LDIF file."""
                ...

        @runtime_checkable
        class LdapAttribute(Protocol):
            """Protocol for LDAP attribute objects from ldap3."""

            value: object

        @runtime_checkable
        class LdapEntry(Protocol):
            """Protocol for LDAP entry objects from ldap3."""

            dn: str
            attributes: dict[str, FlextCore.Types.StringList]

            def __getitem__(self, key: str) -> FlextLdapProtocols.Ldap.LdapAttribute:
                """Get attribute by key."""
                ...

        @runtime_checkable
        class Ldap3ConnectionProtocol(Protocol):
            """Protocol for ldap3 Connection object with proper type annotations.

            This protocol defines the interface for the low-level ldap3.Connection object.
            """

            bound: bool
            last_error: str
            entries: list[FlextLdapProtocols.Ldap.LdapEntry]

            def bind(self) -> bool:
                """Bind to LDAP server."""
                ...

            def unbind(self) -> bool:
                """Unbind from LDAP server."""
                ...

            def search(
                self,
                search_base: str,
                search_filter: str,
                _search_scope: Literal[
                    FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_BASE,
                    FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_LEVEL,
                    FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE,
                ],
                attributes: FlextCore.Types.StringList | None = None,
                _paged_size: int | None = None,
                paged_cookie: str | bytes | None = None,
                controls: FlextCore.Types.List | None = None,
            ) -> bool:
                """Search LDAP directory."""
                ...

            def add(
                self,
                dn: str,
                attributes: dict[str, str | FlextCore.Types.StringList] | None = None,
            ) -> bool:
                """Add entry to LDAP directory."""
                ...

            def modify(
                self,
                dn: str,
                changes: dict[str, list[tuple[str, FlextCore.Types.StringList]]],
            ) -> bool:
                """Modify LDAP entry."""
                ...

            def delete(self, dn: str) -> bool:
                """Delete LDAP entry."""
                ...

            def compare(self, dn: str, attribute: str, value: str) -> bool:
                """Compare attribute value."""
                ...

            def extended(
                self,
                request_name: str,
                request_value: str | bytes | None = None,
            ) -> bool:
                """Perform extended LDAP operation."""
                ...

        # =====================================================================
        # HIGH-LEVEL SERVICE PROTOCOLS - FlextCore.Result-based service protocols
        # =====================================================================

        @runtime_checkable
        class LdapConnectionProtocol(FlextCore.Protocols.Domain.Service, Protocol):
            """Protocol for LDAP connection operations."""

            def connect(
                self,
                server_uri: str,
                bind_dn: str,
                password: str,
            ) -> FlextCore.Result[bool]:
                """Establish LDAP connection.

                Args:
                    server_uri: LDAP server URI
                    bind_dn: Distinguished name for binding
                    password: Authentication password

                Returns:
                    FlextCore.Result[bool]: Connection success status

                """
                ...

            def disconnect(self) -> FlextCore.Result[None]:
                """Close LDAP connection.

                Returns:
                    FlextCore.Result[None]: Disconnect success status

                """
                ...

            def is_connected(self) -> FlextCore.Result[bool]:
                """Check if LDAP connection is active.

                Returns:
                    FlextCore.Result[bool]: Connection status

                """
                ...

        @runtime_checkable
        class LdapSearchProtocol(FlextCore.Protocols.Domain.Service, Protocol):
            """Protocol for LDAP search operations."""

            def search(
                self,
                search_base: str,
                filter_str: str,
                attributes: FlextCore.Types.StringList | None = None,
            ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
                """Perform LDAP search operation.

                Args:
                    search_base: LDAP search base DN
                    filter_str: LDAP search filter
                    attributes: List of attributes to retrieve

                Returns:
                    FlextCore.Result[list[FlextLdapModels.Entry]]: Search results

                """
                ...

            def search_one(
                self,
                search_base: str,
                filter_str: str,
                attributes: FlextCore.Types.StringList | None = None,
            ) -> FlextCore.Result[FlextCore.Types.Dict | None]:
                """Perform LDAP search for single entry.

                Args:
                    search_base: LDAP search base DN
                    filter_str: LDAP search filter
                    attributes: List of attributes to retrieve

                Returns:
                    FlextCore.Result[FlextCore.Types.Dict | None]: Single search result or None

                """
                ...

        @runtime_checkable
        class LdapModifyProtocol(FlextCore.Protocols.Domain.Service, Protocol):
            """Protocol for LDAP modification operations."""

            def add_entry(
                self,
                dn: str,
                attributes: dict[str, FlextCore.Types.StringList],
            ) -> FlextCore.Result[bool]:
                """Add new LDAP entry.

                Args:
                    dn: Distinguished name for new entry
                    attributes: Entry attributes

                Returns:
                    FlextCore.Result[bool]: Add operation success status

                """
                ...

            def modify_entry(
                self,
                dn: str,
                changes: FlextCore.Types.Dict,
            ) -> FlextCore.Result[bool]:
                """Modify existing LDAP entry.

                Args:
                    dn: Distinguished name of entry to modify
                    changes: Attribute changes to apply

                Returns:
                    FlextCore.Result[bool]: Modify operation success status

                """
                ...

            def delete_entry(self, dn: str) -> FlextCore.Result[bool]:
                """Delete LDAP entry.

                Args:
                    dn: Distinguished name of entry to delete

                Returns:
                    FlextCore.Result[bool]: Delete operation success status

                """
                ...

        @runtime_checkable
        class LdapAuthenticationProtocol(FlextCore.Protocols.Domain.Service, Protocol):
            """Protocol for LDAP authentication operations."""

            def authenticate_user(
                self,
                username: str,
                password: str,
            ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
                """Authenticate user against LDAP.

                Args:
                    username: Username for authentication
                    password: Password for authentication

                Returns:
                    FlextCore.Result[LdapUser]: Authentication result with user object

                """
                ...

            def validate_credentials(
                self, dn: str, password: str
            ) -> FlextCore.Result[bool]:
                """Validate user credentials against LDAP.

                Args:
                    dn: User distinguished name
                    password: User password

                Returns:
                    FlextCore.Result[bool]: Validation success status

                """
                ...

        @runtime_checkable
        class LdapValidationProtocol(FlextCore.Protocols.Domain.Service, Protocol):
            """Protocol for LDAP validation operations."""

            def validate_dn(self, dn: str) -> FlextCore.Result[bool]:
                """Validate distinguished name format.

                Args:
                    dn: Distinguished name to validate

                Returns:
                    FlextCore.Result[bool]: Validation success status

                """
                ...

            def validate_entry(
                self, entry: FlextCore.Types.Dict
            ) -> FlextCore.Result[bool]:
                """Validate LDAP entry structure.

                Args:
                    entry: LDAP entry to validate

                Returns:
                    FlextCore.Result[bool]: Validation success status

                """
                ...

        @runtime_checkable
        class LdapConnectionManagerProtocol(
            FlextCore.Protocols.Domain.Service,
            FlextCore.Protocols.Infrastructure.Connection,
            Protocol,
        ):
            """Protocol for LDAP connection management operations.

            Extends both Domain.Service and Infrastructure.Connection protocols,
            providing LDAP-specific connection management capabilities.
            """

            def connect(
                self,
                server_uri: str,
                bind_dn: str | None = None,
                password: str | None = None,
            ) -> FlextCore.Result[bool]:
                """Establish LDAP connection.

                Args:
                    server_uri: LDAP server URI
                    bind_dn: Bind DN for authentication
                    password: Password for authentication

                Returns:
                    FlextCore.Result[bool]: Connection success status

                """
                ...

            def bind(self, bind_dn: str, password: str) -> FlextCore.Result[bool]:
                """Bind to LDAP server.

                Args:
                    bind_dn: Distinguished name for binding
                    password: Authentication password

                Returns:
                    FlextCore.Result[bool]: Bind success status

                """
                ...

            def unbind(self) -> FlextCore.Result[None]:
                """Unbind from LDAP server.

                Returns:
                    FlextCore.Result[None]: Unbind success status

                """
                ...

            def disconnect(self) -> FlextCore.Result[None]:
                """Disconnect from LDAP server.

                Returns:
                    FlextCore.Result[None]: Disconnect success status

                """
                ...

            def is_connected(self) -> bool:
                """Check if connected to LDAP server.

                Returns:
                    bool: Connection status

                """
                ...

            def test_connection(self) -> FlextCore.Result[bool]:
                """Test LDAP connection.

                Returns:
                    FlextCore.Result[bool]: Connection test success status

                """
                ...

            def close_connection(self) -> FlextCore.Result[None]:
                """Close LDAP connection.

                Returns:
                    FlextCore.Result[None]: Close operation success status

                """
                ...

            def get_connection_string(self) -> FlextCore.Result[str]:
                """Get connection string.

                Returns:
                    FlextCore.Result[str]: Connection string

                """
                ...

        @runtime_checkable
        class LdapSearcherProtocol(FlextCore.Protocols.Domain.Service, Protocol):
            """Protocol for LDAP search operations."""

            def search_one(
                self,
                search_base: str,
                filter_str: str,
                attributes: FlextCore.Types.StringList | None = None,
            ) -> FlextCore.Result[FlextLdapModels.Entry | None]:
                """Search for single LDAP entry.

                Args:
                    search_base: LDAP search base DN
                    filter_str: LDAP search filter
                    attributes: List of attributes to retrieve

                Returns:
                    FlextCore.Result[FlextLdapModels.Entry | None]: Single search result or None

                """
                ...

            def search(
                self,
                base_dn: str,
                filter_str: str,
                attributes: FlextCore.Types.StringList | None = None,
            ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
                """Search for LDAP entries.

                Args:
                    base_dn: LDAP search base DN
                    filter_str: LDAP search filter
                    attributes: List of attributes to retrieve

                Returns:
                    FlextCore.Result[list[FlextLdapModels.Entry]]: Search results

                """
                ...

            def get_user(
                self, dn: str
            ) -> FlextCore.Result[FlextLdapModels.LdapUser | None]:
                """Get user by DN.

                Args:
                    dn: User distinguished name

                Returns:
                    FlextCore.Result[FlextLdapModels.LdapUser | None]: User object or None

                """
                ...

            def get_group(
                self, dn: str
            ) -> FlextCore.Result[FlextLdapModels.Group | None]:
                """Get group by DN.

                Args:
                    dn: Group distinguished name

                Returns:
                    FlextCore.Result[FlextLdapModels.Group | None]: Group object or None

                """
                ...

            def user_exists(self, dn: str) -> FlextCore.Result[bool]:
                """Check if user exists.

                Args:
                    dn: User distinguished name

                Returns:
                    FlextCore.Result[bool]: True if user exists

                """
                ...

            def group_exists(self, dn: str) -> FlextCore.Result[bool]:
                """Check if group exists.

                Args:
                    dn: Group distinguished name

                Returns:
                    FlextCore.Result[bool]: True if group exists

                """
                ...


__all__ = [
    "FlextLdapProtocols",
]
