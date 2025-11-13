"""LDAP protocol definitions for flext-ldap domain.

Protocol interfaces and abstract base classes for flext-ldap domain.
All protocols organized under single FlextLdapProtocols class per
FLEXT standardization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection, Server

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants


class FlextLdapProtocols(FlextProtocols):
    """Unified LDAP protocols class extending FlextProtocols.

    This class extends the base FlextProtocols with LDAP-specific protocol definitions,
    using Python's typing.Protocol for structural subtyping.

    Contains both high-level service protocols and low-level ldap3 protocols.
    """

    # =========================================================================
    # INHERIT FOUNDATION PROTOCOLS - Available through inheritance from FlextProtocols
    # =========================================================================

    # Foundation, Domain, Application, Infrastructure, Extensions, Commands
    # are all inherited from FlextProtocols - no need to re-export

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
            """Protocol for LDIF file operations using functional composition.

            Defines the contract for LDIF file processing with railway pattern,
            validation, and error handling.
            """

            def parse_ldif_file(
                self,
                file_path: Path,
                server_type: str = "rfc",
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Parse LDIF file using functional composition and railway pattern.

                Implements file validation, parsing pipeline, and error recovery
                with proper resource management and cleanup.

                Args:
                    file_path: Path to LDIF file (validated for existence and permissions)
                    server_type: Target server type for parsing quirks

                Returns:
                    FlextResult[list[FlextLdifModels.Entry]]: Parsed entries with validation

                """
                ...

            def write_file(
                self,
                entries: list[FlextLdifModels.Entry],
                output_path: Path,
            ) -> FlextResult[str]:
                """Write entries to LDIF file using functional composition.

                Implements validation pipeline, file creation with atomic writes,
                and proper error handling with cleanup on failure.

                Args:
                    entries: List of entries to write (validated)
                    output_path: Output file path (validated for permissions)

                Returns:
                    FlextResult[str]: Success confirmation with file details

                """
                ...

        @runtime_checkable
        class LdapAttribute(Protocol):
            """Protocol for LDAP attribute objects from ldap3."""

            value: str | list[str] | int | bytes | None

        @runtime_checkable
        class LdapEntry(Protocol):
            """Protocol for LDAP entry objects from ldap3."""

            dn: str
            attributes: dict[str, list[str]]

            def __getitem__(self, key: str) -> FlextLdapProtocols.Ldap.LdapAttribute:
                """Get attribute by key."""
                ...

        @runtime_checkable
        class Ldap3ConnectionProtocol(Protocol):
            """Protocol for ldap3 Connection object.

            Defines interface for ldap3.Connection with proper type annotations.
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
                _search_scope: FlextLdapConstants.Types.Ldap3Scope,
                attributes: list[str] | None = None,
                _paged_size: int | None = None,
                paged_cookie: str | bytes | None = None,
                controls: list[object] | None = None,
            ) -> bool:
                """Search LDAP directory."""
                ...

            def add(
                self,
                dn: str,
                attributes: dict[str, str | list[str]] | None = None,
            ) -> bool:
                """Add entry to LDAP directory."""
                ...

            def modify(
                self,
                dn: str,
                changes: dict[str, list[tuple[str, list[str]]]],
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
        # HIGH-LEVEL SERVICE PROTOCOLS - FlextResult-based service protocols
        # =====================================================================

        @runtime_checkable
        class LdapConnectionProtocol(FlextProtocols.Service, Protocol):
            """Protocol for LDAP connection operations using railway pattern.

            Defines the contract for LDAP connection management with functional
            composition and error handling patterns.
            """

            def connect(
                self,
                server_uri: str,
                bind_dn: str,
                password: str,
            ) -> FlextResult[bool]:
                """Establish LDAP connection using functional composition.

                Implements railway pattern for connection establishment with
                proper error propagation and resource management.

                Args:
                    server_uri: LDAP server URI with validation
                    bind_dn: Distinguished name for binding (validated)
                    password: Authentication password (secure handling)

                Returns:
                    FlextResult[bool]: Connection success status with error details

                """
                ...

            def disconnect(self) -> FlextResult[None]:
                """Close LDAP connection with resource cleanup.

                Implements proper resource cleanup using railway pattern,
                ensuring connection is safely closed even on errors.

                Returns:
                    FlextResult[None]: Disconnect success status with cleanup confirmation

                """
                ...

            def is_connected(self) -> FlextResult[bool]:
                """Check if LDAP connection is active using functional validation.

                Performs connection health check with timeout and proper error
                handling using railway pattern.

                Returns:
                    FlextResult[bool]: Connection status with health check details

                """
                ...

        @runtime_checkable
        class LdapSearchProtocol(FlextProtocols.Service, Protocol):
            """Protocol for LDAP search operations."""

            def search(
                self,
                search_base: str,
                filter_str: str,
                attributes: list[str] | None = None,
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Perform LDAP search operation.

                Args:
                search_base: LDAP search base DN
                filter_str: LDAP search filter
                attributes: List of attributes to retrieve

                Returns:
                FlextResult[list[FlextLdifModels.Entry]]: Search results

                """
                ...

            def search_one(
                self,
                search_base: str,
                filter_str: str,
                attributes: list[str] | None = None,
            ) -> FlextResult[dict[str, object] | None]:
                """Perform LDAP search for single entry.

                Args:
                search_base: LDAP search base DN
                filter_str: LDAP search filter
                attributes: List of attributes to retrieve

                Returns:
                FlextResult[dict[str, object] | None]: Single search result or None

                """
                ...

        @runtime_checkable
        class LdapModifyProtocol(FlextProtocols.Service, Protocol):
            """Protocol for LDAP modification operations."""

            def add_entry(
                self,
                dn: str,
                attributes: dict[str, list[str]],
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
                self,
                dn: str,
                changes: dict[str, object],
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
        class LdapAuthenticationProtocol(FlextProtocols.Service, Protocol):
            """Protocol for LDAP authentication operations using functional security.

            Defines secure authentication contracts with railway pattern,
            credential validation, and safe error handling.
            """

            def authenticate_user(
                self,
                username: str,
                password: str,
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Authenticate user against LDAP using functional composition.

                Implements secure authentication pipeline with input sanitization,
                connection validation, and user lookup with proper error masking.

                Args:
                    username: Username for authentication (validated and sanitized)
                    password: Password for authentication (secure handling, not logged)

                Returns:
                    FlextResult[FlextLdifModels.Entry]: User entry on success, masked error on failure

                """
                ...

            def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
                """Validate user credentials against LDAP using railway pattern.

                Performs credential validation with secure error handling,
                timing attack protection, and proper connection management.

                Args:
                    dn: User distinguished name (validated DN format)
                    password: User password (secure handling)

                Returns:
                    FlextResult[bool]: Validation result with security considerations

                """
                ...

            def set_connection_context(
                self,
                connection: Connection | None,
                server: Server | None,
                config: FlextLdapConfig | None,
            ) -> None:
                """Set the connection context for authentication operations.

                Args:
                connection: LDAP connection object
                server: LDAP server object
                config: LDAP configuration object

                """
                ...

        @runtime_checkable
        class LdapValidationProtocol(FlextProtocols.Service, Protocol):
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

        @runtime_checkable
        class LdapConnectionManagerProtocol(
            FlextProtocols.Service,
            Protocol,
        ):
            """Protocol for LDAP connection management operations.

            Provides LDAP-specific connection management capabilities.
            """

            def connect(
                self,
                server_uri: str,
                bind_dn: str | None = None,
                password: str | None = None,
            ) -> FlextResult[bool]:
                """Establish LDAP connection.

                Args:
                server_uri: LDAP server URI
                bind_dn: Bind DN for authentication
                password: Password for authentication

                Returns:
                FlextResult[bool]: Connection success status

                """
                ...

            def bind(self, bind_dn: str, password: str) -> FlextResult[bool]:
                """Bind to LDAP server.

                Args:
                bind_dn: Distinguished name for binding
                password: Authentication password

                Returns:
                FlextResult[bool]: Bind success status

                """
                ...

            def unbind(self) -> FlextResult[None]:
                """Unbind from LDAP server.

                Returns:
                FlextResult[None]: Unbind success status

                """
                ...

            def disconnect(self) -> FlextResult[None]:
                """Disconnect from LDAP server.

                Returns:
                FlextResult[None]: Disconnect success status

                """
                ...

            def is_connected(self) -> bool:
                """Check if connected to LDAP server.

                Returns:
                bool: Connection status

                """
                ...

            def test_connection(self) -> FlextResult[bool]:
                """Test LDAP connection.

                Returns:
                FlextResult[bool]: Connection test success status

                """
                ...

            def close_connection(self) -> FlextResult[None]:
                """Close LDAP connection.

                Returns:
                FlextResult[None]: Close operation success status

                """
                ...

            def get_connection_string(self) -> str:
                """Get connection string.

                Returns:
                str: Connection string

                """
                ...

        @runtime_checkable
        class LdapSearcherProtocol(FlextProtocols.Service, Protocol):
            """Protocol for LDAP search operations."""

            def search_one(
                self,
                search_base: str,
                filter_str: str,
                attributes: list[str] | None = None,
            ) -> FlextResult[FlextLdifModels.Entry | None]:
                """Search for single LDAP entry.

                Args:
                search_base: LDAP search base DN
                filter_str: LDAP search filter
                attributes: List of attributes to retrieve

                Returns:
                FlextResult[FlextLdifModels.Entry | None]: Result or None

                """
                ...

            def search(
                self,
                base_dn: str,
                filter_str: str,
                attributes: list[str] | None = None,
                scope: FlextLdapConstants.Types.Ldap3Scope = "SUBTREE",
                page_size: int = 0,
                paged_cookie: bytes | None = None,
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Search for LDAP entries.

                Args:
                base_dn: LDAP search base DN
                filter_str: LDAP search filter
                attributes: List of attributes to retrieve
                scope: Search scope (BASE, LEVEL, SUBTREE)
                page_size: Page size for paged results
                paged_cookie: Cookie for paged results continuation

                Returns:
                FlextResult[list[FlextLdifModels.Entry]]: Search results

                """
                ...

            def get_user(self, dn: str) -> FlextResult[FlextLdifModels.Entry | None]:
                """Get user by DN.

                Args:
                dn: User distinguished name

                Returns:
                FlextResult[FlextLdifModels.Entry | None]: User object or None

                """
                ...

            def set_connection_context(self, connection: Connection) -> None:
                """Set the connection context for search operations.

                Args:
                connection: LDAP connection object

                """
                ...

            def get_group(self, dn: str) -> FlextResult[FlextLdifModels.Entry | None]:
                """Get group by DN.

                Args:
                dn: Group distinguished name

                Returns:
                FlextResult[FlextLdifModels.Entry | None]: Group object or None

                """
                ...

            def user_exists(self, dn: str) -> FlextResult[bool]:
                """Check if user exists.

                Args:
                dn: User distinguished name

                Returns:
                FlextResult[bool]: True if user exists

                """
                ...

            def group_exists(self, dn: str) -> FlextResult[bool]:
                """Check if group exists.

                Args:
                dn: Group distinguished name

                Returns:
                FlextResult[bool]: True if group exists

                """
                ...

            def sets_mode(
                self,
                quirks_mode: FlextLdapConstants.Types.QuirksMode,
            ) -> None:
                """Set quirks mode for search operations.

                Args:
                quirks_mode: Quirks mode to set (automatic, server, rfc, relaxed)

                """
                ...


__all__ = [
    "FlextLdapProtocols",
]
