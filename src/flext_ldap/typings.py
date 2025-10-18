"""LDAP domain type exports - centralized in FlextTypes.Ldap.

This module consolidates all type aliases, type definitions, and protocol
definitions used throughout the flext-ldap domain. Following FLEXT standards,
all types are organized under a single FlextLdapTypes class and extend
centralized types from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated, Any, Protocol

from flext_core import FlextTypes
from pydantic import Field

from flext_ldap.constants import (
    AclType,
    AuthenticationMethod,
    ConnectionState,
    LdapProjectType,
    ObjectClassKind,
    OperationType,
    SecurityLevel,
    UpdateStrategy,
)

# =========================================================================
# MODULE-LEVEL TYPE ALIASES - LDAP Dictionary Types (Consolidated)
# =========================================================================

# Core LDAP attribute dictionary: attribute_name → attribute_value(s)
type LdapAttributeDict = dict[str, str | list[str]]

# Entry attributes as dict: attribute_name → values (always list)
type LdapEntryAttributeDict = dict[str, list[str]]

# Complex LDAP entry with mixed attribute types
type LdapComplexEntryDict = dict[str, list[str] | str]

# LDAP modify operation: attribute_name → [(operation, values), ...]
type LdapModifyDict = dict[str, list[tuple[str, list[str]]]]

# LDAP search result entries (compatible with ldap3 response format)
type LdapSearchResultDict = dict[str, dict[str, list[str]] | str]

# Configuration dictionaries (more flexible than dict[str, object])
type LdapConfigDict = dict[str, str | int | bool | list[str] | None]

# Schema attribute dictionary
type LdapSchemaAttributeDict = dict[str, str | list[str] | bool | None]

# LDAP response dictionary from ldap3 operations
type LdapResponseDict = dict[str, str | int | bool | list[str] | None]

# LDAP entry template for creating entries
type LdapEntryTemplateDict = dict[str, str | list[str]]

# =========================================================================
# MODULE-LEVEL TYPE ALIASES - LDAP Domain Types (Consolidated)
# =========================================================================

# Core LDAP attribute and value types
type AttributeValue = str | list[str]
type AttributeDict = dict[str, AttributeValue]
type ModifyChanges = dict[str, list[tuple[str, list[str]]]]

# LDAP search and filter types
type SearchFilter = str
type SearchResult = list[LdapSearchResultDict]

# LDAP connection and server types
type ServerURI = str
type BindDN = str
type BindPassword = str
type DistinguishedName = str

# LDAP protocol types
type ObjectClass = str
type AttributeName = str

# Complex LDAP operation types
type BulkOperation = list[dict[str, AttributeValue | OperationType]]
type SearchConfiguration = dict[str, str | int | list[str]]
type EntryTemplate = dict[str, AttributeValue | list[ObjectClass]]

# =========================================================================
# MODULE-LEVEL TYPE ALIASES - LDAP Config Types (Consolidated)
# =========================================================================

# Core configuration types
type ServerConfig = dict[str, str | int | bool | list[str] | None]
type ConnectionConfig = dict[str, str | int | bool | list[str] | None]
type AuthenticationConfig = dict[str, str | bool | list[str] | None]
type SearchConfig = dict[str, str | int | bool | list[str] | None]

# Advanced configuration types
type ServerPoolConfig = dict[str, list[str] | int | bool | None]
type RetryConfig = dict[str, int | float | bool | None]
type TimeoutConfig = dict[str, int | float | None]

# =========================================================================
# MODULE-LEVEL TYPE ALIASES - LDAP Core Composite Types (Consolidated)
# =========================================================================

# LDAP-specific configuration value (composite type)
type LdapConfigValue = (
    str | int | bool | list[str] | dict[str, str | int | bool | list[str] | None]
)

# LDAP-specific attribute value (composite type)
type LdapAttributeValue = str | list[str] | dict[str, str | list[str]]

# LDAP-specific entry value (composite type)
type LdapEntryValue = dict[str, str | list[str]]

# =========================================================================
# MODULE-LEVEL TYPE ALIASES - LDAP Project Types (Consolidated)
# =========================================================================

type LdapProjectConfig = dict[str, str | int | bool | list[str] | None]
type DirectoryConfig = dict[str, str | int | bool | list[str]]
type SyncConfig = dict[str, LdapConfigValue | object]


class FlextLdapTypes(FlextTypes):
    """LDAP types class extending FlextTypes with LDAP-specific definitions.

    Extends base FlextTypes with LDAP-specific aliases, variables,
    definitions, and protocols following FLEXT domain separation patterns.
    All types centralized and extend from flext-core.

    Following FLEXT standards:
    - Single unified class per module (ONE CLASS PER MODULE)
    - Extends FlextTypes from flext-core
    - No duplicate type definitions
    - Centralized type management
    - Python 3.13+ syntax
    """

    # =========================================================================
    # ANNOTATED LDAP TYPES - Pydantic v2 Annotated types with validation
    # =========================================================================

    class AnnotatedLdap:
        """LDAP-specific Annotated types with built-in validation constraints.

        Provides reusable Annotated type definitions for LDAP-specific field patterns,
        eliminating verbose Field() declarations in LDAP models and services.

        Example:
            from flext_ldap.typings import FlextLdapTypes
            from pydantic import BaseModel

            class LdapConnectionConfig(BaseModel):
                server_uri: FlextLdapTypes.AnnotatedLdap.ServerUri
                bind_dn: FlextLdapTypes.AnnotatedLdap.BindDN
                port: FlextLdapTypes.AnnotatedLdap.LdapPort
                timeout: FlextLdapTypes.AnnotatedLdap.ConnectionTimeout

        """

        # Distinguished Name and Attribute Types
        DistinguishedName = Annotated[str, Field(min_length=1, max_length=512)]
        """LDAP Distinguished Name (DN) with length constraints."""

        BindDN = Annotated[str, Field(min_length=1, max_length=512)]
        """Bind DN for LDAP authentication."""

        BaseDN = Annotated[str, Field(min_length=1, max_length=512)]
        """Base DN for LDAP search operations."""

        AttributeName = Annotated[
            str,
            Field(pattern=r"^[a-zA-Z]([a-zA-Z0-9\-]*)?$", min_length=1, max_length=128),
        ]
        """LDAP attribute name with format validation."""

        ObjectClassName = Annotated[
            str,
            Field(pattern=r"^[a-zA-Z]([a-zA-Z0-9\-]*)?$", min_length=1, max_length=64),
        ]
        """LDAP objectClass name with format validation."""

        # Search and Filter Types
        SearchFilter = Annotated[str, Field(min_length=1, max_length=1024)]
        """LDAP search filter string."""

        SearchScope = Annotated[
            str, Field(pattern=r"^(BASE|LEVEL|SUBTREE|SUBORDINATE)$")
        ]
        """LDAP search scope selector."""

        # Server and Connection Types
        ServerUri = Annotated[str, Field(min_length=5, max_length=256)]
        """LDAP server URI (e.g., ldap://localhost:389)."""

        ServerHostname = Annotated[str, Field(min_length=1, max_length=256)]
        """LDAP server hostname or IP address."""

        LdapPort = Annotated[int, Field(ge=1, le=65535)]
        """LDAP server port number (valid range: 1-65535)."""

        ConnectionTimeout = Annotated[int, Field(ge=1, le=300)]
        """LDAP connection timeout in seconds (1-300 seconds)."""

        ReceiveTimeout = Annotated[int, Field(ge=1, le=300)]
        """LDAP receive timeout in seconds (1-300 seconds)."""

        # Authentication Types
        BindPassword = Annotated[str, Field(min_length=1, max_length=512)]
        """Password for LDAP bind operations."""

        AuthMethod = Annotated[str, Field(pattern=r"^(SIMPLE|SASL_DIGEST_MD5|NTLM)$")]
        """LDAP authentication method."""

        # Operation and Processing Types
        MaxResults = Annotated[int, Field(ge=1, le=1000000)]
        """Maximum number of search results (1-1000000)."""

        BatchSize = Annotated[int, Field(ge=1, le=100000)]
        """Batch processing size for bulk operations (1-100000)."""

        MaxRetries = Annotated[int, Field(ge=0, le=10)]
        """Maximum number of connection retries (0-10)."""

        RetryInterval = Annotated[int, Field(ge=1, le=60)]
        """Retry interval in seconds (1-60 seconds)."""

        OperationTimeout = Annotated[int, Field(ge=5, le=600)]
        """LDAP operation timeout in seconds (5-600 seconds)."""

        # Pool and Connection Management Types
        PoolSize = Annotated[int, Field(ge=1, le=100)]
        """Connection pool size (1-100 connections)."""

        MaxConnections = Annotated[int, Field(ge=1, le=500)]
        """Maximum number of connections (1-500)."""

        # Size and Constraint Types
        PageSize = Annotated[int, Field(ge=1, le=100000)]
        """Page size for paged LDAP searches (1-100000)."""

        EntryCount = Annotated[int, Field(ge=0)]
        """Number of LDIF entries processed."""

        ErrorCount = Annotated[int, Field(ge=0)]
        """Number of errors encountered."""

        SuccessRate = Annotated[float, Field(ge=0.0, le=100.0)]
        """Success percentage (0-100%)."""

    # =========================================================================
    # LDAP3 TYPE STUBS - Protocol definitions for ldap3 library types
    # =========================================================================

    class Ldap3Protocols:
        """Protocol definitions for ldap3 library types.

        The ldap3 library has incomplete type stubs. These Protocol classes provide
        proper typing for ldap3.Connection, ldap3.Entry, and ldap3.Server classes
        used throughout flext-ldap.

        Use these instead of type: ignore comments for proper type safety.
        """

        class Connection(Protocol):
            """Protocol for ldap3.Connection with proper type hints.

            Provides type hints for all ldap3.Connection methods and properties
            used in flext-ldap codebase.
            """

            # Properties
            @property
            def entries(self) -> list[Any]:
                """List of Entry objects from last search operation."""
                ...

            @property
            def bound(self) -> bool:
                """Whether connection is currently bound."""
                ...

            @property
            def result(self) -> dict[str, Any]:
                """Result of last LDAP operation."""
                ...

            @property
            def response(self) -> list[dict[str, Any]]:
                """Response from last LDAP operation."""
                ...

            # Methods
            def bind(self) -> bool:
                """Bind to LDAP server. Returns True if successful."""
                ...

            def unbind(self) -> bool:
                """Unbind from LDAP server. Returns True if successful."""
                ...

            def search(
                self,
                search_base: str,
                search_filter: str,
                search_scope: str | int,
                attributes: list[str] | None = None,
                **kwargs: Any,
            ) -> bool:
                """Execute LDAP search. Returns True if successful."""
                ...

            def add(
                self,
                dn: str,
                object_class: str | list[str] | None = None,
                attributes: dict[str, Any] | None = None,
                **kwargs: Any,
            ) -> bool:
                """Add LDAP entry. Returns True if successful."""
                ...

            def modify(
                self,
                dn: str,
                changes: dict[str, Any],
                **kwargs: Any,
            ) -> bool:
                """Modify LDAP entry. Returns True if successful."""
                ...

            def delete(self, dn: str, **kwargs: Any) -> bool:
                """Delete LDAP entry. Returns True if successful."""
                ...

        class Entry(Protocol):
            """Protocol for ldap3.Entry with proper type hints.

            Provides type hints for ldap3.Entry properties and methods
            used in flext-ldap codebase.
            """

            @property
            def entry_dn(self) -> str:
                """Distinguished Name of the entry."""
                ...

            @property
            def entry_attributes_as_dict(self) -> dict[str, Any]:
                """Entry attributes as dictionary."""
                ...

            def entry_to_json(self) -> str:
                """Convert entry to JSON string."""
                ...

            def __getattr__(self, name: str) -> Any:
                """Dynamic attribute access for LDAP attributes."""
                ...

        class Server(Protocol):
            """Protocol for ldap3.Server with proper type hints.

            Provides type hints for ldap3.Server used in flext-ldap codebase.
            """

            @property
            def host(self) -> str:
                """LDAP server host."""
                ...

            @property
            def port(self) -> int:
                """LDAP server port."""
                ...


# =========================================================================
# PUBLIC API EXPORTS - FlextLdapTypes and flext-core TypeVars
# =========================================================================

__all__ = [
    "AclType",
    "Any",  # Re-export for type stub usage
    "AttributeDict",
    "AttributeName",
    "AttributeValue",
    "AuthenticationConfig",
    "AuthenticationMethod",
    "BindDN",
    "BindPassword",
    "BulkOperation",
    "ConnectionConfig",
    "ConnectionState",
    "DirectoryConfig",
    "DistinguishedName",
    "EntryTemplate",
    "FlextLdapTypes",
    "LdapAttributeDict",
    "LdapAttributeValue",
    "LdapComplexEntryDict",
    "LdapConfigDict",
    "LdapConfigValue",
    "LdapEntryAttributeDict",
    "LdapEntryTemplateDict",
    "LdapEntryValue",
    "LdapModifyDict",
    "LdapProjectConfig",
    "LdapProjectType",
    "LdapResponseDict",
    "LdapSchemaAttributeDict",
    "LdapSearchResultDict",
    "ModifyChanges",
    "ObjectClass",
    "ObjectClassKind",
    "OperationType",
    "Protocol",  # Re-export for type stub usage
    "RetryConfig",
    "SearchConfig",
    "SearchConfiguration",
    "SearchFilter",
    "SearchResult",
    "SecurityLevel",
    "ServerConfig",
    "ServerPoolConfig",
    "ServerURI",
    "SyncConfig",
    "TimeoutConfig",
    "UpdateStrategy",
]
