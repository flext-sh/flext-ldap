"""LDAP domain type aliases and definitions.

Type definitions for flext-ldap unified in FlextLdapTypes class following FLEXT
patterns: dictionary types, domain types, config types, and Pydantic-annotated types.

FLEXT Standard: Single unified class per module (ONE CLASS PER MODULE)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, Protocol

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
    # DICTIONARY TYPES - LDAP Dictionary Type Aliases
    # =========================================================================

    class DictionaryTypes:
        """LDAP dictionary type aliases for structured data operations.

        These types represent LDAP-specific dictionary structures used internally
        for configuration, responses, and operational data.
        """

        # LDAP modify operation: attribute_name → [(operation, values), ...]
        ModifyDict = dict[str, list[tuple[str, list[str]]]]
        """LDAP modify changes dict for ldap3 modify operations."""

        # Configuration dictionaries
        ConfigDict = dict[str, str | int | bool | list[str] | None]
        """LDAP configuration dictionary type."""

        # Schema attribute dictionary
        SchemaAttributeDict = dict[str, str | list[str] | bool | None]
        """LDAP schema attribute dictionary."""

        # LDAP response dictionary
        ResponseDict = dict[str, str | int | bool | list[str] | None]
        """LDAP response dictionary from ldap3 operations."""

        # LDAP entry template
        EntryTemplateDict = dict[str, str | list[str]]
        """LDAP entry template dictionary for creating entries."""

    # =========================================================================
    # DOMAIN TYPES - LDAP Domain Type Aliases
    # =========================================================================

    class DomainTypes:
        """LDAP domain type aliases for core LDAP concepts.

        These types represent core LDAP domain concepts like attributes,
        filters, connections, and operations.
        """

        # Attribute value types (DEPRECATED - Phase 3 will use FlextLdifModels)
        AttributeValue = str | int | bool | list[str | int | bool]
        """LDAP attribute value type (deprecated)."""

        # Modify changes
        ModifyChanges = dict[str, list[tuple[str, list[str]]]]
        """LDAP modify operation changes."""

        # Search and filter
        SearchFilter = str
        """LDAP search filter string."""

        # Connection types
        ServerURI = str
        """LDAP server URI."""

        BindDN = str
        """Bind Distinguished Name."""

        BindPassword = str
        """Bind password."""

        # Protocol types
        ObjectClass = str
        """LDAP objectClass string."""

        AttributeName = str
        """LDAP attribute name."""

        # Complex operation types
        BulkOperation = list[dict[str, str | int | bool | list[str]]]
        """Bulk LDAP operation definition."""

        SearchConfiguration = dict[str, str | int | list[str]]
        """Search operation configuration."""

        EntryTemplate = dict[str, str | list[str]]
        """Entry template for creation."""

    # =========================================================================
    # CONFIG TYPES - LDAP Configuration Type Aliases
    # =========================================================================

    class ConfigTypes:
        """LDAP configuration type aliases for system setup.

        These types represent configuration structures for servers,
        connections, authentication, and searches.
        """

        # Core configuration types
        ServerConfig = dict[str, str | int | bool | list[str] | None]
        """LDAP server configuration."""

        ConnectionConfig = dict[str, str | int | bool | list[str] | None]
        """LDAP connection configuration."""

        AuthenticationConfig = dict[str, str | bool | list[str] | None]
        """LDAP authentication configuration."""

        SearchConfig = dict[str, str | int | bool | list[str] | None]
        """LDAP search configuration."""

        # Pool and retry configuration
        PoolConfig = dict[str, list[str] | int | bool | None]
        """LDAP connection pool configuration."""

        RetryConfig = dict[str, int | float | bool | None]
        """LDAP retry configuration."""

        TimeoutConfig = dict[str, int | float | None]
        """LDAP timeout configuration."""

        # Composite configuration
        ConfigValue = (
            str | int | bool | list[str] |
            dict[str, str | int | bool | list[str] | None]
        )
        """LDAP composite configuration value."""

        # Project configuration
        ProjectConfig = dict[str, str | int | bool | list[str] | None]
        """LDAP project configuration."""

        DirectoryConfig = dict[str, str | int | bool | list[str]]
        """LDAP directory configuration."""

        SyncConfig = dict[str, str | int | bool | list[str] | dict[str, object]]
        """LDAP synchronization configuration."""

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
            def entries(self) -> list[object]:
                """List of Entry objects from last search operation."""
                ...

            @property
            def bound(self) -> bool:
                """Whether connection is currently bound."""
                ...

            @property
            def result(self) -> dict[str, object]:
                """Result of last LDAP operation."""
                ...

            @property
            def response(self) -> list[dict[str, object]]:
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
                **kwargs: object,
            ) -> bool:
                """Execute LDAP search. Returns True if successful."""
                ...

            def add(
                self,
                dn: str,
                object_class: str | list[str] | None = None,
                attributes: dict[str, str | list[str]] | None = None,
                **kwargs: object,
            ) -> bool:
                """Add LDAP entry. Returns True if successful."""
                ...

            def modify(
                self,
                dn: str,
                changes: dict[str, list[tuple[int, list[str]]]],
                **kwargs: object,
            ) -> bool:
                """Modify LDAP entry. Returns True if successful."""
                ...

            def delete(self, dn: str, **kwargs: object) -> bool:
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
            def entry_attributes_as_dict(self) -> dict[str, list[str]]:
                """Entry attributes as dictionary."""
                ...

            def entry_to_json(self) -> str:
                """Convert entry to JSON string."""
                ...

            def __getattr__(self, name: str) -> object:
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
# PUBLIC API EXPORTS - FLEXT ONE CLASS PER MODULE
# =========================================================================

# FLEXT Standard: Single unified class per module
# All types are accessed through FlextLdapTypes:
#   from flext_ldap.typings import FlextLdapTypes
#
#   # Dictionary types
#   FlextLdapTypes.DictionaryTypes.ModifyDict
#   FlextLdapTypes.DictionaryTypes.ConfigDict
#
#   # Domain types
#   FlextLdapTypes.DomainTypes.AttributeValue
#   FlextLdapTypes.DomainTypes.SearchFilter
#
#   # Config types
#   FlextLdapTypes.ConfigTypes.ServerConfig
#   FlextLdapTypes.ConfigTypes.ConnectionConfig
#
#   # Annotated Pydantic types
#   FlextLdapTypes.AnnotatedLdap.DistinguishedName
#   FlextLdapTypes.AnnotatedLdap.ServerUri
#
#   # Protocol definitions (ldap3 compatibility)
#   FlextLdapTypes.Ldap3Protocols.Connection
#   FlextLdapTypes.Ldap3Protocols.Entry

__all__ = [
    "AclType",
    "AuthenticationMethod",
    "ConnectionState",
    "FlextLdapTypes",
    "LdapProjectType",
    "ObjectClassKind",
    "OperationType",
    "SecurityLevel",
    "UpdateStrategy",
]
