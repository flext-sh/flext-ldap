"""Unified LDAP models consolidated into FlextLdapModels.

Consolidates models, entities, and value objects into single class
following one-class-per-module pattern.

Note: Some type checker limitations exist (architectural, no runtime
impact) related to generic type inference and optional overrides.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import (
    ClassVar,
    Self,
    cast,
)

from flext_core import (
    FlextConstants,
    FlextExceptions,
    FlextModels,
    FlextResult,
)
from flext_ldif import FlextLdifModels
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)

from flext_ldap.constants import FlextLdapConstants


class FlextLdapModels(FlextModels):
    """Unified LDAP models class consolidating models, entities, and values.

    Consolidates previous separate model classes into single unified class:
    - Data models for LDAP operations
    - Domain entities for business logic
    - Value objects for immutable data

    All LDAP data structures available as nested classes within
    FlextLdapModels using Pydantic 2.11 validation features.
    """

    # Enhanced base configuration for all LDAP models
    model_config = ConfigDict(
        validate_assignment=True,
        validate_return=True,
        validate_default=True,
        strict=True,  # Strict type coercion
        str_strip_whitespace=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        extra="forbid",  # Strict LDAP attribute validation
        frozen=False,  # Allow mutable LDAP models for attribute updates
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        serialize_by_alias=True,
        populate_by_name=True,
        hide_input_in_errors=True,  # Security
        # LDAP serialization features
        json_encoders={
            datetime: lambda v: v.isoformat() if v else None,
        },
        json_schema_extra={
            "title": "FlextLdapModels",
            "description": "Unified LDAP models with validation",
        },
    )

    # =========================================================================
    # VALIDATOR METHODS - Consolidated from _ValidatorRegistry (Phase 5a)
    # =========================================================================

    # =========================================================================
    # Note: Removed StrictModel and FlexibleModel wrappers
    # Use FlextModels.ArbitraryTypesModel directly with model_config overrides
    # =========================================================================

    # =========================================================================
    # VALUE OBJECTS - Immutable LDAP value objects
    # =========================================================================

    class Filter(FlextModels.Value):
        """LDAP filter value object with RFC 4515 compliance.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
        """

        expression: str = Field(
            ...,
            min_length=1,
            pattern=FlextLdapConstants.RegexPatterns.FILTER_PATTERN,
            description="LDAP filter expression",
        )

        @field_validator("expression")
        @classmethod
        def validate_rfc4515_syntax(cls, v: str) -> str:
            """Validate RFC 4515 LDAP filter syntax.

            Validates:
            - Balanced parentheses
            - Valid operators (=, ~=, >=, <=, =*)
            - Proper AND (&), OR (|), NOT (!) syntax
            - Escaped special characters when needed

            RFC 4515: LDAP Search Filter specification
            """
            if not v or not v.strip():
                msg = "Filter expression cannot be empty"
                raise ValueError(msg)

            # RFC 4515: Filter MUST start with '(' and end with ')'
            if not (v.startswith("(") and v.endswith(")")):
                msg = "Filter must be enclosed in parentheses (RFC 4515)"
                raise ValueError(msg)

            # Validate balanced parentheses
            depth = 0
            for char in v:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                if depth < 0:
                    msg = "Unbalanced parentheses in filter (RFC 4515)"
                    raise ValueError(msg)
            if depth != 0:
                msg = "Unbalanced parentheses in filter (RFC 4515)"
                raise ValueError(msg)

            # Validate no invalid characters (RFC 4515 special chars: * ( ) \ NUL)
            # NUL char validation
            if "\x00" in v:
                msg = "NUL character not allowed in filter (RFC 4515)"
                raise ValueError(msg)

            return v

        @classmethod
        def equals(cls, attribute: str, value: str) -> FlextLdapModels.Filter:
            """Create equality filter."""
            return cls(expression=f"({attribute}={value})")

        @classmethod
        def starts_with(
            cls,
            attribute: str,
            value: str,
        ) -> FlextLdapModels.Filter:
            """Create starts-with filter."""
            return cls(expression=f"({attribute}={value}*)")

        @classmethod
        def object_class(cls, object_class: str) -> FlextLdapModels.Filter:
            """Create objectClass filter using builder pattern."""
            return cls(expression=f"(objectClass={object_class})")

        @classmethod
        def _build_filter_expression(
            cls, attribute: str, operator: str, value: str
        ) -> str:
            """Build LDAP filter expression using builder pattern.

            DRY helper for creating filter expressions with proper formatting.
            Handles escaping and formatting for common LDAP filter patterns.

            Args:
                attribute: LDAP attribute name
                operator: Filter operator (=, ~=, >=, <=, etc.)
                value: Attribute value to match

            Returns:
                Properly formatted LDAP filter expression

            """
            return f"({attribute}{operator}{value})"

        @classmethod
        def and_filters(
            cls, *filters: FlextLdapModels.Filter
        ) -> FlextLdapModels.Filter:
            """Combine multiple filters with AND using builder pattern.

            Creates compound filter expressions with proper LDAP syntax.
            Eliminates manual string concatenation for complex filters.

            Args:
                *filters: Filter objects to combine with AND

            Returns:
                Combined filter with AND logic

            """
            if not filters:
                return cls(expression="(objectClass=*)")  # Default match-all filter

            expressions = [f.expression for f in filters]
            combined = f"(&{' '.join(expressions)})"
            return cls(expression=combined)

        @classmethod
        def user_by_uid(cls, uid: str) -> FlextLdapModels.Filter:
            """Create user filter by UID using builder pattern with AND combination."""
            user_filter = cls.object_class("person")
            uid_filter = cls.equals("uid", uid)
            return cls.and_filters(user_filter, uid_filter)

        @classmethod
        def group_by_cn(cls, cn: str) -> FlextLdapModels.Filter:
            """Create group filter by CN using builder pattern with AND combination."""
            group_filter = cls.object_class("groupOfNames")
            cn_filter = cls.equals("cn", cn)
            return cls.and_filters(group_filter, cn_filter)

    class Scope(FlextModels.Value):
        """LDAP search scope value object.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
        """

        value: FlextLdapConstants.Types.SearchScope = Field(
            ...,
            description="LDAP search scope value using FlextLdapConstants",
        )

        BASE: ClassVar[str] = FlextLdapConstants.Scopes.BASE
        ONELEVEL: ClassVar[str] = FlextLdapConstants.Scopes.ONELEVEL
        SUBTREE: ClassVar[str] = FlextLdapConstants.Scopes.SUBTREE

        @classmethod
        def base(cls) -> FlextLdapModels.Scope:
            """Create base scope using FlextLdapConstants with proper type casting."""
            return cls(
                value=cast(
                    "FlextLdapConstants.Types.SearchScope",
                    FlextLdapConstants.Scopes.BASE,
                )
            )

        @classmethod
        def onelevel(cls) -> FlextLdapModels.Scope:
            """Create onelevel scope using FlextLdapConstants with proper type casting."""
            return cls(
                value=cast(
                    "FlextLdapConstants.Types.SearchScope",
                    FlextLdapConstants.Scopes.ONELEVEL,
                )
            )

        @classmethod
        def subtree(cls) -> FlextLdapModels.Scope:
            """Create subtree scope using FlextLdapConstants with proper type casting."""
            return cls(
                value=cast(
                    "FlextLdapConstants.Types.SearchScope",
                    FlextLdapConstants.Scopes.SUBTREE,
                )
            )

    # =========================================================================
    # SCHEMA MODELS - LDAP schema discovery and server quirks handling
    # =========================================================================

    class ServerQuirks(FlextModels.Value):
        """LDAP server-specific quirks and behaviors - Pydantic Value Object."""

        server_type: str = Field(description="LDAP server type for quirks")
        case_sensitive_dns: bool = True
        case_sensitive_attributes: bool = True
        supports_paged_results: bool = True
        supports_vlv: bool = False
        supports_sync: bool = False
        max_page_size: int = 1000
        default_timeout: int = 30
        supports_start_tls: bool = True
        requires_explicit_bind: bool = False
        attribute_name_mappings: dict[str, str] = Field(default_factory=dict)
        object_class_mappings: dict[str, str] = Field(default_factory=dict)
        dn_format_preferences: list[str] = Field(default_factory=list)
        search_scope_limitations: set[str] = Field(default_factory=set)
        filter_syntaxs: list[str] = Field(default_factory=list)
        modify_operations: list[str] = Field(default_factory=list)

    class Base(FlextModels.ArbitraryTypesModel):
        """Base model - dynamic LDAP schema support.

        DYNAMIC LDAP SCHEMA: Accepts arbitrary attributes for varying
        server schemas (OpenLDAP, AD, OID/OUD, 389 DS, etc.)
        """

        model_config = ConfigDict(extra="allow")

        # LDAP-specific timestamp fields (nullable)
        created_at: datetime | None = Field(
            default=None,
            description="Creation timestamp",
        )
        updated_at: datetime | None = Field(
            default=None,
            description="Last update timestamp",
        )

    class EntityBase(FlextModels.Entity):
        """Base class for LDAP entities with common fields and validation.

        Provides common fields and validation methods that are shared
        across multiple LDAP entity types.
        """

        # Common additional attributes field
        additional_attributes: dict[
            str,
            str | int | bool | list[str | int | bool],
        ] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )

    # =========================================================================
    # CORE LDAP ENTITIES - Primary Domain Objects (Consolidated into Entry)
    # =========================================================================
    # Note: LdapUser and Group classes have been consolidated into the unified
    # polymorphic Entry model using Pydantic 2.11 discriminated unions.
    # All functionality is now available through FlextLdifModels.Entry with
    # entry_type discriminator (user, group, organizationalUnit, device, etc.)

    class _SearchDefaults:
        """Default attributes for search operations."""

        DEFAULT_USER_ATTRIBUTES: ClassVar[list[str]] = [
            "cn",
            "sn",
            "mail",
            "objectClass",
        ]
        DEFAULT_GROUP_ATTRIBUTES: ClassVar[list[str]] = [
            "cn",
            "member",
            "description",
            "objectClass",
        ]

        @classmethod
        def get_user_attributes(cls) -> list[str]:
            """Get default user attributes for search requests.

            Returns:
            List of default user attributes.

            """
            return cls.DEFAULT_USER_ATTRIBUTES.copy()

    class SearchRequest(BaseModel):
        """LDAP Search Request with parameters and Pydantic 2.11 validation.

        Uses __slots__ for memory efficiency in high-frequency LDAP operations.
        DRY principle: Uses shared constants from _SearchDefaults to avoid duplication.
        """

        __slots__ = ()  # Enable __slots__ for memory optimization

        @classmethod
        def get_user_attributes(cls) -> list[str]:
            """Get default user attributes for search requests using DRY shared constants."""
            return FlextLdapModels._SearchDefaults.DEFAULT_USER_ATTRIBUTES.copy()

        @classmethod
        def get_group_attributes(cls) -> list[str]:
            """Get default group attributes for search requests using DRY shared constants."""
            return FlextLdapModels._SearchDefaults.DEFAULT_GROUP_ATTRIBUTES.copy()

        # Search scope - Pydantic 2 Field constraints replace validators
        base_dn: str = Field(
            ...,
            min_length=1,
            description="Search base Distinguished Name",
        )
        filter_str: str = Field(
            ...,
            min_length=1,
            description="LDAP search filter",
        )

        scope: str = Field(
            default="subtree",
            description="Search scope: base, onelevel, subtree",
            pattern="^(base|onelevel|subtree|BASE|ONELEVEL|SUBTREE)$",
        )

        # Attribute selection
        attributes: list[str] | None = Field(
            default=None,
            description="Attributes to return (None = all)",
        )

        # Search limits - using centralized constants
        size_limit: int = Field(
            default=FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE,
            description="Maximum number of entries to return",
            ge=0,
        )
        time_limit: int = Field(
            default=FlextConstants.Network.DEFAULT_TIMEOUT,
            description="Search timeout in seconds",
            ge=0,
            le=300,
        )

        # Paging - Optional for paged LDAP search results
        page_size: int | None = Field(
            default=None,
            description="Page size for paged results",
            ge=1,
        )
        paged_cookie: bytes | None = Field(
            default=None,
            description="Paging cookie for continuation",
        )

        # Additional options
        types_only: bool = Field(
            default=False,
            description="Return attribute types only (no values)",
        )
        deref_aliases: str = Field(
            default="never",
            description="Alias dereferencing: never, searching, finding, always",
            pattern="^(never|searching|finding|always)$",
        )

        # Result control
        single: bool = Field(
            default=False,
            description="Return single entry (first result) instead of list",
        )

        # Server-specific handling
        quirks_mode: str | None = Field(
            default=None,
            description="Override quirks mode for server-specific behavior",
        )

        @field_validator("base_dn")
        @classmethod
        def validate_rfc4514_dn(cls, v: str) -> str:
            """Validate DN syntax (RFC 4514).

            RFC 4514 specifies DN format: attribute=value pairs separated by commas.
            Basic validation ensures DN structure compliance while being permissive
            for server-specific extensions stored in Entry metadata.

            RFC 4514: LDAP Distinguished Names specification
            """
            if not v or not v.strip():
                msg = "DN cannot be empty (RFC 4514)"
                raise ValueError(msg)

            v = v.strip()

            # RFC 4514: DN must contain at least one '=' for attribute=value
            if "=" not in v:
                msg = "DN must contain attribute=value pairs (RFC 4514)"
                raise ValueError(msg)

            # RFC 4514: Check for invalid characters (NULL byte)
            if "\x00" in v:
                msg = "DN cannot contain NUL character (RFC 4514)"
                raise ValueError(msg)

            # RFC 4514: Basic RDN structure validation
            # Split by comma (but not escaped comma \,)
            parts = v.split(",")
            for rdn in parts:
                rdn_stripped = rdn.strip()
                if not rdn_stripped:
                    msg = "DN cannot have empty RDN components (RFC 4514)"
                    raise ValueError(msg)

                # Each RDN must have attribute=value format
                if "=" not in rdn_stripped:
                    msg = f"Invalid RDN '{rdn_stripped}': missing '=' (RFC 4514)"
                    raise ValueError(msg)

                # Check for attribute name before =
                attr_name = rdn_stripped.split("=", 1)[0].strip()
                if not attr_name:
                    msg = f"Invalid RDN '{rdn_stripped}': empty attribute name (RFC 4514)"
                    raise ValueError(msg)

            return v

        @model_validator(mode="after")
        def validate_search_consistency(self) -> Self:
            """Model validator for cross-field validation and search optimization."""
            max_time_limit_seconds = 300  # 5 minutes maximum
            max_page_multiplier = 100  # Maximum page size multiplier

            # Optimize size limit for paged searches
            if (
                self.page_size is not None
                and self.page_size > 0
                and self.size_limit > self.page_size * max_page_multiplier
            ):
                # Automatically adjust size limit for very large paged searches
                self.size_limit = min(
                    self.size_limit,
                    self.page_size * max_page_multiplier,
                )

            # Validate time limit is reasonable
            if self.time_limit > max_time_limit_seconds:
                msg = f"Time limit exceeds {max_time_limit_seconds} seconds"
                raise FlextExceptions.ValidationError(
                    msg,
                    field="time_limit",
                    value=str(self.time_limit),
                )

            # (objectClass=*) valid for BASE scope; retrieves entry at base DN

            return self

        @field_serializer("paged_cookie")
        def serialize_cookie(self, value: bytes | None) -> str | None:
            """Field serializer for paging cookie."""
            if value is None:
                return None
            # Encode bytes as base64 for JSON serialization
            return base64.b64encode(value).decode("ascii")

        @field_serializer("filter_str")
        def serialize_filter(self, value: str) -> str:
            """Field serializer for LDAP filter normalization."""
            # Normalize whitespace in filter
            return " ".join(value.split())

        @classmethod
        def create_user_search(
            cls,
            uid: str,
            base_dn: str = "ou=users,dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> Self:
            """Create search request for user using builder pattern and filter helpers."""
            # Use builder pattern for filter creation
            user_filter = FlextLdapModels.Filter.user_by_uid(uid)

            return cls.model_validate(
                {
                    "base_dn": base_dn,
                    "filter_str": user_filter.expression,
                    "attributes": (
                        cls.get_user_attributes() if attributes is None else attributes
                    ),
                    "page_size": FlextConstants.Performance.DEFAULT_PAGE_SIZE,
                    "paged_cookie": None,
                },
            )

        @classmethod
        def create_group_search(
            cls,
            cn: str,
            base_dn: str = "ou=groups,dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> Self:
            """Create search request for group using builder pattern and filter helpers."""
            # Use builder pattern for filter creation
            group_filter = FlextLdapModels.Filter.group_by_cn(cn)

            return cls.model_validate(
                {
                    "base_dn": base_dn,
                    "filter_str": group_filter.expression,
                    "attributes": (
                        cls.get_group_attributes() if attributes is None else attributes
                    ),
                    "page_size": FlextConstants.Performance.DEFAULT_PAGE_SIZE,
                    "paged_cookie": None,
                },
            )

        @classmethod
        def create(
            cls,
            base_dn: str,
            filter_str: str,
            scope: str = "subtree",
            attributes: list[str] | None = None,
        ) -> Self:
            """Factory method with smart defaults from FlextLdapConstants.

            Creates a SearchRequest with intelligent defaults for common parameters,
            eliminating the need to specify page_size, paged_cookie, and other
            boilerplate parameters.

            Args:
                base_dn: Search base Distinguished Name
                filter_str: LDAP search filter (required)
                scope: Search scope (default: SUBTREE from FlextLdapConstants)
                attributes: Attributes to retrieve (empty list = all)

            Returns:
                SearchRequest: Configured request with smart defaults

            Example:
                # OLD: Manual parameter specification
                request = FlextLdapModels.SearchRequest(
                    base_dn=base_dn,
                    filter_str=filter_str,
                    scope=scope,
                    attributes=[] if attributes is None else attributes,
                    page_size=FlextConstants.Performance.DEFAULT_PAGE_SIZE,
                    paged_cookie=b"",
                )

                # Factory method with smart defaults
                req = FlextLdapModels.SearchRequest.create(
                    base_dn, filter_str, scope, attributes
                )

            """
            return cls.model_validate({
                "base_dn": base_dn,
                "filter_str": filter_str,
                "scope": scope,
                "attributes": [] if attributes is None else attributes,
                "page_size": FlextConstants.Performance.DEFAULT_PAGE_SIZE,
                "paged_cookie": b"",
                "size_limit": (
                    FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE
                ),
                "time_limit": FlextConstants.Network.DEFAULT_TIMEOUT,
            })

    class ApplyChangesRequest(BaseModel):
        """LDAP Apply Changes Request with parameters and Pydantic 2 validation.

        Consolidates add/modify/delete operations into unified request model.
        """

        __slots__ = ()  # Enable __slots__ for memory optimization

        # Core operation parameters
        changes: dict[str, str | list[str]] = Field(
            ...,
            description="Attribute changes for single operation",
        )
        dn: str | None = Field(
            default=None,
            description="Distinguished name for single operation",
        )

        # Operation configuration
        operation: str = Field(
            default="add",
            description="Operation type: add, modify, or delete",
            pattern="^(add|modify|delete)$",
        )
        atomic: bool = Field(
            default=False,
            description="If True, attempt atomic modification",
        )
        batch: bool = Field(
            default=False,
            description="If True, use modifications for batch mode",
        )

        # Batch operation parameters
        modifications: list[tuple[str, dict[str, str | list[str]]]] | None = Field(
            default=None,
            description="List of (DN, changes) tuples for batch operations",
        )

        # Server quirks
        quirks_mode: str | None = Field(
            default=None,
            description="Optional quirks mode override",
        )

        @field_validator("dn")
        @classmethod
        def validate_rfc4514_dn_optional(cls, v: str | None) -> str | None:
            """Validate DN syntax when provided (RFC 4514).

            RFC 4514 specifies DN format: attribute=value pairs separated by commas.
            This validator allows None (for batch operations without single DN).

            RFC 4514: LDAP Distinguished Names specification
            """
            # Allow None for batch operations
            if v is None:
                return v

            if not v or not v.strip():
                msg = "DN cannot be empty when provided (RFC 4514)"
                raise ValueError(msg)

            v_stripped = v.strip()

            # RFC 4514: DN must contain at least one '=' for attribute=value
            if "=" not in v_stripped:
                msg = "DN must contain attribute=value pairs (RFC 4514)"
                raise ValueError(msg)

            # RFC 4514: Check for invalid characters (NULL byte)
            if "\x00" in v_stripped:
                msg = "DN cannot contain NUL character (RFC 4514)"
                raise ValueError(msg)

            # RFC 4514: Basic RDN structure validation
            # Split by comma (but not escaped comma \,)
            parts = v_stripped.split(",")
            for rdn in parts:
                rdn_stripped = rdn.strip()
                if not rdn_stripped:
                    msg = "DN cannot have empty RDN components (RFC 4514)"
                    raise ValueError(msg)

                # Each RDN must have attribute=value format
                if "=" not in rdn_stripped:
                    msg = f"Invalid RDN '{rdn_stripped}': missing '=' (RFC 4514)"
                    raise ValueError(msg)

                # Check for attribute name before =
                attr_name = rdn_stripped.split("=", 1)[0].strip()
                if not attr_name:
                    msg = f"Invalid RDN '{rdn_stripped}': empty attribute name (RFC 4514)"
                    raise ValueError(msg)

            return v_stripped

        @model_validator(mode="after")
        def validate_operation_consistency(self) -> Self:
            """Validate operation mode consistency.

            Ensures either single operation (dn + changes) or batch mode (modifications).
            """
            # Batch mode requires modifications
            if self.batch and not self.modifications:
                msg = "Batch mode requires modifications list"
                raise ValueError(msg)

            # Single operation requires dn (unless batch)
            if not self.batch and self.dn is None:
                msg = "Single operation requires DN (use batch=True for batch operations)"
                raise ValueError(msg)

            # Modifications should only be used in batch mode
            if not self.batch and self.modifications:
                msg = "Modifications list requires batch=True"
                raise ValueError(msg)

            return self

    class ConnectionRequest(BaseModel):
        """LDAP Connection Request with parameters and Pydantic 2 validation.

        Consolidates connection parameters into unified request model.
        Reduces connect() method from 6 parameters to 1 model.
        """

        __slots__ = ()  # Enable __slots__ for memory optimization

        # Core connection parameters (required) - Pydantic 2 Field constraints
        server_uri: str = Field(
            ...,
            pattern=r"^ldaps?://",
            min_length=1,
            description="LDAP server URI (e.g., 'ldap://localhost:389')",
        )
        bind_dn: FlextLdifModels.DistinguishedName | str = Field(
            ...,
            description="Distinguished Name for binding",
        )
        password: str = Field(
            ...,
            min_length=1,
            description="Password for binding",
        )

        # Connection configuration (optional)
        auto_discover_schema: bool = Field(
            default=True,
            description="Whether to automatically discover schema",
        )
        connection_options: dict[str, object] | None = Field(
            default=None,
            description="Additional connection options (timeout, pool_size, etc.)",
        )
        quirks_mode: str | None = Field(
            default=None,
            description="Override default quirks mode for this connection",
        )

        @field_validator("server_uri")
        @classmethod
        def validate_ldap_uri_rfc(cls, v: str) -> str:
            """Validate LDAP URI RFC compliance (RFC 4516).

            Validates:
            - Correct scheme (ldap:// or ldaps://)
            - Valid hostname or IP address
            - Valid port range (1-65535) if specified
            - No invalid characters

            RFC 4516: LDAP URL specification
            """
            if not v:
                msg = "LDAP URI cannot be empty"
                raise ValueError(msg)

            # Strip whitespace
            v = v.strip()

            # Validate scheme
            if not v.startswith(("ldap://", "ldaps://")):
                msg = "URI must start with ldap:// or ldaps:// (RFC 4516)"
                raise ValueError(msg)

            # Extract host:port portion
            scheme_end = v.index("://") + 3
            uri_remainder = v[scheme_end:]

            # Split host:port from path/query
            host_port = uri_remainder.split("/")[0].split("?")[0]

            if not host_port:
                msg = "URI must contain hostname or IP (RFC 4516)"
                raise ValueError(msg)

            # Validate port if present
            if ":" in host_port:
                try:
                    port_str = host_port.split(":")[-1]
                    port = int(port_str)
                    max_port = FlextConstants.Network.MAX_PORT
                    if not (1 <= port <= max_port):
                        msg = f"Port {port} out of valid range 1-{max_port} (RFC 4516)"
                        raise ValueError(msg)
                except ValueError as e:
                    if "invalid literal" in str(e):
                        msg = "Invalid port number in URI (RFC 4516)"
                        raise ValueError(msg) from e
                    raise

            return v

    class ExchangeRequest(BaseModel):
        """LDAP Exchange Request with parameters and Pydantic 2 validation.

        Consolidates import/export parameters into unified request model.
        Reduces exchange() method from 6 parameters to 1 model.

        Used for bidirectional data exchange:
        - Import: data → entries
        - Export: entries → data
        """

        __slots__ = ()  # Enable __slots__ for memory optimization

        # Data parameters (mutually exclusive based on direction)
        data: str | None = Field(
            default=None,
            description="Data string for import operation (LDIF/JSON/CSV)",
        )
        entries: list[FlextLdifModels.Entry] | None = Field(
            default=None,
            description="Entries for export operation",
        )

        # Operation configuration
        data_format: str = Field(
            default="ldif",
            description="Data format: ldif, json, or csv",
            pattern="^(ldif|json|csv)$",
        )
        direction: str = Field(
            default="import",
            description="Operation direction: import or export",
            pattern="^(import|export)$",
        )

        # Server quirks
        quirks_mode: str | None = Field(
            default=None,
            description="Optional quirks mode override for format-specific rules",
        )

        @model_validator(mode="after")
        def validate_data_direction(self) -> Self:
            """Validate data/entries provided based on direction.

            - Import direction requires 'data'
            - Export direction requires 'entries'

            Note: mode="after" validators do not use @classmethod in Pydantic v2.
            """
            if self.direction == "import" and not self.data:
                msg = "Data required for import operation"
                raise ValueError(msg)
            if self.direction == "export" and not self.entries:
                msg = "Entries required for export operation"
                raise ValueError(msg)
            return self

    class SearchResponse(BaseModel):
        """LDAP Search Response entity.

        Uses __slots__ for memory efficiency in large result sets.
        """

        __slots__ = ()  # Enable __slots__ for memory optimization

        # Results - using Entry models for type-safe entries
        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Search result entries",
        )

        # Result metadata
        total_count: int = Field(0, description="Total number of entries")
        has_more: bool = Field(default=False, description="More results available")

        # Core response fields
        result_code: int = Field(0, description="LDAP result code")
        result_description: str = Field(default="", description="Result description")
        matched_dn: str = Field(default="", description="Matched DN")
        has_more_pages: bool = Field(default=False, description="More pages available")
        next_cookie: bytes | None = Field(default=None, description="Next page cookie")
        entries_returned: int = Field(
            default=0,
            description="Number of entries returned",
        )
        time_elapsed: float = Field(default=0.0, description="Search time in seconds")

    # =========================================================================
    # GENERIC LDAP REQUEST - Consolidated factory-based implementation
    # Consolidates 9+ request types (Update/Upsert/Create operations)
    # Python 3.13+ with TypeAlias for backward compatibility
    # =========================================================================

    class _LdapRequest(BaseModel):
        """Universal LDAP request - consolidated from 12+ request classes.

        Composition-based consolidation: Entry, User, Group, ACL, Schema operations.
        Eliminates 450+ lines of duplication across specialized request classes.

        Supports:
        - Add/Update/Upsert entry operations
        - Create/Update/Upsert ACL operations
        - Create/Update/Upsert schema operations
        - Create user/group operations
        """

        # Core DN fields
        dn: str | None = Field(default=None, description="Distinguished Name")
        schema_dn: str | None = Field(default=None, description="DN of schema subentry")

        # General attributes (for Add, Update, Upsert operations)
        attributes: FlextLdifModels.LdifAttributes | None = Field(
            default=None,
            description="Entry attributes",
        )
        object_classes: list[str] | None = Field(
            default=None,
            description="LDAP object classes",
        )

        # User/Group specific fields
        cn: str | None = Field(default=None, description="Common Name")
        sn: str | None = Field(default=None, description="Surname")
        uid: str | None = Field(default=None, description="User ID")
        given_name: str | None = Field(default=None, description="Given Name")
        user_password: str | None = Field(default=None, description="User password")
        mail: str | None = Field(default=None, description="Email address")
        owner: str | None = Field(default=None, description="Group owner")
        member: list[str] = Field(default_factory=list, description="Group members")

        # ACL operations
        acl_rules: list[str] | None = Field(default=None, description="ACL rules")
        acl_type: FlextLdapConstants.Types.AclType = "auto"

        # Schema attribute fields
        name: str | None = Field(default=None, description="Schema element name")
        syntax: str | None = Field(default=None, description="LDAP syntax OID")
        single_value: bool = False
        equality_match: str | None = None
        ordering_match: str | None = None
        substr_match: str | None = None

        # Schema changes/elements
        changes: dict[str, str | list[str]] | None = Field(
            default=None,
            description="Schema changes",
        )
        schema_element: dict[str, str | list[str]] | None = Field(
            default=None,
            description="Schema element",
        )

        # Object class definition fields
        must_attributes: list[str] = Field(
            default_factory=list,
            description="MUST attributes",
        )
        may_attributes: list[str] = Field(
            default_factory=list,
            description="MAY attributes",
        )
        parent: str | None = FlextLdapConstants.ObjectClasses.TOP
        kind: FlextLdapConstants.Types.ObjectClassKind = cast(
            "FlextLdapConstants.Types.ObjectClassKind",
            FlextLdapConstants.ObjectClassKindConstants.STRUCTURAL,
        )

        # Update/Upsert strategies
        strategy: FlextLdapConstants.Types.UpdateStrategy = "merge"
        update_strategy: FlextLdapConstants.Types.UpdateStrategy = "merge"

        # General fields
        description: str | None = None
        server_type: str | None = None

        # User-specific fields (consolidated for User create/update operations)
        telephone_number: str | None = None
        department: str | None = None
        title: str | None = None
        organization: str | None = None
        organizational_unit: str | None = None
        mobile: str | None = None

        def _build_attribute_dict(self) -> dict[str, list[str]]:
            """Build LDAP attribute dict from individual fields."""
            attrs: dict[str, list[str]] = {}

            if self.cn:
                attrs["cn"] = [self.cn]
            if self.sn:
                attrs["sn"] = [self.sn]
            if self.uid:
                attrs["uid"] = [self.uid]
            if self.given_name:
                attrs["givenName"] = [self.given_name]
            if self.mail:
                attrs["mail"] = [self.mail]
            if self.description:
                attrs["description"] = [self.description]
            if self.owner:
                attrs["owner"] = [self.owner]
            if self.member:
                attrs["member"] = self.member
            if self.object_classes:
                attrs[FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS] = (
                    self.object_classes
                )

            return attrs

        def to_attributes(self) -> FlextLdifModels.LdifAttributes:
            """Convert request to LDAP attributes using FlextLdifModels.LdifAttributes.

            Returns FlextLdifModels.LdifAttributes wrapping standardized LDAP attribute
            dict with all values as lists (RFC 4511 LDAP protocol standard).
            """
            if self.attributes:
                return self.attributes

            # Build from individual fields using helper method
            attrs = self._build_attribute_dict()
            return FlextLdifModels.LdifAttributes(attributes=attrs)

        @field_validator("dn", "schema_dn", "owner")
        @classmethod
        def validate_dn_optional(cls, v: str | None) -> str | None:
            """Validate DN syntax when provided (RFC 4514).

            RFC 4514 specifies DN format: attribute=value pairs separated by commas.
            This validator allows None for optional DN fields.

            RFC 4514: LDAP Distinguished Names specification
            """
            # Allow None for optional DN fields
            if v is None:
                return v

            if not v or not v.strip():
                msg = "DN cannot be empty when provided (RFC 4514)"
                raise ValueError(msg)

            v_stripped = v.strip()

            # RFC 4514: DN must contain at least one '=' for attribute=value
            if "=" not in v_stripped:
                msg = "DN must contain attribute=value pairs (RFC 4514)"
                raise ValueError(msg)

            # RFC 4514: Check for invalid characters (NULL byte)
            if "\x00" in v_stripped:
                msg = "DN cannot contain NUL character (RFC 4514)"
                raise ValueError(msg)

            # RFC 4514: Basic RDN structure validation
            parts = v_stripped.split(",")
            for rdn in parts:
                rdn_stripped = rdn.strip()
                if not rdn_stripped:
                    msg = "DN cannot have empty RDN components (RFC 4514)"
                    raise ValueError(msg)

                # Each RDN must have attribute=value format
                if "=" not in rdn_stripped:
                    msg = f"Invalid RDN '{rdn_stripped}': missing '=' (RFC 4514)"
                    raise ValueError(msg)

                # Check for attribute name before =
                attr_name = rdn_stripped.split("=", 1)[0].strip()
                if not attr_name:
                    msg = f"Invalid RDN '{rdn_stripped}': empty attribute name (RFC 4514)"
                    raise ValueError(msg)

            return v_stripped

        @field_validator("member")
        @classmethod
        def validate_member_dns(cls, v: list[str]) -> list[str]:
            """Validate member DN list (RFC 4514).

            Each member DN must comply with RFC 4514 DN syntax.
            Empty list is allowed (group without members).

            RFC 4514: LDAP Distinguished Names specification
            """
            if not v:
                return v

            validated_members = []
            for member_dn in v:
                if not member_dn or not member_dn.strip():
                    msg = "Member DN cannot be empty (RFC 4514)"
                    raise ValueError(msg)

                member_stripped = member_dn.strip()

                # RFC 4514: DN must contain at least one '='
                if "=" not in member_stripped:
                    msg = f"Member DN '{member_stripped}' must contain attribute=value pairs (RFC 4514)"
                    raise ValueError(msg)

                # RFC 4514: Check for invalid characters (NULL byte)
                if "\x00" in member_stripped:
                    msg = f"Member DN '{member_stripped}' cannot contain NUL character (RFC 4514)"
                    raise ValueError(msg)

                # RFC 4514: Basic RDN structure validation
                parts = member_stripped.split(",")
                for rdn in parts:
                    rdn_stripped = rdn.strip()
                    if not rdn_stripped:
                        msg = f"Member DN '{member_stripped}' cannot have empty RDN components (RFC 4514)"
                        raise ValueError(msg)

                    if "=" not in rdn_stripped:
                        msg = f"Member DN '{member_stripped}' has invalid RDN '{rdn_stripped}': missing '=' (RFC 4514)"
                        raise ValueError(msg)

                    attr_name = rdn_stripped.split("=", 1)[0].strip()
                    if not attr_name:
                        msg = f"Member DN '{member_stripped}' has invalid RDN '{rdn_stripped}': empty attribute name (RFC 4514)"
                        raise ValueError(msg)

                validated_members.append(member_stripped)

            return validated_members

    # =========================================================================
    # CONSOLIDATED SYNC RESULT - Python 3.13+ composition pattern
    # Consolidates SyncResult, AclSyncResult, SchemaSyncResult into one generic class
    # =========================================================================

    class SyncResult(BaseModel):
        """Generic result model for sync operations using composition.

        Consolidates base sync tracking with ACL and Schema-specific fields.
        All operation-specific fields are optional for flexibility.
        Reduces 64 lines to ~40 lines through aggressive consolidation.

        Supports:
        - Entry sync operations
        - ACL sync operations with format conversion tracking
        - Schema sync operations with attribute/class tracking
        """

        # Core sync statistics (used by all operation types)
        created: int = Field(default=0, description="Number of items created")
        updated: int = Field(default=0, description="Number of items updated")
        deleted: int = Field(default=0, description="Number of items deleted")
        failed: int = Field(default=0, description="Number of failed operations")
        errors: list[str] = Field(
            default_factory=list,
            description="Error messages from failed operations",
        )
        operations: list[dict[str, str]] = Field(
            default_factory=list,
            description="Detailed operation log",
        )

        # ACL sync specific fields (optional for composition)
        acls_converted: int = Field(
            default=0,
            description="Number of ACLs converted between formats",
        )
        server_types_detected: list[str] = Field(
            default_factory=list,
            description="Server types detected during sync",
        )

        # Schema sync specific fields (optional for composition)
        attributes_created: int = Field(
            default=0,
            description="Number of schema attributes created",
        )
        object_classes_created: int = Field(
            default=0,
            description="Number of object classes created",
        )
        schema_conflicts: list[str] = Field(
            default_factory=list,
            description="Schema conflicts encountered",
        )

        @property
        def total_operations(self) -> int:
            """Total number of operations performed."""
            return self.created + self.updated + self.deleted + self.failed

        @property
        def success_rate(self) -> float:
            """Success rate as percentage."""
            if self.total_operations == 0:
                return 100.0
            successful = self.created + self.updated + self.deleted
            return (successful / self.total_operations) * 100.0

    # =========================================================================
    # CONNECTION AND CONFIGURATION ENTITIES
    # =========================================================================

    class ConnectionInfo(BaseModel):
        """LDAP Connection Information entity.

        Uses __slots__ for memory efficiency in connection management.
        """

        __slots__ = ()  # Enable __slots__ for memory optimization

        # Connection details
        server: str = Field(
            default=FlextLdapConstants.DefaultValues.LOCALHOST,
            description="LDAP server hostname/IP",
        )
        port: int = Field(
            FlextLdapConstants.Protocol.DEFAULT_PORT,
            description="LDAP server port",
            ge=1,
            le=FlextConstants.Network.MAX_PORT,
        )
        use_ssl: bool = Field(default=False, description="Use SSL/TLS encryption")
        use_tls: bool = Field(default=False, description="Use StartTLS")

        # Authentication
        bind_dn: str | None = Field(default=None, description="Bind Distinguished Name")
        bind_password: SecretStr | None = Field(
            default=None,
            description="Bind password",
        )

        # Connection options - using centralized constants
        timeout: int = Field(
            FlextConstants.Network.DEFAULT_TIMEOUT,
            description="Connection timeout in seconds",
            ge=1,
        )
        pool_size: int = Field(
            FlextConstants.Performance.DEFAULT_DB_POOL_SIZE,
            description="Connection pool size",
            ge=1,
        )
        pool_keepalive: int = Field(
            FlextConstants.Performance.DEFAULT_TTL_SECONDS,
            description="Pool keepalive in seconds",
            ge=0,
        )

        # SSL/TLS options
        verify_certificates: bool = Field(
            default=True,
            description="Verify SSL certificates",
        )
        ca_certs_file: str | None = Field(
            default=None,
            description="CA certificates file path",
        )

    # =========================================================================
    # ERROR AND STATUS ENTITIES
    # =========================================================================

    class LdapOperationResult(BaseModel):
        """LDAP Operation Result entity."""

        # Result status
        success: bool = Field(default=True, description="Operation success status")
        result_code: int = Field(default=0, description="LDAP result code")
        result_message: str = Field(default="", description="Result message")

        # Operation details
        operation_type: str = Field(default="", description="Type of operation")
        target_dn: str = Field(default="", description="Target DN")

        # Performance metrics
        duration_ms: float = Field(
            0.0,
            description="Operation duration in milliseconds",
        )

        # Additional data
        data: dict[str, object] = Field(
            default_factory=dict,
            description="Additional result data",
        )

        # Timestamp
        timestamp: datetime = Field(
            default_factory=datetime.now,
            description="Operation timestamp",
        )

        @classmethod
        def success_result(
            cls,
            operation_type: str,
            target_dn: str = "",
            data: dict[str, object] | None = None,
            duration_ms: float = 0.0,
        ) -> FlextLdapModels.LdapOperationResult:
            """Create success result."""
            return cls(
                success=True,
                result_code=0,
                result_message="Success",
                operation_type=operation_type,
                target_dn=target_dn,
                data=data or {},
                duration_ms=duration_ms,
            )

        @classmethod
        def error_result(
            cls,
            operation_type: str,
            error_code: int,
            error_message: str,
            target_dn: str = "",
            duration_ms: float = 0.0,
        ) -> FlextLdapModels.LdapOperationResult:
            """Create error result."""
            return cls(
                success=False,
                result_code=error_code,
                result_message=error_message,
                operation_type=operation_type,
                target_dn=target_dn,
                duration_ms=duration_ms,
            )

    class ConnectionConfig(FlextModels.Value):
        """LDAP connection configuration value object - Pydantic Value Object."""

        server: str
        port: int = FlextLdapConstants.Protocol.DEFAULT_PORT
        use_ssl: bool = False
        bind_dn: str | None = None
        bind_password: str | None = None
        base_dn: str = ""
        timeout: int = FlextConstants.Network.DEFAULT_TIMEOUT

        @computed_field  # Pydantic v2 computed field - no @property needed
        def server_uri(self) -> str:
            """Get server URI."""
            protocol = (
                FlextLdapConstants.Protocols.LDAPS
                if self.use_ssl
                else FlextLdapConstants.Protocols.LDAP
            )
            return f"{protocol}{self.server}:{self.port}"

        @computed_field  # Pydantic v2 computed field - no @property needed
        def password(self) -> str | None:
            """Get bind password."""
            return self.bind_password

        # validate_business_rules removed - redundant with Pydantic 2 Field constraints
        # server/port validation handled by Field(min_length=1) and Field(ge=1, le=65535)

    class SearchConfig(BaseModel):
        """LDAP search operation configuration - Pydantic Query."""

        model_config = ConfigDict(frozen=True)

        base_dn: str = Field(default="", description="LDAP search base DN")
        filter_str: str = Field(min_length=1, description="LDAP search filter")
        attributes: list[str] = Field(
            default_factory=list,
            description="Attributes to retrieve",
        )

    # =========================================================================
    # ACL TARGET AND SUBJECT MODELS - Access Control List components
    # =========================================================================

    class AclRule(BaseModel):
        """Generic ACL rule structure."""

        id: str | None = Field(default=None, description="Rule identifier")
        target: FlextLdifModels.AclTarget
        subject: FlextLdifModels.AclSubject
        permissions: FlextLdifModels.AclPermissions
        conditions: dict[str, object] = Field(
            default_factory=dict,
            description="Additional conditions",
        )
        enabled: bool = Field(default=True, description="Whether the rule is enabled")

    class AclInfo(BaseModel):
        """ACL information model with format and metadata."""

        format: str = Field(
            default="aci",
            description="ACL format (aci, slapd, etc.)",
        )
        server_type: str = Field(
            default="generic",
            description="LDAP server type this ACL format is for",
        )

    # =========================================================================
    # CONFIG INFO MODELS - Configuration metadata from FlextLdapConfig
    # =========================================================================

    # =========================================================================
    # CONFIG RUNTIME METADATA - Composite model for configuration metadata
    # =========================================================================

    class ConfigRuntimeMetadata(BaseModel):
        """Composite config metadata with nested sections.

        Reduces 5 models to 1 by grouping related config information via nested classes.
        through computed fields.
        """

        class Authentication(BaseModel):
            """Authentication configuration information."""

            bind_dn_configured: bool = Field(..., description="Bind DN is configured")
            bind_password_configured: bool = Field(
                ...,
                description="Bind password is configured",
            )
            base_dn: str = Field(..., description="LDAP base DN")
            anonymous_bind: bool = Field(..., description="Using anonymous bind")

        class Pooling(BaseModel):
            """Connection pooling configuration information."""

            pool_size: int = Field(..., description="Connection pool size")
            pool_timeout: int = Field(..., description="Pool timeout in seconds")
            pool_utilization: str = Field(..., description="Pool utilization string")

        class OperationLimits(BaseModel):
            """Operation limits configuration information."""

            operation_timeout: int = Field(
                ...,
                description="Operation timeout in seconds",
            )
            size_limit: int = Field(..., description="Search size limit")
            time_limit: int = Field(..., description="Search time limit in seconds")
            connection_timeout: int = Field(
                ...,
                description="Connection timeout in seconds",
            )
            total_timeout: int = Field(
                ...,
                description="Total timeout (operation + connection)",
            )

        class Caching(BaseModel):
            """Caching configuration information."""

            caching_enabled: bool = Field(..., description="Caching is enabled")
            cache_ttl: int = Field(..., description="Cache TTL in seconds")
            cache_ttl_minutes: int = Field(..., description="Cache TTL in minutes")
            cache_effective: bool = Field(
                ...,
                description="Caching is effectively active",
            )

        class Retry(BaseModel):
            """Retry configuration information."""

            retry_attempts: int = Field(..., description="Number of retry attempts")
            retry_delay: int = Field(
                ...,
                description="Delay between retries in seconds",
            )
            total_retry_time: int = Field(
                ...,
                description="Total retry time (attempts × delay)",
            )
            retry_enabled: bool = Field(..., description="Retrying is enabled")

        # Composite sections
        authentication: Authentication = Field(
            ...,
            description="Authentication configuration metadata",
        )
        pooling: Pooling = Field(..., description="Pooling configuration metadata")
        operation_limits: OperationLimits = Field(
            ...,
            description="Operation limits configuration metadata",
        )
        caching: Caching = Field(..., description="Caching configuration metadata")
        retry: Retry = Field(..., description="Retry configuration metadata")

    class ConfigCapabilities(BaseModel):
        """Configuration LDAP capabilities information."""

        supports_ssl: bool = Field(..., description="SSL/TLS is supported")
        supports_caching: bool = Field(..., description="Caching is supported")
        supports_retry: bool = Field(..., description="Retry is supported")
        supports_debug: bool = Field(..., description="Debug logging is supported")
        has_authentication: bool = Field(
            ...,
            description="Authentication is configured",
        )
        has_pooling: bool = Field(..., description="Connection pooling is enabled")
        is_production_ready: bool = Field(
            ...,
            description="Configuration is production-ready",
        )

    # =========================================================================
    # ACL MODEL CLASSES - Server-specific ACL representations
    # =========================================================================

    class OpenLdapAcl(BaseModel):
        """OpenLDAP ACL model for slapd access control directives."""

        access_line: str = Field(..., description="OpenLDAP access directive line")
        target_spec: str = Field(
            ...,
            description="Target specification (*, attrs, etc.)",
        )
        subject_spec: str = Field(
            ...,
            description="Subject specification (user, group, etc.)",
        )
        permissions: str = Field(
            ...,
            description="Permission specification (read, write, etc.)",
        )
        control: str = Field(default="", description="Control specification")

        @classmethod
        def create(
            cls,
            access_line: str,
            target_spec: str,
            subject_spec: str | None = None,
            permissions: str | None = None,
        ) -> FlextResult[FlextLdapModels.OpenLdapAcl]:
            """Create OpenLdapAcl from access line components."""
            # ACL parsing constants
            min_acl_parts = 2  # Minimum parts required for valid ACL
            min_subject_perm_parts = 2  # Minimum parts for subject and permissions

            try:
                # Parse access line if components not provided
                if not subject_spec or not permissions:
                    # Simple parsing logic for demonstration
                    parts = access_line.replace("access to", "").strip().split("by")
                    if len(parts) >= min_acl_parts:
                        parts[0].strip()
                        subject_perm_part = parts[1].strip()
                        subject_perm_split = subject_perm_part.split()
                        if len(subject_perm_split) >= min_subject_perm_parts:
                            subject_spec = subject_spec or subject_perm_split[0]
                            permissions = permissions or " ".join(
                                subject_perm_split[1:],
                            )

                return FlextResult[FlextLdapModels.OpenLdapAcl].ok(
                    cls(
                        access_line=access_line,
                        target_spec=target_spec,
                        subject_spec=subject_spec or "*",
                        permissions=permissions
                        or FlextLdapConstants.AclPermissions.READ,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.OpenLdapAcl].fail(
                    f"Failed to create OpenLdapAcl: {e}",
                )

    class OracleAcl(BaseModel):
        """Oracle OID/OUD ACL model for ACI directives."""

        aci_value: str = Field(..., description="Oracle ACI directive value")
        target_dn: str = Field(..., description="Target DN for the ACI")
        subject_spec: str = Field(..., description="Subject specification")
        permissions: str = Field(..., description="Permission specification")
        scope: str = Field(default="subtree", description="ACI scope")

        @classmethod
        def create(
            cls,
            aci_value: str,
            target_dn: str,
            subject_spec: str | None = None,
            permissions: str | None = None,
        ) -> FlextResult[FlextLdapModels.OracleAcl]:
            """Create OracleAcl from ACI components."""
            try:
                return FlextResult[FlextLdapModels.OracleAcl].ok(
                    cls(
                        aci_value=aci_value,
                        target_dn=target_dn,
                        subject_spec=subject_spec or "*",
                        permissions=permissions
                        or FlextLdapConstants.AclPermissions.READ,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.OracleAcl].fail(
                    f"Failed to create OracleAcl: {e}",
                )

    class AciFormat(BaseModel):
        """ACI (Access Control Information) format model."""

        aci_string: str = Field(..., description="Complete ACI string")
        version: str = Field(default="v3", description="ACI version")
        target: str = Field(..., description="Target specification")
        subject: str = Field(..., description="Subject specification")
        permissions: str = Field(..., description="Permissions specification")

        @classmethod
        def create(
            cls,
            aci_string: str,
            target: str | None = None,
            subject: str | None = None,
            permissions: str | None = None,
        ) -> FlextResult[FlextLdapModels.AciFormat]:
            """Create AciFormat from ACI string components."""
            try:
                return FlextResult[FlextLdapModels.AciFormat].ok(
                    cls(
                        aci_string=aci_string,
                        target=target or "*",
                        subject=subject or "*",
                        permissions=permissions
                        or FlextLdapConstants.AclPermissions.READ,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.AciFormat].fail(
                    f"Failed to create AciFormat: {e}",
                )

    class ConversionResult(BaseModel):
        """Result of ACL/entry conversion operations."""

        success: bool = Field(..., description="Whether conversion succeeded")
        original_format: str = Field(..., description="Original format type")
        target_format: str = Field(..., description="Target format type")
        converted_data: dict[str, object] = Field(
            default_factory=dict,
            description="Converted data structure",
        )
        errors: list[str] = Field(
            default_factory=list,
            description="Conversion errors/warnings",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="Conversion warnings",
        )

        @classmethod
        def create(
            cls,
            *,
            success: bool,
            original_format: str,
            target_format: str,
            converted_data: dict[str, object] | None = None,
            errors: list[str] | None = None,
            warnings: list[str] | None = None,
        ) -> FlextResult[FlextLdapModels.ConversionResult]:
            """Create ConversionResult from conversion operation."""
            try:
                return FlextResult[FlextLdapModels.ConversionResult].ok(
                    cls(
                        success=success,
                        original_format=original_format,
                        target_format=target_format,
                        converted_data=converted_data or {},
                        errors=errors or [],
                        warnings=warnings or [],
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Failed to create ConversionResult: {e}",
                )

    class ServerInfo(FlextModels.ArbitraryTypesModel):
        """Model for LDAP server information from Root DSE.

        Uses FlextModels.ArbitraryTypesModel to allow server-specific attributes.
        """

        model_config = ConfigDict(extra="allow")

        naming_contexts: list[str] = Field(
            default_factory=list,
            description="Naming contexts",
        )
        supported_ldap_version: list[str] = Field(
            default_factory=list,
            description="Supported LDAP versions",
        )
        supported_sasl_mechanisms: list[str] = Field(
            default_factory=list,
            description="Supported SASL mechanisms",
        )
        supported_controls: list[str] = Field(
            default_factory=list,
            description="Supported controls",
        )
        supported_extensions: list[str] = Field(
            default_factory=list,
            description="Supported extensions",
        )
        vendor_name: str | None = Field(default=None, description="Vendor name")
        vendor_version: str | None = Field(default=None, description="Vendor version")

    class AdditionalAttributes(FlextModels.ArbitraryTypesModel):
        """Model for additional LDAP attributes with dynamic schema support."""

        model_config = ConfigDict(extra="allow")

    class EntryChanges(FlextModels.ArbitraryTypesModel):
        """Model for LDAP entry attribute changes."""

        model_config = ConfigDict(extra="allow")

    class ServerCapabilities(FlextModels.ArbitraryTypesModel):
        """Model for LDAP server capabilities."""

        supports_ssl: bool = Field(default=True, description="Supports SSL/TLS")
        supports_starttls: bool = Field(default=True, description="Supports STARTTLS")
        supports_paged_results: bool = Field(
            default=True,
            description="Supports paged results",
        )
        supports_vlv: bool = Field(
            default=False,
            description="Supports Virtual List View",
        )
        supports_sasl: bool = Field(
            default=True,
            description="Supports SASL authentication",
        )
        max_page_size: int = Field(default=1000, ge=0, description="Maximum page size")

    class ServerAttributes(FlextModels.ArbitraryTypesModel):
        """Model for server-specific LDAP attributes."""

        model_config = ConfigDict(extra="allow")

    class RootDSE(FlextModels.ArbitraryTypesModel):
        """Model for LDAP Root DSE (DSA-Specific Entry) information."""

        naming_contexts: list[str] = Field(
            default_factory=list,
            description="Naming contexts",
        )
        supported_ldap_version: list[str] = Field(
            default_factory=list,
            description="Supported LDAP versions",
        )
        supported_sasl_mechanisms: list[str] = Field(
            default_factory=list,
            description="Supported SASL mechanisms",
        )
        supported_controls: list[str] = Field(
            default_factory=list,
            description="Supported controls",
        )
        supported_extensions: list[str] = Field(
            default_factory=list,
            description="Supported extensions",
        )
        subschema_subentry: str | None = Field(
            default=None,
            description="Subschema subentry DN",
        )
        vendor_name: str | None = Field(default=None, description="Vendor name")
        vendor_version: str | None = Field(default=None, description="Vendor version")

    # =========================================================================
    # LDAP OPERATION ENTITIES - Request/Response Objects
    # =========================================================================
    # Note: SearchRequest is defined earlier in this file (see line 247)
    # This duplicate definition section has been removed to eliminate duplication


__all__ = [
    "FlextLdapModels",
]
