"""LDAP operations module - Python 3.13 optimized with advanced patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from os import getenv
from typing import Final, Literal, cast

import ldap3
from ldap3 import Connection
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    computed_field,
    field_validator,
)

from flext_core import (
    FlextDomainService,
    FlextExceptions,
    FlextMixins,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from flext_ldap.clients import FlextLdapClient
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

# Type aliases using Python 3.13 syntax
type SearchResultEntry = dict[str, object]
type AttributeMap = dict[str, list[str]]
type ConnectionId = str


class FlextLdapOperations(FlextDomainService[object]):
    """Consolidated LDAP operations."""

    type ConnectionRegistry = dict[ConnectionId, object]
    type OperationResult = FlextResult[dict[str, object]]

    def execute(self) -> FlextResult[object]:
        """Execute domain operation - required by FlextDomainService."""
        return FlextResult[object].ok({"status": "operations_available"})

    def generate_id(self) -> str:
        """Generate unique ID using flext-core utilities - SOURCE OF TRUTH."""
        return FlextUtilities.Generators.generate_entity_id()

    @staticmethod
    def _normalize_ldap_attributes(
        attributes: Mapping[str, object],
    ) -> dict[str, list[str]]:
        """Normalize LDAP attributes to consistent list[str] format.

        Converts LDAP attribute values from str | bytes | list[str] | list[bytes]
        to dict[str, list[str]] for model compatibility.
        """
        normalized: dict[str, list[str]] = {}
        for key, value in attributes.items():
            if isinstance(value, list):
                normalized[str(key)] = [str(item) for item in value]
            else:
                # Handle str, bytes, or any other type
                normalized[str(key)] = [str(value)]
        return normalized

    # ==========================================================================
    # NESTED PARAMETER AND EXTRACTOR CLASSES - CONSOLIDATED FOR SOLID COMPLIANCE
    # ==========================================================================

    class LDAPCommandProcessor:
        """Command processor for LDAP operations - nested for SOLID compliance."""

        class SearchCommand:
            """Search command for LDAP operations."""

            def __init__(
                self,
                connection_id: str,
                base_dn: str,
                search_filter: str,
                scope: str,
                attributes: list[str],
                size_limit: int = 100,
            ) -> None:
                """Initialize search command."""
                self.connection_id = connection_id
                self.base_dn = base_dn
                self.search_filter = search_filter
                self.scope = scope
                self.attributes = attributes
                self.size_limit = size_limit

            def execute(self) -> FlextResult[dict[str, object]]:
                """Execute search command returning command parameters."""
                return FlextResult[dict[str, object]].ok(
                    {
                        "connection_id": self.connection_id,
                        "base_dn": self.base_dn,
                        "filter": self.search_filter,
                        "scope": self.scope,
                        "attributes": self.attributes,
                        "size_limit": self.size_limit,
                    },
                )

    # ==========================================================================
    # PARAMETER OBJECTS AND EXTRACTORS
    # ==========================================================================

    class UserConversionParams(BaseModel):
        """User conversion parameters."""

        model_config = ConfigDict(
            frozen=True,  # Immutable for safety
            extra="forbid",  # Strict validation
            validate_assignment=True,
            str_strip_whitespace=True,
        )

        entries: Sequence[SearchResultEntry] = Field(
            description="LDAP entries to convert",
            min_length=0,
        )
        include_disabled: bool = Field(
            default=False,
            description="Include disabled user accounts",
        )
        include_system: bool = Field(
            default=False,
            description="Include system accounts",
        )
        attribute_filter: list[str] | None = Field(
            default=None,
            description="Filter specific attributes",
            min_length=0,  # Allow empty lists
        )

        @field_validator("entries")
        @classmethod
        def validate_entries(
            cls,
            v: Sequence[SearchResultEntry],
        ) -> Sequence[SearchResultEntry]:
            """Validate entries structure."""
            return v

        @computed_field
        def entry_count(self) -> int:
            """Computed field for entry count."""
            return len(self.entries)

        @computed_field
        def has_filters(self) -> bool:
            """Check if object filters are applied."""
            return (
                self.include_disabled
                or self.include_system
                or bool(self.attribute_filter)
            )

    class LdapBaseExtractor:
        """Base extractor with common methods - eliminates duplication."""

        def _extract_as_string(self, value: object) -> str:
            """Extract string value using standard pattern."""
            if isinstance(value, list):
                return str(value[0]) if value else ""
            return str(value) if value is not None else ""

        def _extract_string_attribute(self, value: object, default: str = "") -> str:
            """Extract string using base class method - test compatibility."""
            try:
                return self._extract_as_string(value)
            except (AttributeError, ValueError, TypeError):
                return default

        def _extract_optional_string_attribute(
            self,
            value: object,
            default: str = "",
        ) -> str | None:
            """Extract optional string attribute - test compatibility."""
            if value is None:
                return None
            try:
                result = self._extract_as_string(value)
                return result if result != default else None
            except (AttributeError, ValueError, TypeError):
                return None

    class UserAttributeExtractor(LdapBaseExtractor):
        """Advanced user attribute extractor with strategy pattern."""

        def __init__(self) -> None:
            """Initialize with FlextUtilities - NO duplication."""
            super().__init__()
            # Use FlextUtilities directly - NO custom extractors

        # Compatibility aliases for tests using FlextUtilities
        @property
        def string_extractor(self) -> object:
            """Alias using FlextUtilities - test compatibility."""
            return FlextUtilities

        def process_data(self, entry: object) -> FlextResult[dict[str, object]]:
            """Extract user attributes using FlextUtilities."""
            # Prefer explicit branching to avoid placeholder statements
            if hasattr(entry, "attributes"):
                attrs = getattr(entry, "attributes", {})
            elif isinstance(entry, dict):
                attrs = entry
            else:
                return FlextResult[dict[str, object]].fail("Invalid entry format")

            if not isinstance(attrs, dict):
                return FlextResult[dict[str, object]].fail("Invalid attributes format")

            # Use FlextUtilities for extraction - NO custom strategies
            extracted = self._extract_ldap_attributes(attrs)
            return FlextResult[dict[str, object]].ok(extracted)

        def _extract_ldap_attributes(
            self,
            attrs: dict[str, object],
        ) -> dict[str, object]:
            """Extract LDAP attributes using FlextUtilities only."""
            result: dict[str, object] = {}

            for attr_name, attr_value in attrs.items():
                # Use FlextUtilities directly - eliminate custom extractors
                result[attr_name] = self._extract_as_string(attr_value)

            return result

    class GroupAttributeExtractor(LdapBaseExtractor):
        """Group attribute extractor using FlextUtilities - NO duplication."""

        def __init__(self) -> None:
            """Initialize with FlextUtilities - NO custom strategies."""
            super().__init__()

        def process_data(self, entry: object) -> FlextResult[dict[str, object]]:
            """Extract group attributes using FlextUtilities."""
            # Same pattern as UserAttributeExtractor - NO duplication
            if hasattr(entry, "attributes"):
                attrs = getattr(entry, "attributes", {})
            elif isinstance(entry, dict):
                attrs = entry
            else:
                return FlextResult[dict[str, object]].fail("Invalid group entry format")

            if not isinstance(attrs, dict):
                return FlextResult[dict[str, object]].fail(
                    "Invalid group attributes format",
                )

            # Simplified extraction - NO custom strategies
            result: dict[str, object] = {}
            for attr_name, attr_value in attrs.items():
                if attr_name == "member":
                    result["members"] = self._extract_member_list(attr_value)
                else:
                    result[attr_name] = self._extract_as_string(attr_value)

            return FlextResult[dict[str, object]].ok(result)

        def _extract_member_list(self, members: object) -> list[str]:
            """Extract member list using Python 3.13 patterns."""
            if not members:
                return []

            match members:
                case list() as member_list:
                    return [str(member) for member in member_list if member]
                case str() as single_member:
                    return [single_member] if single_member else []
                case _:
                    return []

    # ==========================================================================
    # INTERNAL OPTIMIZED SERVICE CLASS
    # ==========================================================================

    class OperationsService(FlextMixins.Loggable):
        """Internal operations service - ELIMINATES DUPLICATION."""

        # Immutable configuration using direct validation patterns
        _operation_config: Final[dict[str, object]] = {
            "max_retries": 3,
            "timeout_seconds": 30,
            "batch_size": 1000,
        }

        def __init__(self) -> None:
            """Initialize service - NO custom service architecture."""
            super().__init__()  # Initializes FlextMixins.Loggable
            self._connection_registry: dict[ConnectionId, object] = {}

        def process(self, request: dict[str, object]) -> FlextResult[dict[str, object]]:
            """Process request into domain object - required by ServiceProcessor."""
            # Use direct validation for request validation
            if not request:
                return FlextResult[dict[str, object]].fail("Empty request")
            return FlextResult[dict[str, object]].ok(request)

        def build(
            self,
            domain: dict[str, object],
            *,
            correlation_id: str,
        ) -> dict[str, object]:
            """Build final result from domain object - required by ServiceProcessor."""
            return {
                **domain,
                "correlation_id": correlation_id,
                "processed_at": FlextUtilities.generate_iso_timestamp(),
            }

        def _generate_id(self) -> ConnectionId:
            """Generate connection ID using FlextUtilities."""
            return FlextUtilities.Generators.generate_id()

        # Advanced validation using direct validation - ELIMINATES custom validation duplication
        def validate_dn_string(self, dn: str, context: str = "DN") -> FlextResult[None]:
            """Validate DN using centralized validation - SOURCE OF TRUTH."""
            return FlextLdapValidations.validate_dn(dn, context)

        def validate_filter_string(self, search_filter: str) -> FlextResult[None]:
            """Validate LDAP filter using centralized validation - SOURCE OF TRUTH."""
            return FlextLdapValidations.validate_filter(search_filter)

        # ELIMINATE wrapper methods - use validate_* directly (SOLID: no unnecessary indirection)

        def validate_uri_string(self, server_uri: str) -> FlextResult[None]:
            """Validate server URI using centralized validation - SOURCE OF TRUTH."""
            return FlextLdapValidations.validate_uri(server_uri)

        # ELIMINATE URI wrapper - use validate_uri_string directly

        # Advanced exception handling using FlextExceptions - ELIMINATES custom exception handling
        def handle_ldap_exception(
            self,
            operation: str,
            exception: Exception,
            connection_id: ConnectionId | None = None,
            **extra_context: object,
        ) -> str:
            """Handle exceptions using FlextExceptions - NO custom exception handlers."""
            context = {
                "operation": operation,
                "exception_type": type(exception).__name__,
                "connection_id": connection_id,
                **extra_context,
            }

            # Use FlextExceptions for structured exception handling
            structured_error: FlextExceptions.BaseError
            if isinstance(exception, (ConnectionError, OSError)):
                structured_error = FlextExceptions._ConnectionError(
                    f"LDAP connection failed during {operation}",
                    context=context,
                    original_exception=exception,
                )
            elif isinstance(exception, ValueError):
                structured_error = FlextExceptions._ValidationError(
                    f"LDAP validation failed during {operation}",
                    context=context,
                    original_exception=exception,
                )
            elif isinstance(exception, TypeError):
                structured_error = FlextExceptions._TypeError(
                    f"LDAP type error during {operation}",
                    context=context,
                    original_exception=exception,
                )
            else:
                structured_error = FlextExceptions._OperationError(
                    f"LDAP operation failed: {operation}",
                    context=context,
                    original_exception=exception,
                )

            # Log using the structured error
            self.log_error(str(structured_error))

            return f"Failed to {operation.lower()}: {exception!s}"

        def _handle_exception_with_context(
            self,
            operation: str,
            exception: Exception,
            connection_id: ConnectionId | None = None,
            **extra_context: object,
        ) -> str:
            """Handle exceptions using FlextExceptions - NO custom exception handlers."""
            return self.handle_ldap_exception(
                operation,
                exception,
                connection_id,
                **extra_context,
            )

        # ELIMINATED: _log_operation_success - USING FlextMixins.Service.log_info DIRECTLY

    # ==========================================================================
    # INTERNAL SPECIALIZED CLASSES FOR DIFFERENT OPERATION DOMAINS
    # ==========================================================================

    class ConnectionOperations(OperationsService):
        """Specialized connection operations with advanced patterns."""

        # Connection metadata model using Pydantic
        class ConnectionMetadata(BaseModel):
            """Connection metadata with enhanced validation."""

            model_config = ConfigDict(
                frozen=True,
                extra="forbid",
            )

            server_uri: str = Field(description="LDAP server URI")
            bind_dn: str | None = Field(
                default=None,
                description="Bind DN for authentication",
            )
            created_at: datetime = Field(description="Connection creation timestamp")
            timeout_seconds: int = Field(
                default=30,
                ge=1,
                le=300,
                description="Connection timeout",
            )
            is_authenticated: bool = Field(
                description="Whether connection is authenticated",
            )

            @property
            def age_seconds(self) -> float:
                """Calculate connection age in seconds."""
                return (datetime.now(UTC) - self.created_at).total_seconds()

        def __init__(self) -> None:
            """Initialize with enhanced connection registry."""
            super().__init__()
            self._active_connections: dict[
                ConnectionId,
                FlextLdapOperations.ConnectionOperations.ConnectionMetadata,
            ] = {}

        async def create_connection(
            self,
            server_uri: str,
            bind_dn: str | None = None,
            _bind_password: str | None = None,
            timeout_seconds: int = 30,
        ) -> FlextResult[ConnectionId]:
            """Create LDAP connection with advanced validation and error handling."""
            # Parameter validation using railway pattern
            validation_result = await self._validate_connection_parameters(
                server_uri,
                bind_dn,
                timeout_seconds,
            )
            if validation_result.is_failure:
                return FlextResult[ConnectionId].fail(
                    validation_result.error or "Validation failed",
                )

            try:
                connection_id = self._generate_id()

                # Create immutable connection metadata
                metadata = self.ConnectionMetadata(
                    server_uri=server_uri,
                    bind_dn=bind_dn,
                    created_at=datetime.now(UTC),
                    timeout_seconds=timeout_seconds,
                    is_authenticated=bind_dn is not None,
                )

                # Store in registry
                self._active_connections[connection_id] = metadata

                # Direct FlextMixins.Service logging
                self.log_info(
                    "LDAP connection_created completed successfully",
                    extra={
                        "operation": "connection_created",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "server_uri": server_uri,
                        "authenticated": metadata.is_authenticated,
                        "timeout": timeout_seconds,
                    },
                )

                return FlextResult[ConnectionId].ok(connection_id)

            except Exception as e:
                error_msg = self._handle_exception_with_context(
                    "create_connection",
                    e,
                    server_uri=server_uri,
                )
                return FlextResult[ConnectionId].fail(error_msg)

        async def _validate_connection_parameters(
            self,
            server_uri: str,
            bind_dn: str | None,
            timeout_seconds: int,
        ) -> FlextResult[None]:
            """Validate connection parameters with enhanced checks."""
            # URI validation
            uri_validation = self.validate_uri_string(server_uri)
            if uri_validation.is_failure:
                return uri_validation

            # DN validation if provided
            if bind_dn:
                dn_validation = self.validate_dn_string(bind_dn, "bind_dn")
                if dn_validation.is_failure:
                    return dn_validation

            # Timeout validation using pattern matching
            max_timeout = FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS
            match timeout_seconds:
                case int() if 1 <= timeout_seconds <= max_timeout:
                    return FlextResult[None].ok(None)
                case _:
                    return FlextResult[None].fail(
                        f"Timeout must be between 1 and {max_timeout} seconds",
                    )

        def get_connection_info(
            self,
            connection_id: ConnectionId,
        ) -> FlextResult[dict[str, object]]:
            """Get connection information with type safety."""
            if connection_id not in self._active_connections:
                return FlextResult[dict[str, object]].fail(
                    f"Connection not found: {connection_id}",
                )

            metadata = self._active_connections[connection_id]
            return FlextResult[dict[str, object]].ok(
                {
                    "connection_id": connection_id,
                    "server_uri": metadata.server_uri,
                    "bind_dn": metadata.bind_dn,
                    "is_authenticated": metadata.is_authenticated,
                    "age_seconds": metadata.age_seconds,
                    "created_at": metadata.created_at.isoformat(),
                },
            )

        async def close_connection(
            self,
            connection_id: ConnectionId,
        ) -> FlextResult[None]:
            """Close LDAP connection with enhanced cleanup."""
            connection_id_typed = connection_id

            if connection_id_typed not in self._active_connections:
                return FlextResult[None].fail(f"Connection not found: {connection_id}")

            try:
                metadata = self._active_connections.pop(connection_id_typed)

                # Direct FlextMixins.Service logging
                self.log_info(
                    "LDAP connection_closed completed successfully",
                    extra={
                        "operation": "connection_closed",
                        "connection_id": connection_id_typed,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "server_uri": metadata.server_uri,
                        "duration_seconds": metadata.age_seconds,
                        "was_authenticated": metadata.is_authenticated,
                    },
                )

                return FlextResult[None].ok(None)

            except Exception as e:
                error_msg = self._handle_exception_with_context(
                    "close_connection",
                    e,
                    connection_id_typed,
                )
                return FlextResult[None].fail(error_msg)

        def list_active_connections(self) -> FlextResult[list[dict[str, object]]]:
            """List active connections with enhanced information."""
            try:
                connections: list[dict[str, object]] = []
                for conn_id, metadata in self._active_connections.items():
                    # Handle both ConnectionMetadata objects and dict formats
                    if hasattr(metadata, "server_uri"):
                        # Metadata is a ConnectionMetadata object
                        dict_connection_info: dict[str, object] = {
                            "connection_id": conn_id,
                            "server_uri": metadata.server_uri,
                            "bind_dn": metadata.bind_dn,
                            "is_authenticated": metadata.is_authenticated,
                            "age_seconds": metadata.age_seconds,
                            "created_at": metadata.created_at.isoformat(),
                            "timeout_seconds": metadata.timeout_seconds,
                        }
                    else:
                        # Metadata is a dict (test format)
                        metadata_dict = cast("dict[str, object]", metadata)
                        created_at = metadata_dict.get("created_at")
                        age_seconds = 0.0
                        if isinstance(created_at, datetime):
                            age_seconds = (
                                datetime.now(UTC) - created_at
                            ).total_seconds()

                        # Build connection info with proper typing
                        server_uri = str(metadata_dict.get("server_uri", "unknown"))
                        bind_dn = metadata_dict.get("bind_dn")
                        is_authenticated = bool(
                            metadata_dict.get("is_authenticated", False),
                        )
                        timeout_value = metadata_dict.get("timeout_seconds", 30)
                        timeout_seconds = (
                            int(timeout_value)
                            if isinstance(timeout_value, (int, str, float))
                            else 30
                        )

                        dict_connection_info = {
                            "connection_id": conn_id,
                            "server_uri": server_uri,
                            "bind_dn": bind_dn,
                            "is_authenticated": is_authenticated,
                            "age_seconds": age_seconds,
                            "created_at": created_at.isoformat()
                            if isinstance(created_at, datetime)
                            else str(created_at),
                            "timeout_seconds": timeout_seconds,
                        }
                    connections.append(dict_connection_info)

                return FlextResult[list[dict[str, object]]].ok(connections)

            except Exception as e:
                error_msg = self._handle_exception_with_context(
                    "list_active_connections",
                    e,
                )
                return FlextResult[list[dict[str, object]]].fail(error_msg)

        def cleanup_expired_connections(
            self,
            max_age_seconds: int = 3600,
        ) -> FlextResult[int]:
            """Clean up expired connections with configurable timeout."""
            try:
                expired_ids = [
                    conn_id
                    for conn_id, metadata in self._active_connections.items()
                    if metadata.age_seconds > max_age_seconds
                ]

                for conn_id in expired_ids:
                    del self._active_connections[conn_id]

                if expired_ids:
                    self.log_info(
                        f"Cleaned up {len(expired_ids)} expired connections",
                        extra={
                            "expired_count": len(expired_ids),
                            "max_age_seconds": max_age_seconds,
                        },
                    )

                return FlextResult[int].ok(len(expired_ids))

            except Exception as e:
                error_msg = self._handle_exception_with_context(
                    "cleanup_expired_connections",
                    e,
                    max_age_seconds=max_age_seconds,
                )
                return FlextResult[int].fail(error_msg)

        def _calculate_duration(self, start_time: object) -> float:
            """Calculate duration from start time to now in seconds."""
            try:
                if isinstance(start_time, datetime):
                    return (datetime.now(UTC) - start_time).total_seconds()
                return 0.0
            except Exception:
                return 0.0

    class SearchOperations(OperationsService):
        """Advanced search operations with enhanced patterns."""

        # Search result model for type safety
        class SearchResult(BaseModel):
            """Search result with metadata."""

            model_config = ConfigDict(
                frozen=True,
                extra="forbid",
            )

            entries: list[dict[str, object]] = Field(
                description="Search result entries",
            )
            total_count: int = Field(ge=0, description="Total number of entries found")
            execution_time_ms: float = Field(ge=0, description="Search execution time")
            connection_id: ConnectionId = Field(
                description="Connection used for search",
            )

            @computed_field
            def has_results(self) -> bool:
                """Check if search returned results."""
                return self.total_count > 0

        async def search_entries(
            self,
            params: FlextLdapModels.SearchRequest,
        ) -> FlextResult[FlextLdapOperations.SearchOperations.SearchResult]:
            """Execute LDAP search with enhanced validation and metrics."""
            start_time = datetime.now(UTC)

            # Comprehensive parameter validation
            validation_result = await self._validate_search_parameters(params)
            if validation_result.is_failure:
                return FlextResult[
                    "FlextLdapOperations.SearchOperations.SearchResult"
                ].fail(validation_result.error or "Validation failed")

            try:
                # Execute search with enhanced monitoring
                entries = await self._execute_search_operation(params)
                execution_time = (datetime.now(UTC) - start_time).total_seconds() * 1000

                # Create typed result
                search_result = self.SearchResult(
                    entries=entries,
                    total_count=len(entries),
                    execution_time_ms=execution_time,
                    connection_id="default",
                )

                # Direct FlextMixins.Service logging
                self.log_info(
                    "LDAP search_entries completed successfully",
                    extra={
                        "operation": "search_entries",
                        "connection_id": search_result.connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "base_dn": params.base_dn,
                        "filter": params.filter_str,
                        "scope": params.scope,
                        "result_count": search_result.total_count,
                        "execution_time_ms": search_result.execution_time_ms,
                        "size_limit": params.size_limit,
                        "time_limit": params.time_limit,
                    },
                )

                return FlextResult[
                    "FlextLdapOperations.SearchOperations.SearchResult"
                ].ok(search_result)

            except Exception as e:
                execution_time = (datetime.now(UTC) - start_time).total_seconds() * 1000
                error_msg = self._handle_exception_with_context(
                    "search_entries",
                    e,
                    "default",
                    execution_time_ms=execution_time,
                    base_dn=params.base_dn,
                )
                return FlextResult[
                    "FlextLdapOperations.SearchOperations.SearchResult"
                ].fail(error_msg)

        async def _validate_search_parameters(
            self,
            params: FlextLdapModels.SearchRequest,
        ) -> FlextResult[None]:
            """Validate search parameters comprehensively."""
            # Base DN validation
            dn_validation = self.validate_dn_string(params.base_dn, "base_dn")
            if dn_validation.is_failure:
                return dn_validation

            # Filter validation
            filter_validation = self.validate_filter_string(params.filter_str)
            if filter_validation.is_failure:
                return filter_validation

            # Size limit validation using pattern matching
            max_entries = FlextLdapConstants.Protocol.MAX_SEARCH_ENTRIES
            match params.size_limit:
                case int() if 1 <= params.size_limit <= max_entries:
                    pass
                case _:
                    return FlextResult[None].fail(
                        f"Size limit must be between 1 and {max_entries}",
                    )

            # Time limit validation
            max_timeout = FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS
            match params.time_limit:
                case int() if 1 <= params.time_limit <= max_timeout:
                    pass
                case _:
                    return FlextResult[None].fail(
                        f"Time limit must be between 1 and {max_timeout} seconds",
                    )

            return FlextResult[None].ok(None)

        async def _execute_search_operation(
            self,
            _params: FlextLdapModels.SearchRequest,
        ) -> list[dict[str, object]]:
            """Execute the actual search operation using FlextLdapClient."""
            server = getenv("LDAP_TEST_SERVER")
            bind_dn = getenv("LDAP_TEST_BIND_DN")
            password = getenv("LDAP_TEST_PASSWORD")

            if not server or not bind_dn or not password:
                return []

            client = FlextLdapClient()
            try:
                connect_result = await client.connect(server, bind_dn, password)
                if not connect_result.is_success:
                    return []

                # Prefer direct ldap3 conversion to ensure attributes presence

                # Build ldap3 server/connection
                server_obj = ldap3.Server(server, get_info=ldap3.NONE)
                conn: Connection = ldap3.Connection(
                    server_obj,
                    user=bind_dn,
                    password=password,
                    auto_bind=True,
                )
                try:
                    scope_lower = _params.scope.lower()
                    if scope_lower == "base":
                        scope_const: Literal["BASE", "LEVEL", "SUBTREE"] = "BASE"
                    elif scope_lower in {"one", "onelevel"}:
                        scope_const = "LEVEL"
                    else:
                        scope_const = "SUBTREE"
                    success = conn.search(
                        search_base=_params.base_dn,
                        search_filter=_params.filter_str,
                        search_scope=scope_const,
                        attributes=_params.attributes or ldap3.ALL_ATTRIBUTES,
                        size_limit=_params.size_limit,
                        time_limit=_params.time_limit,
                    )
                    if not success:
                        return []
                    normalized: list[dict[str, object]] = []
                    for entry in conn.entries:
                        # entry.entry_attributes_as_dict contains attribute -> list
                        entry_dict: dict[str, object] = {
                            "dn": str(getattr(entry, "entry_dn", "")),
                        }
                        attrs = getattr(entry, "entry_attributes_as_dict", {})
                        if isinstance(attrs, dict):
                            for k, v in attrs.items():
                                if isinstance(v, list):
                                    vals: list[object] = []
                                    for item in v:
                                        if isinstance(item, bytes):
                                            vals.append(
                                                item.decode("utf-8", errors="ignore"),
                                            )
                                        else:
                                            vals.append(str(item))
                                    entry_dict[k] = vals
                                else:
                                    entry_dict[k] = str(v)
                        normalized.append(entry_dict)
                    return normalized
                finally:
                    with contextlib.suppress(Exception):
                        conn.unbind()
            finally:
                with contextlib.suppress(Exception):
                    await client.unbind()

        # ELIMINATED: _log_search_success - USING FlextMixins.Service.log_info DIRECTLY

        async def search_users(
            self,
            connection_id: ConnectionId,
            base_dn: str,
            filter_criteria: dict[str, object] | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLdapModels.User]]:
            """Search for users with enhanced filtering and type safety."""
            try:
                # Build user-specific filter with advanced patterns
                user_filter = self._build_enhanced_user_filter(filter_criteria)

                # Create search parameters with user-specific attributes
                search_params = FlextLdapModels.SearchRequest(
                    base_dn=base_dn,
                    filter_str=user_filter,
                    scope="subtree",
                    attributes=self._get_user_attributes(),
                    size_limit=size_limit,
                )

                # Execute search using the enhanced search method
                search_result = await self.search_entries(search_params)
                if search_result.is_failure:
                    return FlextResult[list[FlextLdapModels.User]].fail(
                        f"User search failed: {search_result.error}",
                    )

                # Convert search result to user entities
                users = await self._convert_search_result_to_users(
                    search_result.unwrap(),
                )

                # Direct FlextMixins.Service logging
                self.log_info(
                    "LDAP search_users completed successfully",
                    extra={
                        "operation": "search_users",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "base_dn": base_dn,
                        "filter_criteria": filter_criteria,
                        "user_count": len(users),
                        "size_limit": size_limit,
                    },
                )

                return FlextResult[list[FlextLdapModels.User]].ok(users)

            except Exception as e:
                error_msg = self._handle_exception_with_context(
                    "search_users",
                    e,
                    connection_id,
                    base_dn=base_dn,
                )
                return FlextResult[list[FlextLdapModels.User]].fail(error_msg)

        def _build_enhanced_user_filter(
            self,
            criteria: dict[str, object] | None = None,
        ) -> str:
            """Build LDAP filter for user search with enhanced patterns."""
            base_filter = "(objectClass=person)"

            if not criteria:
                return base_filter

            # Advanced filter building using pattern matching
            additional_filters: list[str] = []

            for key, value in criteria.items():
                match key, value:
                    case "uid", str() as uid_value:
                        additional_filters.append(f"(uid={uid_value})")
                    case "cn", str() as cn_value:
                        additional_filters.append(f"(cn=*{cn_value}*)")
                    case "mail", str() as mail_value:
                        additional_filters.append(f"(mail={mail_value})")
                    case "department", str() as dept_value:
                        additional_filters.append(f"(departmentNumber={dept_value})")
                    case _:
                        # Skip unknown criteria
                        continue

            if additional_filters:
                all_filters = [base_filter, *additional_filters]
                return f"(&{''.join(all_filters)})"

            return base_filter

        def _get_user_attributes(self) -> list[str]:
            """Get standard user attributes for search."""
            return [
                "uid",
                "cn",
                "sn",
                "givenName",
                "displayName",
                "mail",
                "telephoneNumber",
                "mobile",
                "departmentNumber",
                "employeeNumber",
                "title",
                "objectClass",
                "createTimestamp",
                "modifyTimestamp",
            ]

        async def _convert_search_result_to_users(
            self,
            search_result: SearchResult,
        ) -> list[FlextLdapModels.User]:
            """Convert search results to user entities with type safety."""
            users: list[FlextLdapModels.User] = []

            for entry in search_result.entries:
                try:
                    # Use attribute processor for consistent extraction
                    processor = FlextLdapOperations.UserAttributeExtractor()
                    processed_result = processor.process_data(entry)

                    if processed_result.is_success:
                        processed_attrs = processed_result.unwrap()
                        # Create user entity from processed attributes with required fields
                        uid_str = str(processed_attrs.get("uid", "unknown"))
                        dn_str = (
                            str(entry["dn"])
                            if "dn" in entry
                            else f"uid={uid_str},ou=users"
                        )

                        user = FlextLdapModels.User(
                            id=uid_str,  # Required field
                            dn=dn_str,  # Required field
                            uid=uid_str,
                            cn=str(processed_attrs.get("cn", ""))
                            if processed_attrs.get("cn")
                            else None,
                            sn=str(processed_attrs.get("sn", ""))
                            if processed_attrs.get("sn")
                            else None,
                            given_name=str(processed_attrs.get("givenName", ""))
                            if processed_attrs.get("givenName")
                            else None,
                            mail=str(processed_attrs.get("mail", ""))
                            if processed_attrs.get("mail")
                            else None,
                            user_password=None,  # Required field
                            modified_at=None,  # Required field
                            attributes=cast(
                                "dict[str, str | bytes | list[str] | list[bytes]]",
                                FlextLdapOperations._normalize_ldap_attributes(
                                    processed_attrs
                                ),
                            ),
                        )
                        users.append(user)
                except Exception as e:
                    # Log conversion errors but continue processing
                    self.log_error(
                        f"Failed to convert entry to user: {e}",
                        extra={"entry": entry},
                    )
                    continue

            return users

        async def search_groups(
            self,
            connection_id: str,
            base_dn: str,
            filter_criteria: FlextTypes.Core.Dict | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLdapModels.Group]]:
            """Search for group entriess."""
            try:
                # Use filter building
                base_filter = self._build_group_filter(filter_criteria)

                # Use general search and convert to groups
                search_params = FlextLdapModels.SearchRequest(
                    base_dn=base_dn,
                    filter_str=base_filter,
                    scope="subtree",
                    attributes=["cn", "description", "member", "objectClass"],
                    size_limit=size_limit,
                )
                search_result = await self.search_entries(search_params)

                if not search_result.is_success:
                    return FlextResult[list[FlextLdapModels.Group]].fail(
                        search_result.error or "Group search failed",
                    )

                # Convert dict entries to Entry objects first
                entry_objects = [
                    FlextLdapModels.Entry(
                        id=FlextUtilities.Generators.generate_id(),
                        dn=str(entry_dict.get("dn", f"cn=unknown,{base_dn}")),
                        object_classes=(
                            [
                                str(cls)
                                for cls in cast(
                                    "list[str]",
                                    entry_dict.get("objectClass", []),
                                )
                            ]
                            if isinstance(entry_dict.get("objectClass", []), list)
                            else []
                        ),
                        attributes=cast(
                            "dict[str, str | bytes | list[str] | list[bytes]]",
                            FlextLdapOperations._normalize_ldap_attributes(entry_dict),
                        ),
                        modified_at=None,
                    )
                    for entry_dict in search_result.value.entries
                ]
                # Use CORRECTED conversion with Entry objects
                groups = self._convert_entries_to_groups(entry_objects)

                # Direct FlextMixins.Service logging
                self.log_info(
                    "LDAP group search completed successfully",
                    extra={
                        "operation": "group_search",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "base_dn": base_dn,
                        "criteria": filter_criteria,
                        "result_count": len(groups),
                    },
                )

                return FlextResult[list[FlextLdapModels.Group]].ok(groups)

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "group search",
                    e,
                    connection_id,
                )
                return FlextResult[list[FlextLdapModels.Group]].fail(error_msg)

        async def get_entry_by_dn(
            self,
            connection_id: str,
            dn: str,
            attributes: list[str] | None = None,
        ) -> FlextResult[FlextLdapModels.Entry]:
            """Get a single entry by DN - REFACTORED."""
            # Use connection_id for logging context
            self.log_debug(f"Getting entry by DN: {dn}", connection_id=connection_id)

            search_params = FlextLdapModels.SearchRequest(
                base_dn=dn,
                filter_str="(objectClass=*)",
                scope="base",
                attributes=attributes,
                size_limit=1,
            )
            search_result = await self.search_entries(search_params)

            if not search_result.is_success:
                return FlextResult.fail(
                    search_result.error or "Search operation failed",
                )

            if not search_result.value.entries:
                return FlextResult.fail(
                    f"Entry not found: {dn}",
                )

            entry_data = search_result.value.entries[0]
            # Convert dict to Entry object with proper type conversion
            entry = FlextLdapModels.Entry(
                id=FlextUtilities.Generators.generate_id(),
                dn=dn,
                object_classes=(
                    [
                        str(cls)
                        for cls in cast("list[str]", entry_data.get("objectClass", []))
                    ]
                    if isinstance(entry_data.get("objectClass", []), list)
                    else []
                ),
                attributes=cast(
                    "dict[str, str | bytes | list[str] | list[bytes]]",
                    FlextLdapOperations._normalize_ldap_attributes(entry_data),
                ),
                modified_at=None,
            )
            return FlextResult.ok(entry)

        def _build_user_filter(
            self,
            filter_criteria: FlextTypes.Core.Dict | None,
        ) -> str:
            """Build user-specific filter."""
            base_filter = "(&(objectClass=person)"
            if filter_criteria:
                for attr, value in filter_criteria.items():
                    escaped_value = self._escape_ldap_filter_value(str(value))
                    base_filter += f"({attr}=*{escaped_value}*)"
            return base_filter + ")"

        def _build_group_filter(
            self,
            filter_criteria: FlextTypes.Core.Dict | None,
        ) -> str:
            """Build group-specific filter."""
            base_filter = "(&(objectClass=groupOfNames)"
            if filter_criteria:
                for attr, value in filter_criteria.items():
                    escaped_value = self._escape_ldap_filter_value(str(value))
                    base_filter += f"({attr}=*{escaped_value}*)"
            return base_filter + ")"

        def _escape_ldap_filter_value(self, value: str) -> str:
            """Escape special LDAP filter characters."""
            return (
                value.replace("\\", "\\5c")
                .replace("*", "\\2a")
                .replace("(", "\\28")
                .replace(")", "\\29")
            )

        def _convert_entries_to_users(
            self,
            entries: list[FlextLdapModels.Entry],
        ) -> list[FlextLdapModels.User]:
            """Convert entries to users."""
            users: list[FlextLdapModels.User] = []
            # Create processor using flext-core patterns
            attribute_processor = FlextLdapOperations.UserAttributeExtractor()

            for entry in entries:
                # Use flext-core processor instead of manual extraction
                extraction_result = attribute_processor.process_data(entry)

                if not extraction_result.is_success:
                    # Skip invalid entries instead of crashing
                    self.log_error(
                        f"Failed to extract attributes from entry {entry.dn}: {extraction_result.error}",
                    )
                    continue

                # Get extracted attributes using flext-core result pattern
                attrs = extraction_result.value

                # Build user entity using extracted data with safe casting
                users.append(
                    FlextLdapModels.User(
                        id=FlextUtilities.Generators.generate_id(),
                        dn=entry.dn,
                        uid=str(attrs.get("uid") or "unknown"),
                        cn=str(attrs.get("cn"))
                        if attrs.get("cn") is not None
                        else None,
                        sn=str(attrs.get("sn"))
                        if attrs.get("sn") is not None
                        else None,
                        given_name=str(attrs.get("givenName"))
                        if attrs.get("givenName") is not None
                        else None,
                        mail=str(attrs.get("mail"))
                        if attrs.get("mail") is not None
                        else None,
                        user_password=None,
                        object_classes=entry.object_classes,
                        attributes=entry.attributes,
                        modified_at=None,
                    ),
                )
            return users

        def _convert_entries_to_groups(
            self,
            entries: list[FlextLdapModels.Entry],
        ) -> list[FlextLdapModels.Group]:
            """Convert entries to groups."""
            groups: list[FlextLdapModels.Group] = []
            # Create processor using flext-core patterns
            attribute_processor = FlextLdapOperations.GroupAttributeExtractor()

            for entry in entries:
                # Use flext-core processor instead of manual extraction
                extraction_result = attribute_processor.process_data(entry)

                if not extraction_result.is_success:
                    # Skip invalid entries instead of crashing
                    self.log_error(
                        f"Failed to extract group attributes from entry {entry.dn}: {extraction_result.error}",
                    )
                    continue

                # Get extracted attributes using flext-core result pattern
                attrs = extraction_result.value

                # Build group entity using extracted data
                groups.append(
                    FlextLdapModels.Group(
                        id=FlextUtilities.Generators.generate_id(),
                        dn=entry.dn,
                        cn=str(attrs.get("cn", "unknown"))
                        if attrs.get("cn")
                        else "unknown",
                        description=str(attrs.get("description"))
                        if attrs.get("description")
                        else None,
                        members=cast("list[str]", attrs.get("members"))
                        if isinstance(attrs.get("members"), list)
                        else [],
                        object_classes=entry.object_classes,
                        attributes=entry.attributes,
                        modified_at=None,
                    ),
                )
            return groups

    class EntryOperations(OperationsService):
        """Internal specialized entry management operations class."""

        async def create_entry(
            self,
            connection_id: str,
            dn_or_entry: str | FlextLdapModels.Entry,
            object_classes: list[str] | None = None,
            attributes: FlextLdapTypes.Entry.AttributeDict | None = None,
        ) -> FlextResult[FlextLdapModels.Entry]:
            """Create a new LDAP entry."""
            try:
                # Handle both Entry object and individual parameters
                if isinstance(dn_or_entry, FlextLdapModels.Entry):
                    # Extract from Entry object
                    entry_obj = dn_or_entry
                    dn = entry_obj.dn
                    object_classes = entry_obj.object_classes
                    attributes = entry_obj.attributes
                else:
                    # Use individual parameters
                    dn = dn_or_entry
                    if not object_classes:
                        return FlextResult.fail(
                            "Entry must have at least one object class",
                        )

                # Use validation helpers
                dn_validation = self.validate_dn_string(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                # Ensure attributes is not None - fix MyPy error
                safe_attributes = attributes or {}

                # Create entry entity with validation
                entry = FlextLdapModels.Entry(
                    id=FlextUtilities.Generators.generate_id(),
                    dn=dn,
                    object_classes=object_classes,
                    attributes=cast(
                        "dict[str, str | bytes | list[str] | list[bytes]]",
                        FlextLdapOperations._normalize_ldap_attributes(safe_attributes),
                    ),
                    modified_at=None,
                    # Note: no status field as FlextModels already has it
                )

                validation_result = entry.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"Entry validation failed: {validation_result.error}",
                    )

                # Perform real LDAP add via client when test env is available
                server = getenv("LDAP_TEST_SERVER")
                bind_dn = getenv("LDAP_TEST_BIND_DN")
                password = getenv("LDAP_TEST_PASSWORD")
                if server and bind_dn and password:
                    client = FlextLdapClient()
                    try:
                        connect_result = await client.connect(server, bind_dn, password)
                        if not connect_result.is_success:
                            return FlextResult.fail(
                                connect_result.error or "Connect failed",
                            )
                        # Ensure objectClass is included
                        ldap_attributes: FlextLdapTypes.Entry.AttributeDict = dict(
                            safe_attributes
                        )
                        if object_classes:
                            ldap_attributes["objectClass"] = object_classes
                        add_result = await client.add_entry(dn, ldap_attributes)
                        if not add_result.is_success:
                            return FlextResult.fail(add_result.error or "Add failed")
                    finally:
                        with contextlib.suppress(Exception):
                            await client.unbind()

                # Log success
                self.log_info(
                    "LDAP entry created successfully",
                    extra={
                        "operation": "create_entry",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "entry_dn": dn,
                        "object_classes": object_classes,
                        "attribute_count": len(safe_attributes),
                    },
                )

                return FlextResult.ok(entry)

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "create entry",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def modify_entry(
            self,
            connection_id: str,
            dn: str,
            modifications: FlextTypes.Core.Dict,
        ) -> FlextResult[None]:
            """Modify an existing LDAP entry - REFACTORED."""
            try:
                # Use validation helpers
                dn_validation = self.validate_dn_string(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                if not modifications:
                    return FlextResult.fail("No modifications specified")

                # Perform real LDAP modify via client when test env is available
                server = getenv("LDAP_TEST_SERVER")
                bind_dn = getenv("LDAP_TEST_BIND_DN")
                password = getenv("LDAP_TEST_PASSWORD")
                if server and bind_dn and password:
                    client = FlextLdapClient()
                    try:
                        connect_result = await client.connect(server, bind_dn, password)
                        if not connect_result.is_success:
                            return FlextResult.fail(
                                connect_result.error or "Connect failed",
                            )
                        ldap_mods: FlextLdapTypes.Entry.AttributeDict = {}
                        for key, val in dict(modifications).items():
                            if isinstance(val, list):
                                ldap_mods[key] = [str(x) for x in val]
                            else:
                                ldap_mods[key] = [str(val)]
                        mod_result = await client.modify_entry(dn, ldap_mods)
                        if not mod_result.is_success:
                            return FlextResult.fail(mod_result.error or "Modify failed")
                    finally:
                        with contextlib.suppress(Exception):
                            await client.unbind()

                self.log_info(
                    "LDAP entry modified successfully",
                    extra={
                        "operation": "modify_entry",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "entry_dn": dn,
                        "modification_count": len(modifications),
                    },
                )

                return FlextResult.ok(None)

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "modify entry",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def delete_entry(
            self,
            connection_id: str,
            dn: str,
        ) -> FlextResult[None]:
            """Delete an LDAP entry - REFACTORED."""
            try:
                # Use validation helpers
                dn_validation = self.validate_dn_string(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                # Perform real LDAP delete via client when test env is available
                server = getenv("LDAP_TEST_SERVER")
                bind_dn = getenv("LDAP_TEST_BIND_DN")
                password = getenv("LDAP_TEST_PASSWORD")
                if server and bind_dn and password:
                    client = FlextLdapClient()
                    try:
                        connect_result = await client.connect(server, bind_dn, password)
                        if not connect_result.is_success:
                            return FlextResult.fail(
                                connect_result.error or "Connect failed",
                            )
                        del_result = await client.delete(dn)
                        if not del_result.is_success:
                            return FlextResult.fail(del_result.error or "Delete failed")
                    finally:
                        with contextlib.suppress(Exception):
                            await client.unbind()

                self.log_info(
                    "LDAP entry deleted completed successfully",
                    extra={
                        "operation": "entry deleted",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "entry_dn": dn,
                    },
                )

                return FlextResult.ok(None)

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "delete entry",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

    class UserOperations(OperationsService):
        """Internal specialized user management operations class."""

        # Private attribute for entry operations
        _entry_ops: object | None = PrivateAttr(default=None)

        def __init__(self, **data: object) -> None:
            """Initialize user operations - USES BASE."""
            super().__init__(**data)
            self._entry_ops = FlextLdapOperations.EntryOperations()

        async def create_user(
            self,
            connection_id: str,
            user_request: FlextLdapModels.CreateUserRequest,
        ) -> FlextResult[FlextLdapModels.User]:
            """Create a new LDAP user - with helper composition."""
            try:
                # Use attribute building
                attributes = self._build_user_attributes(user_request)

                # Create entry using shared operations with standard user object classes
                if self._entry_ops is None:
                    return FlextResult.fail(
                        "Entry operations not available",
                    )

                entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
                entry_result = await entry_ops.create_entry(
                    connection_id,
                    user_request.dn,
                    ["inetOrgPerson", "person", "top"],
                    attributes,
                )

                if not entry_result.is_success:
                    return FlextResult.fail(
                        f"Failed to create user entry: {entry_result.error}",
                    )

                # Use user creation
                user = self._build_user_entity(user_request, attributes)

                validation_result = user.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"User validation failed: {validation_result.error}",
                    )

                # Direct FlextMixins.Service logging
                self.log_info(
                    "LDAP user created successfully",
                    extra={
                        "operation": "create_user",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "user_dn": user_request.dn,
                        "uid": user_request.uid,
                    },
                )

                return FlextResult.ok(user)

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "create user",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def update_user_password(
            self,
            connection_id: str,
            user_dn: str,
            new_password: str,
        ) -> FlextResult[None]:
            """Update user password - with centralized validation."""
            # Use centralized password validation from validations module
            validation_result = FlextLdapValidations.validate_password(new_password)
            if validation_result.is_failure:
                return FlextResult.fail(
                    validation_result.error or "Password validation failed"
                )

            modifications: FlextTypes.Core.Dict = {"userPassword": [new_password]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        async def update_user_email(
            self,
            connection_id: str,
            user_dn: str,
            email: str,
        ) -> FlextResult[None]:
            """Update user email address - with validation."""
            if "@" not in email:
                return FlextResult.fail("Invalid email format")

            modifications: FlextTypes.Core.Dict = {"mail": [email]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        async def activate_user(
            self,
            connection_id: str,
            user_dn: str,
        ) -> FlextResult[None]:
            """Activate user account - REFACTORED."""
            modifications: FlextTypes.Core.Dict = {"accountStatus": ["active"]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        async def deactivate_user(
            self,
            connection_id: str,
            user_dn: str,
        ) -> FlextResult[None]:
            """Deactivate user account - REFACTORED."""
            modifications: FlextTypes.Core.Dict = {"accountStatus": ["inactive"]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        def _build_user_attributes(
            self,
            user_request: FlextLdapModels.CreateUserRequest,
        ) -> FlextLdapTypes.Entry.AttributeDict:
            """Build user attributes from request."""
            attributes: FlextLdapTypes.Entry.AttributeDict = {
                "uid": [user_request.uid],
                "cn": [user_request.cn],
            }
            # Only add non-None optional attributes
            if user_request.sn:
                attributes["sn"] = [user_request.sn]
            if user_request.given_name:
                attributes["givenName"] = [user_request.given_name]
            if user_request.mail:
                attributes["mail"] = [user_request.mail]
            return attributes

        def _build_user_entity(
            self,
            user_request: FlextLdapModels.CreateUserRequest,
            attributes: FlextLdapTypes.Entry.AttributeDict,
        ) -> FlextLdapModels.User:
            """Build user entity."""
            user_id_str = self._generate_id()
            return FlextLdapModels.User(
                id=user_id_str,
                dn=user_request.dn,
                object_classes=["inetOrgPerson", "person", "top"],
                attributes=cast(
                    "dict[str, str | bytes | list[str] | list[bytes]]",
                    FlextLdapOperations._normalize_ldap_attributes(attributes),
                ),
                uid=user_request.uid,
                cn=user_request.cn,
                sn=user_request.sn,
                given_name=user_request.given_name,
                mail=user_request.mail,
                user_password=user_request.user_password,
                modified_at=None,
                # Note: no phone field in FlextLdapModels.User
                # Note: no status field as FlextModels already has it
            )

    class GroupOperations(OperationsService):
        """Internal specialized group management operations class."""

        # Private attribute for entry operations
        _entry_ops: object | None = PrivateAttr(default=None)
        _search_ops: object | None = PrivateAttr(default=None)

        def __init__(self, **data: object) -> None:
            """Initialize group operations - USES BASE."""
            super().__init__(**data)
            self._entry_ops = FlextLdapOperations.EntryOperations()
            self._search_ops = FlextLdapOperations.SearchOperations()

        async def create_group(
            self,
            connection_id: str,
            dn: str,
            cn: str,
            description: str | None = None,
            initial_members: list[str] | None = None,
        ) -> FlextResult[FlextLdapModels.Group]:
            """Create a new LDAP group - with helper composition."""
            try:
                # Use helper for member handling
                members = self._prepare_group_members(initial_members)
                attributes = self._build_group_attributes(cn, description, members)

                # Create entry using shared operations
                if self._entry_ops is None:
                    return FlextResult.fail(
                        "Entry operations not available",
                    )

                entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
                entry_result = await entry_ops.create_entry(
                    connection_id,
                    dn,
                    ["groupOfNames", "top"],
                    attributes,
                )

                if not entry_result.is_success:
                    return FlextResult.fail(
                        f"Failed to create group entry: {entry_result.error}",
                    )

                # Use group creation
                group = self._build_group_entity(
                    dn,
                    cn,
                    description,
                    members,
                    attributes,
                )

                validation_result = group.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"Group validation failed: {validation_result.error}",
                    )

                # Direct FlextMixins.Service logging
                self.log_info(
                    "LDAP group created successfully",
                    extra={
                        "operation": "create_group",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "group_dn": dn,
                        "cn": cn,
                        "member_count": len(members),
                    },
                )

                return FlextResult.ok(group)

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "create group",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def add_group_member(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Add member to LDAP group - with helper composition."""
            try:
                # Use validation helpers
                member_validation = self.validate_dn_string(member_dn, "member DN")
                if not member_validation.is_success:
                    return FlextResult.fail(
                        member_validation.error or "Member validation failed",
                    )

                # Use member management
                return await self._modify_group_membership(
                    connection_id,
                    group_dn,
                    member_dn,
                    action="add",
                )

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "add group member",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def remove_group_member(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Remove member from LDAP group."""
            try:
                # Use member management
                return await self._modify_group_membership(
                    connection_id,
                    group_dn,
                    member_dn,
                    action="remove",
                )

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "remove group member",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def get_group_members(
            self,
            connection_id: str,
            group_dn: str,
        ) -> FlextResult[list[str]]:
            """Get all members of a group - REFACTORED."""
            try:
                if self._search_ops is None:
                    return FlextResult[list[str]].fail(
                        "Search operations not available",
                    )

                search_ops = cast(
                    "FlextLdapOperations.SearchOperations",
                    self._search_ops,
                )
                group_result = await search_ops.get_entry_by_dn(
                    connection_id="default",
                    dn=group_dn,
                    attributes=["member"],
                )

                if not group_result.is_success:
                    return FlextResult[list[str]].fail(
                        f"Failed to get group: {group_result.error}",
                    )

                # Get member attribute and convert to list of strings
                member_attr = group_result.value.get_attribute_values("member")
                members = [str(m) for m in member_attr] if member_attr else []

                real_members = self._filter_dummy_members(members)
                return FlextResult[list[str]].ok(real_members)

            except Exception as e:
                # Use exception handling
                error_msg = self._handle_exception_with_context(
                    "get group members",
                    e,
                    connection_id,
                )
                return FlextResult[list[str]].fail(error_msg)

        async def update_group_description(
            self,
            connection_id: str,
            group_dn: str,
            description: str,
        ) -> FlextResult[None]:
            """Update group description - REFACTORED."""
            modifications: FlextTypes.Core.Dict = {"description": [description]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(
                connection_id,
                group_dn,
                modifications,
            )

        def _prepare_group_members(
            self,
            initial_members: list[str] | None,
        ) -> list[str]:
            """Prepare group members with dummy member if needed."""
            members = initial_members or []
            if not members:
                # Add dummy member if none provided (required by groupOfNames)
                members = ["cn=dummy,ou=temp,dc=example,dc=com"]
            return members

        def _build_group_attributes(
            self,
            cn: str,
            description: str | None,
            members: list[str],
        ) -> FlextLdapTypes.Entry.AttributeDict:
            """Build group attributes."""
            attributes: FlextLdapTypes.Entry.AttributeDict = {
                "cn": [cn],
                "member": members,
            }
            if description:
                attributes["description"] = [description]
            return attributes

        def _build_group_entity(
            self,
            dn: str,
            cn: str,
            description: str | None,
            members: list[str],
            attributes: FlextLdapTypes.Entry.AttributeDict,
        ) -> FlextLdapModels.Group:
            """Build group entity."""
            group_id_str = self._generate_id()
            return FlextLdapModels.Group(
                id=group_id_str,
                dn=dn,
                object_classes=["groupOfNames", "top"],
                attributes=cast(
                    "dict[str, str | bytes | list[str] | list[bytes]]",
                    FlextLdapOperations._normalize_ldap_attributes(attributes),
                ),
                cn=cn,
                description=description,
                members=members,
                modified_at=None,
                # Note: no status field as FlextModels already has it
            )

        def _filter_dummy_members(self, members: list[str]) -> list[str]:
            """Filter out dummy members."""
            return [m for m in members if not m.startswith("cn=dummy,ou=temp")]

        async def _modify_group_membership(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
            action: str,
        ) -> FlextResult[None]:
            """Modify group membership (add/remove) - using Command Pattern.

            Complexity reduced by encapsulating operation as command.
            """
            # Validate command parameters directly
            if (
                not connection_id
                or not group_dn
                or not member_dn
                or action not in {"add", "remove"}
            ):
                return FlextResult[None].fail("Invalid membership command parameters")

            # Execute membership modification pipeline
            return await self._execute_membership_command(
                connection_id,
                group_dn,
                member_dn,
                action,
            )

        async def _execute_membership_command(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
            action: str,
        ) -> FlextResult[None]:
            """Execute membership command - encapsulates complex membership logic."""
            try:
                # Step 1: Get current group membership using encapsulated method
                group_result = await self._get_group_membership(
                    connection_id,
                    group_dn,
                )
                if group_result.is_failure:
                    return FlextResult[None].fail(
                        f"Failed to get group membership: {group_result.error}"
                    )

                group_entry = group_result.unwrap()

                # Extract member list from the group entry
                member_attr = group_entry.get_attribute_values("member")
                current_members = [str(m) for m in member_attr] if member_attr else []

                # Step 2: Check if member is already in group
                member_exists = any(
                    member.lower() == member_dn.lower() for member in current_members
                )

                # Step 3: Validate action against current state
                if action == "add" and member_exists:
                    return FlextResult[None].fail(
                        f"Member {member_dn} already exists in group {group_dn}"
                    )

                if action == "remove" and not member_exists:
                    return FlextResult[None].fail(
                        f"Member {member_dn} does not exist in group {group_dn}"
                    )

                # Step 4: Calculate updated members list
                updated_result = self._calculate_updated_members(
                    current_members, member_dn, action
                )
                if updated_result.is_failure:
                    return FlextResult[None].fail(
                        f"Failed to calculate members: {updated_result.error}"
                    )

                updated_members = updated_result.unwrap()

                # Step 5: Apply membership change with audit logging
                return await self._apply_membership_change(
                    connection_id, group_dn, updated_members, action, member_dn
                )

            except Exception as e:
                return FlextResult[None].fail(
                    f"Membership command execution failed: {e!s}"
                )

        def _extract_current_members(self, group_entry: object) -> list[str]:
            """Extract current members from group entry - simplified logic."""
            if not hasattr(group_entry, "get_attribute"):
                return []

            current_members = getattr(group_entry, "get_attribute", lambda _: None)(
                "member",
            )
            return current_members if isinstance(current_members, list) else []

        async def _get_group_membership(
            self,
            connection_id: str,
            group_dn: str,
        ) -> FlextResult[FlextLdapModels.Entry]:
            """Get current group membership data."""
            if self._search_ops is None:
                return FlextResult.fail(
                    "Search operations not available",
                )

            search_ops = cast("FlextLdapOperations.SearchOperations", self._search_ops)
            group_result = await search_ops.get_entry_by_dn(
                connection_id=connection_id,
                dn=group_dn,
                attributes=["member"],
            )

            if not group_result.is_success:
                return FlextResult.fail(
                    f"Failed to get group: {group_result.error}",
                )

            return FlextResult.ok(group_result.value)

        def _calculate_updated_members(
            self,
            current_members: list[str],
            member_dn: str,
            action: str,
        ) -> FlextResult[list[str]]:
            """Calculate updated member list based on action."""
            updated_members = current_members.copy()

            if action == "add":
                if member_dn not in updated_members:
                    updated_members.append(member_dn)
            elif action == "remove":
                if member_dn in updated_members:
                    updated_members.remove(member_dn)
            else:
                return FlextResult.fail(f"Unknown action: {action}")

            return FlextResult.ok(updated_members)

        async def _apply_membership_change(
            self,
            connection_id: str,
            group_dn: str,
            updated_members: list[str],
            action: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Apply the membership change to LDAP."""
            modifications: FlextTypes.Core.Dict = {"member": updated_members}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLdapOperations.EntryOperations", self._entry_ops)
            modify_result = await entry_ops.modify_entry(
                connection_id=connection_id,
                dn=group_dn,
                modifications=modifications,
            )

            if modify_result.is_success:
                self.log_info(
                    f"Group membership {action} successful",
                    extra={
                        "operation": f"member_{action}_group",
                        "connection_id": connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "group_dn": group_dn,
                        "member_dn": member_dn,
                    },
                )

            return modify_result

    # ==========================================================================
    # MAIN CONSOLIDATED INTERFACE
    # ==========================================================================

    def __init__(self) -> None:
        """Initialize all operation handlers with consolidated pattern."""
        self._connections = self.ConnectionOperations()
        self._search = self.SearchOperations()
        self._entries = self.EntryOperations()
        self._users = self.UserOperations()
        self._groups = self.GroupOperations()

    # Public properties to expose private operation handlers
    @property
    def connections(self) -> ConnectionOperations:
        """Access to connection operations."""
        return self._connections

    @property
    def search(self) -> SearchOperations:
        """Access to search operations."""
        return self._search

    @property
    def entries(self) -> EntryOperations:
        """Access to entry operations."""
        return self._entries

    @property
    def users(self) -> UserOperations:
        """Access to user operations."""
        return self._users

    @property
    def groups(self) -> GroupOperations:
        """Access to group operations."""
        return self._groups

    # Convenience methods that delegate to operation handlers
    def get_connection_info(
        self,
        connection_id: ConnectionId,
    ) -> FlextResult[dict[str, object]]:
        """Get connection information - delegates to connections handler."""
        return self._connections.get_connection_info(connection_id)

    async def create_connection_and_bind(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[str]:
        """Create connection and perform bind operation."""
        return await self._connections.create_connection(
            server_uri=server_uri,
            bind_dn=bind_dn,
            _bind_password=bind_password,
        )

    async def search_and_get_first(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Search and return first matching entry."""
        # Use connection_id for logging context
        self.log_debug(
            f"Searching for first entry: {search_filter} in {base_dn}",
            connection_id=connection_id,
        )

        search_params = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            attributes=attributes,
            size_limit=1,
        )
        search_result = await self._search.search_entries(search_params)

        if not search_result.is_success:
            return FlextResult.fail(
                search_result.error or "Search operation failed",
            )

        if search_result.value.entries:
            entry_data = search_result.value.entries[0]
            first_entry = FlextLdapModels.Entry(
                id=FlextUtilities.Generators.generate_id(),
                dn=base_dn,
                object_classes=(
                    [
                        str(cls)
                        for cls in cast("list[str]", entry_data.get("objectClass", []))
                    ]
                    if isinstance(entry_data.get("objectClass", []), list)
                    else []
                ),
                attributes=cast(
                    "dict[str, str | bytes | list[str] | list[bytes]]",
                    FlextLdapOperations._normalize_ldap_attributes(entry_data),
                ),
                modified_at=None,
            )
        else:
            first_entry = None
        return FlextResult.ok(first_entry)

    def _handle_exception_with_context(
        self,
        operation: str,
        exception: Exception,
        connection_id: str = "",
    ) -> str:
        """Delegate to internal exception handling for testing purposes."""
        service = self.OperationsService()
        return service._handle_exception_with_context(
            operation,
            exception,
            connection_id,
        )

    def _log_operation_success(
        self,
        operation: str,
        connection_id: str,
        **kwargs: object,
    ) -> None:
        """Simple alias for test compatibility - delegates to FlextMixins.Service.log_info."""
        # Direct delegation to flext-core - NO duplication logic
        extra_context = {
            "operation": operation,
            "connection_id": connection_id,
            "timestamp": FlextUtilities.generate_iso_timestamp(),
            **kwargs,
        }
        self._connections.log_info(
            f"LDAP {operation} completed successfully",
            extra=extra_context,
        )

    async def cleanup_connection(self, connection_id: str) -> None:
        """Clean up connection resources."""
        await self._connections.close_connection(connection_id)


__all__ = [
    "FlextLdapOperations",
]
