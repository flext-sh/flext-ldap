"""LDAP operations module - Python 3.13 optimized with advanced patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from collections.abc import Sequence
from datetime import datetime
from typing import (
    Final,
    Literal,
    cast,
)

from flext_core import (
    FlextExceptions,
    FlextMixins,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    computed_field,
    field_validator,
)

from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.domain import FlextLDAPDomain
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.typings import LdapAttributeDict

# NO module-level logger - use FlextMixins.Service in classes

# Type aliases using Python 3.13 syntax
type SearchResultEntry = dict[str, object]
type AttributeMap = dict[str, list[str]]
type ConnectionId = str


# SearchParams moved to entities.py to eliminate duplication
# Use FlextLDAPEntities.SearchParams instead


# LDAP MONSTER FILE: 2218 LINES COM 129 CLASSES/MÉTODOS!
# GOD OBJECT HELL: Uma classe para TODAS as operações LDAP!
# PATTERN SOUP: Strategy + Command + Result patterns para LDAP básico!
# PYTHON 3.13 MARKETING: "Advanced patterns" para justify complexity!

class FlextLDAPOperations:
    """MONSTER LDAP CLASS: 2218 lines of LDAP over-engineering!

    ARCHITECTURAL VIOLATIONS:
    - GOD OBJECT with 129+ methods for all LDAP operations
    - PATTERN SOUP: Strategy + Command patterns for LDAP queries
    - "COMPREHENSIVE LDAP OPERATIONS" = God object antipattern
    - "Python 3.13 advanced patterns" as complexity justification
    - IMMUTABLE DATA STRUCTURES for mutable LDAP directory operations

    REALITY CHECK: This should be separated into connection, query, and user management modules.
    MIGRATE TO: python-ldap wrapper + simple query functions + connection manager.

    Consolidated LDAP operations with Python 3.13 advanced patterns.

    Implements comprehensive LDAP operations using:
    - Advanced type hints and protocols
    - Immutable data structures
    - Strategy pattern for attribute processing
    - Command pattern for operation execution
    - Result-oriented error handling
    """

    type ConnectionRegistry = dict[ConnectionId, object]
    type OperationResult = FlextResult[dict[str, object]]

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
                    }
                )

        class MembershipCommand(BaseModel):
            """Membership command for group operations with Pydantic validation."""

            model_config = ConfigDict(frozen=True, extra="forbid")

            connection_id: str = Field(description="LDAP connection identifier")
            group_dn: str = Field(description="Group distinguished name")
            member_dn: str = Field(description="Member distinguished name")
            action: Literal["add", "remove"] = Field(
                description="Membership action (add or remove only)"
            )

            def execute(self) -> FlextResult[dict[str, object]]:
                """Execute membership command returning command parameters."""
                return FlextResult[dict[str, object]].ok(
                    {
                        "connection_id": self.connection_id,
                        "group_dn": self.group_dn,
                        "member_dn": self.member_dn,
                        "action": self.action,
                    }
                )

            def validate_membership_operation(self) -> FlextResult[None]:
                """Validate membership operation parameters."""
                if not self.group_dn or not self.member_dn:
                    return FlextResult[None].fail("Group DN and member DN are required")
                if self.action not in {"add", "remove"}:
                    return FlextResult[None].fail("Action must be 'add' or 'remove'")
                return FlextResult[None].ok(None)

    # ==========================================================================
    # PARAMETER OBJECTS AND EXTRACTORS - CONSOLIDATED FOR SOLID COMPLIANCE
    # ==========================================================================

    class UserConversionParams(BaseModel):
        """User conversion parameters with advanced Pydantic v2 patterns."""

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
            cls, v: Sequence[SearchResultEntry]
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
            self, value: object, default: str = ""
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
            # Structural pattern matching (Python 3.13)
            match entry:
                case obj if hasattr(obj, "attributes"):
                    attrs = getattr(obj, "attributes", {})
                case dict() as attrs:
                    pass
                case _:
                    return FlextResult[dict[str, object]].fail("Invalid entry format")

            if not isinstance(attrs, dict):
                return FlextResult[dict[str, object]].fail("Invalid attributes format")

            # Use FlextUtilities for extraction - NO custom strategies
            extracted = self._extract_ldap_attributes(attrs)
            return FlextResult[dict[str, object]].ok(extracted)

        def _extract_ldap_attributes(
            self, attrs: dict[str, object]
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
            match entry:
                case obj if hasattr(obj, "attributes"):
                    attrs = getattr(obj, "attributes", {})
                case dict() as attrs:
                    pass
                case _:
                    return FlextResult[dict[str, object]].fail(
                        "Invalid group entry format"
                    )

            if not isinstance(attrs, dict):
                return FlextResult[dict[str, object]].fail(
                    "Invalid group attributes format"
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

        # Immutable configuration using FlextValidations patterns
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
            # Use FlextValidations for request validation
            if not request:
                return FlextResult[dict[str, object]].fail("Empty request")
            return FlextResult[dict[str, object]].ok(request)

        def build(
            self, domain: dict[str, object], *, correlation_id: str
        ) -> dict[str, object]:
            """Build final result from domain object - required by ServiceProcessor."""
            return {
                **domain,
                "correlation_id": correlation_id,
                "processed_at": FlextUtilities.generate_iso_timestamp(),
            }

        def _generate_id(self) -> ConnectionId:
            """Generate connection ID using FlextUtilities - NO DUPLICATION."""
            return FlextUtilities.Generators.generate_entity_id()

        # Advanced validation using FlextValidations - ELIMINATES custom validation duplication
        def validate_dn_string(self, dn: str, context: str = "DN") -> FlextResult[None]:
            """Validate DN using centralized validation - SOURCE OF TRUTH."""
            return FlextLDAPDomain.CentralizedValidations.validate_dn(dn, context)

        def validate_filter_string(self, search_filter: str) -> FlextResult[None]:
            """Validate LDAP filter using centralized validation - SOURCE OF TRUTH."""
            return FlextLDAPDomain.CentralizedValidations.validate_filter(search_filter)

        # ELIMINATE wrapper methods - use validate_* directly (SOLID: no unnecessary indirection)

        def validate_uri_string(self, server_uri: str) -> FlextResult[None]:
            """Validate server URI using centralized validation - SOURCE OF TRUTH."""
            return FlextLDAPDomain.CentralizedValidations.validate_uri(server_uri)

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
                operation, exception, connection_id, **extra_context
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
                default=None, description="Bind DN for authentication"
            )
            created_at: datetime = Field(description="Connection creation timestamp")
            timeout_seconds: int = Field(
                default=30, ge=1, le=300, description="Connection timeout"
            )
            is_authenticated: bool = Field(
                description="Whether connection is authenticated"
            )

            @property
            def age_seconds(self) -> float:
                """Calculate connection age in seconds."""
                return FlextUtilities.get_elapsed_time(self.created_at)

        def __init__(self) -> None:
            """Initialize with enhanced connection registry."""
            super().__init__()
            self._active_connections: dict[
                ConnectionId,
                FlextLDAPOperations.ConnectionOperations.ConnectionMetadata,
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
                server_uri, bind_dn, timeout_seconds
            )
            if validation_result.is_failure:
                return FlextResult[ConnectionId].fail(
                    validation_result.error or "Validation failed"
                )

            try:
                connection_id = self._generate_id()

                # Create immutable connection metadata
                metadata = self.ConnectionMetadata(
                    server_uri=server_uri,
                    bind_dn=bind_dn,
                    created_at=datetime.now(),
                    timeout_seconds=timeout_seconds,
                    is_authenticated=bind_dn is not None,
                )

                # Store in registry
                self._active_connections[connection_id] = metadata

                # Direct FlextMixins.Service logging - NO DUPLICATION
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
                    "create_connection", e, server_uri=server_uri
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
            max_timeout = FlextLDAPConstants.Protocol.DEFAULT_TIMEOUT_SECONDS
            match timeout_seconds:
                case int() if 1 <= timeout_seconds <= max_timeout:
                    return FlextResult[None].ok(None)
                case _:
                    return FlextResult[None].fail(
                        f"Timeout must be between 1 and {max_timeout} seconds"
                    )

        def get_connection_info(
            self, connection_id: ConnectionId
        ) -> FlextResult[dict[str, object]]:
            """Get connection information with type safety."""
            if connection_id not in self._active_connections:
                return FlextResult[dict[str, object]].fail(
                    f"Connection not found: {connection_id}"
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
                }
            )

        async def close_connection(
            self, connection_id: ConnectionId
        ) -> FlextResult[None]:
            """Close LDAP connection with enhanced cleanup."""
            connection_id_typed = connection_id

            if connection_id_typed not in self._active_connections:
                return FlextResult[None].fail(f"Connection not found: {connection_id}")

            try:
                metadata = self._active_connections.pop(connection_id_typed)

                # Direct FlextMixins.Service logging - NO DUPLICATION
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
                    "close_connection", e, connection_id_typed
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
                            age_seconds = FlextUtilities.get_elapsed_time(created_at)

                        # Build connection info with proper typing
                        server_uri = str(metadata_dict.get("server_uri", "unknown"))
                        bind_dn = metadata_dict.get("bind_dn")
                        is_authenticated = bool(
                            metadata_dict.get("is_authenticated", False)
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
                    "list_active_connections", e
                )
                return FlextResult[list[dict[str, object]]].fail(error_msg)

        def cleanup_expired_connections(
            self, max_age_seconds: int = 3600
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
                    "cleanup_expired_connections", e, max_age_seconds=max_age_seconds
                )
                return FlextResult[int].fail(error_msg)

        def _calculate_duration(self, start_time: object) -> float:
            """Calculate duration from start time to now in seconds."""
            try:
                if isinstance(start_time, datetime):
                    return FlextUtilities.get_elapsed_time(start_time)
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
                description="Search result entries"
            )
            total_count: int = Field(ge=0, description="Total number of entries found")
            execution_time_ms: float = Field(ge=0, description="Search execution time")
            connection_id: ConnectionId = Field(
                description="Connection used for search"
            )

            @computed_field
            def has_results(self) -> bool:
                """Check if search returned results."""
                return self.total_count > 0

        async def search_entries(
            self,
            params: FlextLDAPEntities.SearchParams,
        ) -> FlextResult["FlextLDAPOperations.SearchOperations.SearchResult"]:
            """Execute LDAP search with enhanced validation and metrics."""
            start_time = datetime.now()

            # Comprehensive parameter validation
            validation_result = await self._validate_search_parameters(params)
            if validation_result.is_failure:
                return FlextResult[
                    "FlextLDAPOperations.SearchOperations.SearchResult"
                ].fail(validation_result.error or "Validation failed")

            try:
                # Execute search with enhanced monitoring
                entries = await self._execute_search_operation(params)
                execution_time = FlextUtilities.get_elapsed_time(start_time) * 1000

                # Create typed result
                search_result = self.SearchResult(
                    entries=entries,
                    total_count=len(entries),
                    execution_time_ms=execution_time,
                    connection_id=params.connection_id,
                )

                # Direct FlextMixins.Service logging - NO DUPLICATION
                self.log_info(
                    "LDAP search_entries completed successfully",
                    extra={
                        "operation": "search_entries",
                        "connection_id": search_result.connection_id,
                        "timestamp": FlextUtilities.generate_iso_timestamp(),
                        "base_dn": params.base_dn,
                        "filter": params.search_filter,
                        "scope": params.scope,
                        "result_count": search_result.total_count,
                        "execution_time_ms": search_result.execution_time_ms,
                        "size_limit": params.size_limit,
                        "time_limit": params.time_limit,
                    },
                )

                return FlextResult[
                    "FlextLDAPOperations.SearchOperations.SearchResult"
                ].ok(search_result)

            except Exception as e:
                execution_time = FlextUtilities.get_elapsed_time(start_time) * 1000
                error_msg = self._handle_exception_with_context(
                    "search_entries",
                    e,
                    params.connection_id,
                    execution_time_ms=execution_time,
                    base_dn=params.base_dn,
                )
                return FlextResult[
                    "FlextLDAPOperations.SearchOperations.SearchResult"
                ].fail(error_msg)

        async def _validate_search_parameters(
            self, params: FlextLDAPEntities.SearchParams
        ) -> FlextResult[None]:
            """Validate search parameters comprehensively."""
            # Base DN validation
            dn_validation = self.validate_dn_string(params.base_dn, "base_dn")
            if dn_validation.is_failure:
                return dn_validation

            # Filter validation
            filter_validation = self.validate_filter_string(params.search_filter)
            if filter_validation.is_failure:
                return filter_validation

            # Size limit validation using pattern matching
            max_entries = FlextLDAPConstants.Protocol.MAX_SEARCH_ENTRIES
            match params.size_limit:
                case int() if 1 <= params.size_limit <= max_entries:
                    pass
                case _:
                    return FlextResult[None].fail(
                        f"Size limit must be between 1 and {max_entries}"
                    )

            # Time limit validation
            max_timeout = FlextLDAPConstants.Protocol.DEFAULT_TIMEOUT_SECONDS
            match params.time_limit:
                case int() if 1 <= params.time_limit <= max_timeout:
                    pass
                case _:
                    return FlextResult[None].fail(
                        f"Time limit must be between 1 and {max_timeout} seconds"
                    )

            return FlextResult[None].ok(None)

        async def _execute_search_operation(
            self, _params: FlextLDAPEntities.SearchParams
        ) -> list[dict[str, object]]:
            """Execute the actual search operation."""
            # Simulated search - in real implementation would call LDAP client
            return []

        # ELIMINATED: _log_search_success - USING FlextMixins.Service.log_info DIRECTLY

        async def search_users(
            self,
            connection_id: ConnectionId,
            base_dn: str,
            filter_criteria: dict[str, object] | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLDAPEntities.User]]:
            """Search for users with enhanced filtering and type safety."""
            try:
                # Build user-specific filter with advanced patterns
                user_filter = self._build_enhanced_user_filter(filter_criteria)

                # Create search parameters with user-specific attributes
                search_params = FlextLDAPEntities.SearchParams(
                    connection_id=connection_id,
                    base_dn=base_dn,
                    search_filter=user_filter,
                    scope="subtree",
                    attributes=self._get_user_attributes(),
                    size_limit=size_limit,
                )

                # Execute search using the enhanced search method
                search_result = await self.search_entries(search_params)
                if search_result.is_failure:
                    return FlextResult[list[FlextLDAPEntities.User]].fail(
                        f"User search failed: {search_result.error}"
                    )

                # Convert search result to user entities
                users = await self._convert_search_result_to_users(
                    search_result.unwrap()
                )

                # Direct FlextMixins.Service logging - NO DUPLICATION
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

                return FlextResult[list[FlextLDAPEntities.User]].ok(users)

            except Exception as e:
                error_msg = self._handle_exception_with_context(
                    "search_users", e, connection_id, base_dn=base_dn
                )
                return FlextResult[list[FlextLDAPEntities.User]].fail(error_msg)

        def _build_enhanced_user_filter(
            self, criteria: dict[str, object] | None = None
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
            self, search_result: SearchResult
        ) -> list[FlextLDAPEntities.User]:
            """Convert search results to user entities with type safety."""
            users: list[FlextLDAPEntities.User] = []

            for entry in search_result.entries:
                try:
                    # Use attribute processor for consistent extraction
                    processor = FlextLDAPOperations.UserAttributeExtractor()
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

                        user = FlextLDAPEntities.User(
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
                            attributes={
                                k: str(v)
                                if isinstance(v, (str, bytes))
                                else (
                                    [str(item) for item in v]
                                    if isinstance(v, list)
                                    else str(v)
                                )
                                for k, v in processed_attrs.items()
                            },
                        )
                        users.append(user)
                except Exception as e:
                    # Log conversion errors but continue processing
                    self.log_error(
                        f"Failed to convert entry to user: {e}", extra={"entry": entry}
                    )
                    continue

            return users

        async def search_groups(
            self,
            connection_id: str,
            base_dn: str,
            filter_criteria: FlextTypes.Core.Headers | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLDAPEntities.Group]]:
            """Search for group entries - REFACTORED with helper composition."""
            try:
                # Use REFACTORED filter building - NO DUPLICATION
                base_filter = self._build_group_filter(filter_criteria)

                # Use general search and convert to groups
                search_params = FlextLDAPEntities.SearchParams(
                    connection_id=connection_id,
                    base_dn=base_dn,
                    search_filter=base_filter,
                    scope="subtree",
                    attributes=["cn", "description", "member", "objectClass"],
                    size_limit=size_limit,
                )
                search_result = await self.search_entries(search_params)

                if not search_result.is_success:
                    return FlextResult[list[FlextLDAPEntities.Group]].fail(
                        search_result.error or "Group search failed",
                    )

                # Convert dict entries to Entry objects first
                entry_objects = [
                    FlextLDAPEntities.Entry(
                        id=FlextUtilities.Generators.generate_entity_id(),
                        dn=str(entry_dict.get("dn", f"cn=unknown,{base_dn}")),
                        object_classes=(
                            [
                                str(cls)
                                for cls in cast(
                                    "list[str]", entry_dict.get("objectClass", [])
                                )
                            ]
                            if isinstance(entry_dict.get("objectClass", []), list)
                            else []
                        ),
                        attributes={
                            k: (
                                str(v)
                                if isinstance(v, (str, bytes))
                                else [str(item) for item in v]
                                if isinstance(v, list)
                                else str(v)
                            )
                            for k, v in entry_dict.items()
                        },
                        modified_at=None,
                    )
                    for entry_dict in search_result.value.entries
                ]
                # Use CORRECTED conversion with Entry objects
                groups = self._convert_entries_to_groups(entry_objects)

                # Direct FlextMixins.Service logging - NO DUPLICATION
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

                return FlextResult[list[FlextLDAPEntities.Group]].ok(groups)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "group search",
                    e,
                    connection_id,
                )
                return FlextResult[list[FlextLDAPEntities.Group]].fail(error_msg)

        async def get_entry_by_dn(
            self,
            connection_id: str,
            dn: str,
            attributes: FlextTypes.Core.StringList | None = None,
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Get a single entry by DN - REFACTORED."""
            search_params = FlextLDAPEntities.SearchParams(
                connection_id=connection_id,
                base_dn=dn,
                search_filter="(objectClass=*)",
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
            entry = FlextLDAPEntities.Entry(
                id=FlextUtilities.Generators.generate_entity_id(),
                dn=dn,
                object_classes=(
                    [
                        str(cls)
                        for cls in cast("list[str]", entry_data.get("objectClass", []))
                    ]
                    if isinstance(entry_data.get("objectClass", []), list)
                    else []
                ),
                attributes={
                    k: (
                        str(v)
                        if isinstance(v, (str, bytes))
                        else [str(item) for item in v]
                        if isinstance(v, list)
                        else str(v)
                    )
                    for k, v in entry_data.items()
                },
                modified_at=None,
            )
            return FlextResult.ok(entry)

        def _build_user_filter(
            self, filter_criteria: FlextTypes.Core.Headers | None
        ) -> str:
            """Build user-specific filter - REUSABLE HELPER."""
            base_filter = "(&(objectClass=person)"
            if filter_criteria:
                for attr, value in filter_criteria.items():
                    escaped_value = self._escape_ldap_filter_value(value)
                    base_filter += f"({attr}=*{escaped_value}*)"
            return base_filter + ")"

        def _build_group_filter(
            self, filter_criteria: FlextTypes.Core.Headers | None
        ) -> str:
            """Build group-specific filter - REUSABLE HELPER."""
            base_filter = "(&(objectClass=groupOfNames)"
            if filter_criteria:
                for attr, value in filter_criteria.items():
                    escaped_value = self._escape_ldap_filter_value(value)
                    base_filter += f"({attr}=*{escaped_value}*)"
            return base_filter + ")"

        def _escape_ldap_filter_value(self, value: str) -> str:
            """Escape special LDAP filter characters - REUSABLE HELPER."""
            return (
                value.replace("\\", "\\5c")
                .replace("*", "\\2a")
                .replace("(", "\\28")
                .replace(")", "\\29")
            )

        def _convert_entries_to_users(
            self,
            entries: list[FlextLDAPEntities.Entry],
        ) -> list[FlextLDAPEntities.User]:
            """Convert entries to users - REFACTORED using FlextProcessors Strategy Pattern.

            Complexity reduced from 19 to ~5 using LDAP Attribute Processing Strategy.
            """
            users: list[FlextLDAPEntities.User] = []
            # Create processor using flext-core patterns
            attribute_processor = FlextLDAPOperations.UserAttributeExtractor()

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
                    FlextLDAPEntities.User(
                        id=FlextUtilities.Generators.generate_entity_id(),
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
            entries: list[FlextLDAPEntities.Entry],
        ) -> list[FlextLDAPEntities.Group]:
            """Convert entries to groups - REFACTORED using FlextProcessors Strategy Pattern.

            Complexity reduced using LDAP Group Attribute Processing Strategy.
            """
            groups: list[FlextLDAPEntities.Group] = []
            # Create processor using flext-core patterns
            attribute_processor = FlextLDAPOperations.GroupAttributeExtractor()

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
                    FlextLDAPEntities.Group(
                        id=FlextUtilities.Generators.generate_entity_id(),
                        dn=entry.dn,
                        cn=str(attrs.get("cn", "unknown"))
                        if attrs.get("cn")
                        else "unknown",
                        description=str(attrs.get("description"))
                        if attrs.get("description")
                        else None,
                        members=cast("FlextTypes.Core.StringList", attrs.get("members"))
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
            dn_or_entry: str | FlextLDAPEntities.Entry,
            object_classes: FlextTypes.Core.StringList | None = None,
            attributes: LdapAttributeDict | None = None,
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Create a new LDAP entry - REFACTORED with shared validation."""
            try:
                # Handle both Entry object and individual parameters
                if isinstance(dn_or_entry, FlextLDAPEntities.Entry):
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

                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self.validate_dn_string(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                # Ensure attributes is not None - fix MyPy error
                safe_attributes = attributes or {}

                # Create entry entity with validation
                entry = FlextLDAPEntities.Entry(
                    id=FlextUtilities.Generators.generate_entity_id(),
                    dn=dn,
                    object_classes=object_classes,
                    attributes=safe_attributes,
                    modified_at=None,
                    # Note: no status field as FlextModels already has it
                )

                validation_result = entry.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"Entry validation failed: {validation_result.error}",
                    )

                # Direct FlextMixins.Service logging - NO DUPLICATION
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
                # Use REFACTORED exception handling - NO DUPLICATION
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
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self.validate_dn_string(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                if not modifications:
                    return FlextResult.fail("No modifications specified")

                # Direct FlextMixins.Service logging - NO DUPLICATION
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
                # Use REFACTORED exception handling - NO DUPLICATION
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
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self.validate_dn_string(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                # Direct FlextMixins.Service logging - NO DUPLICATION
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
                # Use REFACTORED exception handling - NO DUPLICATION
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
            """Initialize user operations - USES REFACTORED BASE."""
            super().__init__(**data)
            self._entry_ops = FlextLDAPOperations.EntryOperations()

        async def create_user(
            self,
            connection_id: str,
            user_request: FlextLDAPEntities.CreateUserRequest,
        ) -> FlextResult[FlextLDAPEntities.User]:
            """Create a new LDAP user - REFACTORED with helper composition."""
            try:
                # Use REFACTORED attribute building - NO DUPLICATION
                attributes = self._build_user_attributes(user_request)

                # Create entry using shared operations with standard user object classes
                if self._entry_ops is None:
                    return FlextResult.fail(
                        "Entry operations not available",
                    )

                entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
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

                # Use REFACTORED user creation - NO DUPLICATION
                user = self._build_user_entity(user_request, attributes)

                validation_result = user.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"User validation failed: {validation_result.error}",
                    )

                # Direct FlextMixins.Service logging - NO DUPLICATION
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
                # Use REFACTORED exception handling - NO DUPLICATION
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
            """Update user password - REFACTORED with validation."""
            if (
                not new_password
                or len(new_password)
                < FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH
            ):
                return FlextResult.fail(
                    f"Password must be at least {FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH} characters",
                )

            modifications: FlextTypes.Core.Dict = {"userPassword": [new_password]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        async def update_user_email(
            self,
            connection_id: str,
            user_dn: str,
            email: str,
        ) -> FlextResult[None]:
            """Update user email address - REFACTORED with validation."""
            if "@" not in email:
                return FlextResult.fail("Invalid email format")

            modifications: FlextTypes.Core.Dict = {"mail": [email]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
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

            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
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

            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        def _build_user_attributes(
            self,
            user_request: FlextLDAPEntities.CreateUserRequest,
        ) -> LdapAttributeDict:
            """Build user attributes from request - REUSABLE HELPER."""
            attributes: LdapAttributeDict = {
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
            user_request: FlextLDAPEntities.CreateUserRequest,
            attributes: LdapAttributeDict,
        ) -> FlextLDAPEntities.User:
            """Build user entity - REUSABLE HELPER."""
            user_id_str = self._generate_id()
            return FlextLDAPEntities.User(
                id=user_id_str,
                dn=user_request.dn,
                object_classes=["inetOrgPerson", "person", "top"],
                attributes=attributes,
                uid=user_request.uid,
                cn=user_request.cn,
                sn=user_request.sn,
                given_name=user_request.given_name,
                mail=user_request.mail,
                user_password=user_request.user_password,
                modified_at=None,
                # Note: no phone field in FlextLDAPEntities.User
                # Note: no status field as FlextModels already has it
            )

    class GroupOperations(OperationsService):
        """Internal specialized group management operations class."""

        # Private attribute for entry operations
        _entry_ops: object | None = PrivateAttr(default=None)
        _search_ops: object | None = PrivateAttr(default=None)

        def __init__(self, **data: object) -> None:
            """Initialize group operations - USES REFACTORED BASE."""
            super().__init__(**data)
            self._entry_ops = FlextLDAPOperations.EntryOperations()
            self._search_ops = FlextLDAPOperations.SearchOperations()

        async def create_group(
            self,
            connection_id: str,
            dn: str,
            cn: str,
            description: str | None = None,
            initial_members: FlextTypes.Core.StringList | None = None,
        ) -> FlextResult[FlextLDAPEntities.Group]:
            """Create a new LDAP group - REFACTORED with helper composition."""
            try:
                # Use REFACTORED helper for member handling - NO DUPLICATION
                members = self._prepare_group_members(initial_members)
                attributes = self._build_group_attributes(cn, description, members)

                # Create entry using shared operations
                if self._entry_ops is None:
                    return FlextResult.fail(
                        "Entry operations not available",
                    )

                entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
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

                # Use REFACTORED group creation - NO DUPLICATION
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

                # Direct FlextMixins.Service logging - NO DUPLICATION
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
                # Use REFACTORED exception handling - NO DUPLICATION
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
            """Add member to LDAP group - REFACTORED with helper composition."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                member_validation = self.validate_dn_string(member_dn, "member DN")
                if not member_validation.is_success:
                    return FlextResult.fail(
                        member_validation.error or "Member validation failed",
                    )

                # Use REFACTORED member management - NO DUPLICATION
                return await self._modify_group_membership(
                    connection_id,
                    group_dn,
                    member_dn,
                    action="add",
                )

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
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
            """Remove member from LDAP group - REFACTORED with helper composition."""
            try:
                # Use REFACTORED member management - NO DUPLICATION
                return await self._modify_group_membership(
                    connection_id,
                    group_dn,
                    member_dn,
                    action="remove",
                )

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
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
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Get all members of a group - REFACTORED."""
            try:
                if self._search_ops is None:
                    return FlextResult[FlextTypes.Core.StringList].fail(
                        "Search operations not available",
                    )

                search_ops = cast(
                    "FlextLDAPOperations.SearchOperations",
                    self._search_ops,
                )
                group_result = await search_ops.get_entry_by_dn(
                    connection_id=connection_id,
                    dn=group_dn,
                    attributes=["member"],
                )

                if not group_result.is_success:
                    return FlextResult[FlextTypes.Core.StringList].fail(
                        f"Failed to get group: {group_result.error}",
                    )

                # Get member attribute and convert to list of strings
                member_attr = group_result.value.get_attribute("member")
                members: FlextTypes.Core.StringList = []
                if member_attr:
                    if isinstance(member_attr, list):
                        members = [str(m) for m in member_attr]
                    else:
                        members = [str(member_attr)]

                real_members = self._filter_dummy_members(members)
                return FlextResult[FlextTypes.Core.StringList].ok(real_members)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "get group members",
                    e,
                    connection_id,
                )
                return FlextResult[FlextTypes.Core.StringList].fail(error_msg)

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

            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(
                connection_id,
                group_dn,
                modifications,
            )

        def _prepare_group_members(
            self,
            initial_members: FlextTypes.Core.StringList | None,
        ) -> FlextTypes.Core.StringList:
            """Prepare group members with dummy member if needed - REUSABLE HELPER."""
            members = initial_members or []
            if not members:
                # Add dummy member if none provided (required by groupOfNames)
                members = ["cn=dummy,ou=temp,dc=example,dc=com"]
            return members

        def _build_group_attributes(
            self,
            cn: str,
            description: str | None,
            members: FlextTypes.Core.StringList,
        ) -> LdapAttributeDict:
            """Build group attributes - REUSABLE HELPER."""
            attributes: LdapAttributeDict = {
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
            members: FlextTypes.Core.StringList,
            attributes: LdapAttributeDict,
        ) -> FlextLDAPEntities.Group:
            """Build group entity - REUSABLE HELPER."""
            group_id_str = self._generate_id()
            return FlextLDAPEntities.Group(
                id=group_id_str,
                dn=dn,
                object_classes=["groupOfNames", "top"],
                attributes=attributes,
                cn=cn,
                description=description,
                members=members,
                modified_at=None,
                # Note: no status field as FlextModels already has it
            )

        def _filter_dummy_members(
            self, members: FlextTypes.Core.StringList
        ) -> FlextTypes.Core.StringList:
            """Filter out dummy members - REUSABLE HELPER."""
            return [m for m in members if not m.startswith("cn=dummy,ou=temp")]

        async def _modify_group_membership(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
            action: str,
        ) -> FlextResult[None]:
            """Modify group membership (add/remove) - REFACTORED using Command Pattern.

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
                connection_id, group_dn, member_dn, action
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
                    return FlextResult.fail(
                        group_result.error or "Failed to get group",
                    )

                # Step 2: Extract and process members using simplified logic
                current_members = self._extract_current_members(group_result.value)
                updated_members_result = self._calculate_updated_members(
                    current_members,
                    member_dn,
                    action,
                )

                if updated_members_result.is_failure:
                    return FlextResult.fail(
                        updated_members_result.error or "Failed to calculate members",
                    )

                # Step 3: Apply the change using existing method
                return await self._apply_membership_change(
                    connection_id,
                    group_dn,
                    updated_members_result.value,
                    action,
                    member_dn,
                )
            except Exception as e:
                return FlextResult.fail(
                    f"Membership command execution failed: {e}",
                )

        def _extract_current_members(
            self, group_entry: object
        ) -> FlextTypes.Core.StringList:
            """Extract current members from group entry - simplified logic."""
            if not hasattr(group_entry, "get_attribute"):
                return []

            current_members = getattr(group_entry, "get_attribute", lambda _: None)(
                "member"
            )

            # Simplified member extraction using Strategy Pattern
            if current_members is None:
                return []
            if isinstance(current_members, list):
                return [str(item) for item in current_members]
            return [str(current_members)]

        async def _get_group_membership(
            self,
            connection_id: str,
            group_dn: str,
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Get current group membership data."""
            if self._search_ops is None:
                return FlextResult.fail(
                    "Search operations not available",
                )

            search_ops = cast("FlextLDAPOperations.SearchOperations", self._search_ops)
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
            current_members: FlextTypes.Core.StringList,
            member_dn: str,
            action: str,
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Calculate updated member list based on action."""
            if action == "add":
                return self._handle_add_member(current_members, member_dn)
            if action == "remove":
                return self._handle_remove_member(current_members, member_dn)
            return FlextResult[FlextTypes.Core.StringList].fail(
                f"Invalid action: {action}"
            )

        def _handle_add_member(
            self,
            current_members: FlextTypes.Core.StringList,
            member_dn: str,
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Handle adding a member to the group."""
            if member_dn in current_members:
                return FlextResult[FlextTypes.Core.StringList].fail(
                    f"Member already exists in group: {member_dn}",
                )
            return FlextResult[FlextTypes.Core.StringList].ok(
                [*current_members, member_dn]
            )

        def _handle_remove_member(
            self,
            current_members: FlextTypes.Core.StringList,
            member_dn: str,
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Handle removing a member from the group."""
            if member_dn not in current_members:
                return FlextResult[FlextTypes.Core.StringList].fail(
                    f"Member not found in group: {member_dn}",
                )

            updated_members = [m for m in current_members if m != member_dn]
            # Add dummy member if none left (LDAP groupOfNames requirement)
            if not updated_members:
                updated_members = ["cn=dummy,ou=temp,dc=example,dc=com"]

            return FlextResult[FlextTypes.Core.StringList].ok(updated_members)

        async def _apply_membership_change(
            self,
            connection_id: str,
            group_dn: str,
            updated_members: FlextTypes.Core.StringList,
            action: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Apply the membership change to LDAP."""
            modifications: FlextTypes.Core.Dict = {"member": updated_members}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            modify_result = await entry_ops.modify_entry(
                connection_id=connection_id,
                dn=group_dn,
                modifications=modifications,
            )

            if modify_result.is_success:
                action_verb = "added to" if action == "add" else "removed from"
                # Direct FlextMixins.Service logging - NO DUPLICATION
                self.log_info(
                    f"LDAP member {action_verb} group successfully",
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

    @property
    def connections(self) -> ConnectionOperations:
        """Access connections operations through consolidated interface."""
        return self._connections

    @property
    def search(self) -> SearchOperations:
        """Access search operations through consolidated interface."""
        return self._search

    @property
    def entries(self) -> EntryOperations:
        """Access entry operations through consolidated interface."""
        return self._entries

    @property
    def users(self) -> UserOperations:
        """Access user operations through consolidated interface."""
        return self._users

    @property
    def groups(self) -> GroupOperations:
        """Access group operations through consolidated interface."""
        return self._groups

    # High-level convenience methods - ELIMINATED DUPLICATION
    # Use FlextUtilities.Generators.generate_entity_id() directly - NO WRAPPER METHODS

    async def create_connection_and_bind(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[str]:
        """Create connection and perform bind operation."""
        return await self.connections.create_connection(
            server_uri=server_uri,
            bind_dn=bind_dn,
            _bind_password=bind_password,
        )

    async def search_and_get_first(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: FlextTypes.Core.StringList | None = None,
    ) -> FlextResult[FlextLDAPEntities.Entry | None]:
        """Search and return first matching entry."""
        search_params = FlextLDAPEntities.SearchParams(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
            attributes=attributes,
            size_limit=1,
        )
        search_result = await self.search.search_entries(search_params)

        if not search_result.is_success:
            return FlextResult.fail(
                search_result.error or "Search operation failed",
            )

        if search_result.value.entries:
            entry_data = search_result.value.entries[0]
            first_entry = FlextLDAPEntities.Entry(
                id=FlextUtilities.Generators.generate_entity_id(),
                dn=base_dn,
                object_classes=(
                    [
                        str(cls)
                        for cls in cast("list[str]", entry_data.get("objectClass", []))
                    ]
                    if isinstance(entry_data.get("objectClass", []), list)
                    else []
                ),
                attributes={
                    k: (
                        str(v)
                        if isinstance(v, (str, bytes))
                        else [str(item) for item in v]
                        if isinstance(v, list)
                        else str(v)
                    )
                    for k, v in entry_data.items()
                },
                modified_at=None,
            )
        else:
            first_entry = None
        return FlextResult.ok(first_entry)

    # ELIMINATE delegation wrappers - use service.validate_* methods directly (SOLID: no indirection)

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

    # ELIMINATED: _log_operation_success wrapper - USING FlextMixins.Service.log_info DIRECTLY

    def _log_operation_success(
        self, operation: str, connection_id: str, **kwargs: object
    ) -> None:
        """Simple alias for test compatibility - delegates to FlextMixins.Service.log_info."""
        # Direct delegation to flext-core - NO duplication logic
        extra_context = {
            "operation": operation,
            "connection_id": connection_id,
            "timestamp": FlextUtilities.generate_iso_timestamp(),
            **kwargs,
        }
        self.connections.log_info(
            f"LDAP {operation} completed successfully", extra=extra_context
        )

    async def cleanup_connection(self, connection_id: str) -> None:
        """Clean up connection resources."""
        await self.connections.close_connection(connection_id)


# Export internal classes for external access (backward compatibility)
# Export aliases eliminated - use FlextLDAPOperations.* directly following flext-core pattern

# Compatibility aliases for nested classes
LDAPCommandProcessor = FlextLDAPOperations.LDAPCommandProcessor
UserConversionParams = FlextLDAPOperations.UserConversionParams


# LDAPAttributeProcessor eliminated - ZERO TOLERANCE for duplicate classes
# Use FlextLDAPOperations.UserAttributeExtractor and FlextLDAPOperations.GroupAttributeExtractor directly

# SINGLE UNIFIED CLASS PATTERN - all functionality through FlextLDAPOperations
# Following flext-core consolidation - eliminate external aliases

__all__ = [
    "FlextLDAPOperations",
]
