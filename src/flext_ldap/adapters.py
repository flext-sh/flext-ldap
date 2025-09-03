"""LDAP Adapters - Single FlextLDAPAdapters class following FLEXT patterns.

Single consolidated class with all LDAP adapter functionality including
directory operations,
connection management, search services, and entry management organized as specialized
internal subclasses for complete backward compatibility.

Examples:
    Connection and directory operations:

        from adapters import FlextLDAPAdapters

        # Create connection service
        connection = FlextLDAPAdapters.ConnectionService(config)

        # Create search service
        search = FlextLDAPAdapters.SearchService(client)

        # Create directory adapter
        adapter = FlextLDAPAdapters.DirectoryAdapter(client)

    Entry and operation management:

        # Entry service for CRUD operations
        entry_service = FlextLDAPAdapters.EntryService(client)

        # Directory entry handling
        entry = FlextLDAPAdapters.DirectoryEntry(dn="cn=user,dc=example,dc=com")

        # Operation execution
        executor = FlextLDAPAdapters.OperationExecutor(client)

    Legacy compatibility:

        # All previous classes still work as direct imports
        from adapters import FlextLDAPConnectionService, FlextLDAPSearchService
        conn_service = FlextLDAPConnectionService(config)

"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import override
from urllib.parse import urlparse

from flext_core import (
    FlextDomainService,
    FlextLogger,
    FlextModels,
    FlextResult,
)
from pydantic import ConfigDict, Field, field_validator

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.typings import LdapAttributeDict, LdapSearchResult

# Utilities eliminated - using Python standard library and flext-core directly

logger = FlextLogger(__name__)

# =============================================================================
# SINGLE FLEXT LDAP ADAPTERS CLASS - Consolidated adapter functionality
# =============================================================================


class FlextLDAPAdapters:
    """Single FlextLDAPAdapters class with all LDAP adapter functionality.

    Consolidates ALL LDAP adapter functionality into a single class following FLEXT patterns.
    Everything from connection services to directory adapters is available as specialized
    internal classes with full backward compatibility and enterprise-grade functionality.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP adapter functionality consolidated
        - Open/Closed: Extensible without modification through internal class inheritance
        - Liskov Substitution: All internal classes maintain consistent interfaces
        - Interface Segregation: Specialized classes for specific adapter concerns
        - Dependency Inversion: Depends on FlextDomainService and FlextModels abstractions

    Examples:
        Connection management:

            config = FlextLDAPAdapters.ConnectionConfig(
                server="ldap://localhost:389",
                bind_dn="cn=admin,dc=example,dc=com"
            )
            connection = FlextLDAPAdapters.ConnectionService(config)

        Search operations:

            search_service = FlextLDAPAdapters.SearchService(client)
            results = await search_service.search_entries(
                base_dn="dc=example,dc=com",
                filter_str="(uid=john)"
            )

        Directory operations:

            adapter = FlextLDAPAdapters.DirectoryAdapter(client)
            entries = await adapter.get_all_entries("ou=users,dc=example,dc=com")

    """

    # =========================================================================
    # CONFIGURATION AND MODELS - Specialized configuration classes
    # =========================================================================

    class DirectoryEntry(FlextModels.Entity):
        """Directory entry model for LDAP operations."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
            frozen=True,
        )

        id: str = Field(
            default_factory=lambda: f"entry_{id(object())}",
            description="Unique identifier",
        )
        dn: str = Field(..., description="Distinguished Name", min_length=3)
        object_classes: list[str] = Field(
            default_factory=list, description="LDAP object classes"
        )
        attributes: LdapAttributeDict = Field(
            default_factory=dict, description="LDAP attributes dictionary"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format using simple validation."""
            if not v or not isinstance(v, str):
                msg = "DN must be a non-empty string"
                raise ValueError(msg)
            return v

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate directory entry business rules."""
            if not self.dn:
                return FlextResult[None].fail("DN cannot be empty")

            return FlextResult[None].ok(None)

    class ConnectionConfig(FlextModels.Value):
        """Connection configuration for LDAP operations."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        server: str = Field(..., description="LDAP server URI", min_length=1)
        bind_dn: str | None = Field(None, description="Bind DN for authentication")
        bind_password: str | None = Field(None, description="Bind password")
        timeout: int = Field(
            default=FlextLDAPConstants.Connection.DEFAULT_TIMEOUT,
            description="Connection timeout in seconds",
            gt=0,
            le=300,
        )
        use_tls: bool = Field(default=False, description="Use TLS encryption")

        @field_validator("server")
        @classmethod
        def validate_server(cls, v: str) -> str:
            """Validate server URI format - USES FLEXT-CORE."""
            # Basic URL validation
            parsed = urlparse(v)
            if not parsed.scheme or not parsed.netloc:
                msg = "Server must be a valid URL"
                raise ValueError(msg)
            if not parsed.scheme or parsed.scheme not in {"ldap", "ldaps"}:
                msg = "Server must be a valid LDAP URI (ldap:// or ldaps://)"
                raise ValueError(msg)
            return v

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate connection config business rules."""
            if not self.server:
                return FlextResult[None].fail("Server cannot be empty")
            if self.timeout <= 0:
                return FlextResult[None].fail("Timeout must be positive")
            return FlextResult[None].ok(None)

    # =========================================================================
    # OPERATION SERVICES - Specialized operation execution classes
    # =========================================================================

    class OperationExecutor(FlextDomainService[list[FlextLDAPEntities.Entry]]):
        """Base operation executor for LDAP operations with async support."""

        def __init__(self, client: FlextLDAPClient, **data: object) -> None:
            """Initialize with LDAP client."""
            super().__init__(**data)
            self._client = client

        async def execute_async_operation(
            self,
            operation_func: Callable[
                [], Coroutine[None, None, FlextResult[list[FlextLDAPEntities.Entry]]]
            ],
            context: str = "LDAP operation",
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Execute async operation with proper error handling."""
            try:
                logger.debug(f"Executing {context}")
                return await operation_func()
            except Exception as e:
                error_msg = f"Failed to execute {context}: {e}"
                logger.exception(error_msg)
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(error_msg)

        @override
        def execute(self) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Execute operation - required by FlextDomainService."""
            return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                "Not implemented in base class"
            )

    class ConnectionService(OperationExecutor):
        """Specialized connection service for LDAP server connectivity."""

        def __init__(self, config: FlextLDAPAdapters.ConnectionConfig) -> None:
            """Initialize with connection configuration."""
            # Create client - FlextLDAPClient takes no constructor arguments
            client = FlextLDAPClient()
            super().__init__(client)
            self._config = config

        async def test_connection(self) -> FlextResult[None]:
            """Test LDAP server connection."""
            try:
                if self._config.bind_dn and self._config.bind_password:
                    return await self._client.bind(
                        self._config.bind_dn, self._config.bind_password
                    )
                return await self._client.connect(
                    self._config.server,
                    self._config.bind_dn or "",
                    self._config.bind_password or "",
                )
            except Exception as e:
                error_msg = f"Connection test failed: {e}"
                logger.exception(error_msg)
                return FlextResult[None].fail(error_msg)

        async def connect_and_bind(self) -> FlextResult[None]:
            """Connect to server and bind with credentials."""
            connect_result = await self._client.connect(
                self._config.server,
                self._config.bind_dn or "",
                self._config.bind_password or "",
            )
            if not connect_result.is_success:
                return connect_result

            if self._config.bind_dn and self._config.bind_password:
                return await self._client.bind(
                    self._config.bind_dn, self._config.bind_password
                )

            return FlextResult[None].ok(None)

        async def establish_connection(
            self, config: FlextLDAPAdapters.ConnectionConfig
        ) -> FlextResult[None]:
            """Establish connection to LDAP server."""
            try:
                # Validate configuration
                validation_result = config.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult[None].fail(
                        validation_result.error or "Configuration validation failed"
                    )

                # Update config and attempt connection
                self._config = config
                return await self.connect_and_bind()
            except Exception as e:
                return FlextResult[None].fail(f"Failed to establish connection: {e}")

        async def terminate_connection(self) -> FlextResult[None]:
            """Terminate LDAP connection."""
            try:
                connected = self.is_connected()
                if not connected:
                    return FlextResult[None].fail("No active connection to terminate")

                # For now, just disconnect
                if hasattr(self._client, "_connection") and self._client._connection:
                    unbind_method = getattr(
                        self._client._connection, "unbind", lambda: None
                    )
                    unbind_method()
                    self._client._connection = None
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Failed to terminate connection: {e}")

        def is_connected(self) -> bool:
            """Check if client is connected."""
            try:
                # Use getattr to safely access the method
                is_connected_method = getattr(
                    self._client, "is_connected", lambda: False
                )
                result = is_connected_method()
                return bool(result)
            except Exception:
                return False

    class SearchService(FlextDomainService[list[FlextLDAPEntities.Entry]]):
        """Specialized search service for LDAP search operations."""

        def __init__(self, client: FlextLDAPClient, **data: object) -> None:
            """Initialize with LDAP client."""
            super().__init__(**data)
            self._client = client

        async def search_entries(
            self,
            base_dn: str,
            filter_str: str = "(objectClass=*)",
            scope: str = "subtree",
            attributes: list[str] | None = None,
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Search LDAP entries with comprehensive error handling."""
            try:
                # Validate parameters
                validation_error = self._validate_search_params(base_dn, filter_str)
                if validation_error:
                    return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                        validation_error
                    )

                # Perform search
                search_request = FlextLDAPEntities.SearchRequest(
                    base_dn=base_dn,
                    filter_str=filter_str,
                    scope=scope,
                    attributes=attributes,
                    size_limit=1000,
                    time_limit=30,
                )
                search_result = await self._client.search(search_request)

                if search_result.is_success:
                    # Convert to FlextLDAPEntities.Entry objects - SearchResponse.entries is list[LdapSearchResult]
                    entries = self._convert_search_results_to_ldap_entries(
                        search_result.value.entries
                    )
                    return FlextResult[list[FlextLDAPEntities.Entry]].ok(entries)
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                    search_result.error or "Search failed"
                )

            except Exception as e:
                error_msg = f"Search operation failed: {e}"
                logger.exception(error_msg)
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(error_msg)

        def _validate_search_params(
            self, base_dn: str, search_filter: str
        ) -> str | None:
            """Validate search parameters."""
            if not base_dn or not base_dn.strip():
                return "Base DN cannot be empty"

            if not search_filter or not search_filter.strip():
                return "Search filter cannot be empty"

            return None

        def _convert_search_results_to_ldap_entries(
            self, results: list[LdapSearchResult]
        ) -> list[FlextLDAPEntities.Entry]:
            """Convert search results to FlextLDAPEntities.Entry objects."""
            entries: list[FlextLDAPEntities.Entry] = []

            for result in results:
                try:
                    # Extract DN from result
                    dn = result.get("dn", "")
                    if isinstance(dn, list):
                        dn = dn[0] if dn else ""
                    # Ensure dn is always string for type safety
                    dn_str = str(dn) if dn else ""

                    # Convert attributes using Python standard conversion
                    result_dict = {k: v for k, v in result.items() if k != "dn"}
                    attributes_dict = {
                        k: [str(v)]
                        if not isinstance(v, list)
                        else [str(item) for item in v]
                        for k, v in result_dict.items()
                        if v is not None
                    }

                    # Create entry with properly typed attributes
                    from typing import cast

                    typed_attributes = cast("LdapAttributeDict", attributes_dict)
                    entry = FlextLDAPEntities.Entry(
                        id=f"entry_{hash(dn_str)}",
                        dn=dn_str,
                        attributes=typed_attributes,
                        object_classes=[],
                        modified_at=None,
                    )
                    entries.append(entry)

                except Exception as e:
                    logger.warning(
                        f"Failed to convert search result to FlextLDAPEntities.Entry: {e}"
                    )
                    continue

            return entries

        @override
        def execute(self) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Execute search operation - required by FlextDomainService."""
            return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                "Use search_entries method"
            )

    class EntryService(OperationExecutor):
        """Specialized entry service for LDAP entry CRUD operations."""

        def __init__(self, client: FlextLDAPClient, **data: object) -> None:
            """Initialize entry service with client."""
            super().__init__(client, **data)

        async def add_entry(
            self,
            entry_param: FlextLDAPAdapters.DirectoryEntry | str,
            attributes: dict[str, object] | None = None,
        ) -> FlextResult[None]:
            """Add new LDAP entry."""
            try:
                # Handle both DirectoryEntry and dn+attributes parameters
                if isinstance(entry_param, FlextLDAPAdapters.DirectoryEntry):
                    entry = entry_param
                    # Validate entry
                    validation_error = self._validate_entry(entry)
                    if validation_error:
                        return FlextResult[None].fail(validation_error)

                    # Use entry attributes
                    dn = entry.dn
                    # Convert to the expected type
                    entry_attributes: LdapAttributeDict = dict(entry.attributes)
                else:
                    # Legacy mode: dn as string with attributes dict
                    if attributes is None:
                        return FlextResult[None].fail(
                            "Attributes required when using DN string"
                        )

                    dn = entry_param
                    validation_error = self._validate_dn_param(dn)
                    if validation_error:
                        return FlextResult[None].fail(validation_error)

                    # Convert to the expected type
                    from typing import cast

                    legacy_attributes: LdapAttributeDict = cast(
                        "LdapAttributeDict", attributes
                    )
                    entry_attributes = legacy_attributes

                # Convert to LDAP attributes using Python standard conversion
                ldap_attrs = {
                    k: [str(v)]
                    if not isinstance(v, list)
                    else [str(item) for item in v]
                    for k, v in entry_attributes.items()
                    if v is not None
                }

                # Cast to proper type for client
                from typing import cast

                typed_ldap_attrs = cast("LdapAttributeDict", ldap_attrs)
                return await self._client.add(dn, typed_ldap_attrs)

            except Exception as e:
                error_msg = f"Failed to add entry: {e}"
                logger.exception(error_msg)
                return FlextResult[None].fail(error_msg)

        async def modify_entry(
            self, dn: str, modifications: dict[str, object]
        ) -> FlextResult[None]:
            """Modify existing LDAP entry."""
            try:

                def validation_func() -> str | None:
                    return self._validate_modify_params(dn, modifications)

                validation_result = await self.execute_async_operation(
                    lambda: self._async_validation_wrapper(validation_func),
                    "modify parameters validation",
                )

                if not validation_result.is_success:
                    return FlextResult[None].fail(
                        validation_result.error or "Validation failed"
                    )

                # Convert modifications to proper LDAP attribute format using Python standard
                ldap_modifications = {}
                for key, value in modifications.items():
                    if isinstance(value, list):
                        ldap_modifications[key] = [str(item) for item in value]
                    else:
                        ldap_modifications[key] = [str(value)]

                # Cast to proper type for client
                from typing import cast

                typed_modifications = cast("LdapAttributeDict", ldap_modifications)
                return await self._client.modify(dn, typed_modifications)

            except Exception as e:
                error_msg = f"Failed to modify entry {dn}: {e}"
                logger.exception(error_msg)
                return FlextResult[None].fail(error_msg)

        async def delete_entry(self, dn: str) -> FlextResult[None]:
            """Delete LDAP entry."""
            try:

                def validation_func() -> str | None:
                    return self._validate_dn_param(dn)

                validation_result = await self.execute_async_operation(
                    lambda: self._async_validation_wrapper(validation_func),
                    "DN validation",
                )

                if not validation_result.is_success:
                    return FlextResult[None].fail(
                        validation_result.error or "Validation failed"
                    )

                return await self._client.delete(dn)

            except Exception as e:
                error_msg = f"Failed to delete entry {dn}: {e}"
                logger.exception(error_msg)
                return FlextResult[None].fail(error_msg)

        async def _async_validation_wrapper(
            self, validation_func: Callable[[], str | None]
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Wrapper to make validation async compatible."""
            error = validation_func()
            if error:
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(error)
            return FlextResult[list[FlextLDAPEntities.Entry]].ok([])

        def _validate_modify_params(
            self, dn: str, modifications: dict[str, object]
        ) -> str | None:
            """Validate modify operation parameters."""
            dn_error = self._validate_dn_param(dn)
            if dn_error:
                return dn_error

            if not modifications:
                return "Modifications cannot be empty"

            return None

        def _validate_dn_param(self, dn: str) -> str | None:
            """Validate DN parameter."""
            if not dn or not dn.strip():
                return "DN cannot be empty"

            return None

        def _validate_entry(
            self, entry: FlextLDAPAdapters.DirectoryEntry
        ) -> str | None:
            """Validate LDAP entry for add operation."""
            # Check if entry has attributes
            if not entry.attributes:
                return "Entry must have at least one attribute"

            # Check if entry has objectClass
            object_classes = entry.attributes.get("objectClass", [])
            if not object_classes:
                return "Entry must have objectClass"

            return None

        def _perform_add_entry(self) -> None:
            """Perform add entry operation (placeholder for private method)."""

        def _perform_modify_entry(self) -> None:
            """Perform modify entry operation (placeholder for private method)."""

        def _perform_delete_entry(self) -> None:
            """Perform delete entry operation (placeholder for private method)."""

    # =========================================================================
    # DIRECTORY SERVICES - High-level directory operation classes
    # =========================================================================

    class DirectoryService(FlextDomainService[object]):
        """High-level directory service for comprehensive LDAP operations."""

        def __init__(self, client: FlextLDAPClient, **data: object) -> None:
            """Initialize with LDAP client."""
            super().__init__(**data)
            self._client = client

        async def get_all_entries(
            self, base_dn: str, filter_str: str = "(objectClass=*)"
        ) -> FlextResult[list[dict[str, object]]]:
            """Get all entries from directory."""
            try:
                search_request = FlextLDAPEntities.SearchRequest(
                    base_dn=base_dn,
                    filter_str=filter_str,
                    scope="subtree",
                    attributes=None,
                    size_limit=1000,
                    time_limit=30,
                )
                search_result = await self._client.search(search_request)

                if search_result.is_success:
                    # Convert results to protocol format - SearchResponse.entries is the list we need
                    protocol_entries = self._convert_entries_to_protocol(
                        search_result.value.entries
                    )
                    return FlextResult[list[dict[str, object]]].ok(protocol_entries)
                return FlextResult[list[dict[str, object]]].fail(
                    search_result.error or "Search failed"
                )

            except Exception as e:
                error_msg = f"Failed to get all entries: {e}"
                logger.exception(error_msg)
                return FlextResult[list[dict[str, object]]].fail(error_msg)

        def _convert_entries_to_protocol(
            self, entries: list[LdapSearchResult]
        ) -> list[dict[str, object]]:
            """Convert entries to protocol format."""
            protocol_entries: list[dict[str, object]] = []

            for entry in entries:
                try:
                    # Extract DN
                    dn = entry.get("dn", "")
                    if isinstance(dn, list):
                        dn = dn[0] if dn else ""
                    # Ensure dn is always string for type safety
                    dn_str = str(dn) if dn else ""

                    # Get other attributes
                    entry_attrs = {k: v for k, v in entry.items() if k != "dn"}

                    # Create protocol entry with type safety
                    normalized_attrs = self._normalize_entry_attributes(entry_attrs)
                    protocol_entry: dict[str, object] = {"dn": dn_str}
                    protocol_entry.update(normalized_attrs)
                    protocol_entries.append(protocol_entry)

                except Exception as e:
                    logger.warning(f"Failed to convert entry to protocol format: {e}")
                    continue

            return protocol_entries

        def _normalize_entry_attributes(
            self, attributes: dict[str, object]
        ) -> dict[str, object]:
            """Normalize entry attributes for protocol compatibility."""
            # Convert attributes using Python standard conversion
            ldap_attrs = {
                k: [str(v)] if not isinstance(v, list) else [str(item) for item in v]
                for k, v in attributes.items()
                if v is not None
            }

            # Return normalized format with explicit typing
            normalized_attrs: dict[str, object] = {}
            for k, v in ldap_attrs.items():
                if isinstance(v, list) and len(v) == 1:
                    normalized_attrs[k] = v[0]
                else:
                    normalized_attrs[k] = v
            return normalized_attrs

        async def connect(
            self, config: FlextLDAPAdapters.ConnectionConfig
        ) -> FlextResult[None]:
            """Connect to LDAP server."""
            try:
                # Use connection service for actual connection
                connection_service = FlextLDAPAdapters.ConnectionService(config)
                return await connection_service.establish_connection(config)
            except Exception as e:
                return FlextResult[None].fail(f"Failed to connect: {e}")

        async def search_users(
            self,
            search_filter: str = "(objectClass=person)",
            base_dn: str = "dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Search for users in directory."""
            try:
                search_request = FlextLDAPEntities.SearchRequest(
                    base_dn=base_dn,
                    filter_str=search_filter,
                    scope="subtree",
                    attributes=attributes,
                    size_limit=1000,
                    time_limit=30,
                )
                search_result = await self._client.search(search_request)

                if search_result.is_success:
                    protocol_entries = self._convert_entries_to_protocol(
                        search_result.value.entries
                    )
                    return FlextResult[list[dict[str, object]]].ok(protocol_entries)
                return FlextResult[list[dict[str, object]]].fail(
                    search_result.error or "User search failed"
                )
            except Exception as e:
                error_msg = f"Failed to search users: {e}"
                logger.exception(error_msg)
                return FlextResult[list[dict[str, object]]].fail(error_msg)

        @override
        def execute(self) -> FlextResult[object]:
            """Execute directory service operation - required by FlextDomainService."""
            return FlextResult[object].fail("Use specific methods like get_all_entries")

    class DirectoryAdapter:
        """Main directory adapter orchestrating all LDAP operations."""

        def __init__(self, client: FlextLDAPClient) -> None:
            """Initialize with LDAP client and create specialized services."""
            self._client = client
            self.connection = FlextLDAPAdapters.ConnectionService(
                FlextLDAPAdapters.ConnectionConfig(
                    server="ldap://localhost:389",
                    bind_dn="cn=admin,dc=example,dc=com",
                    bind_password="admin",  # noqa: S106
                )
            )
            self.search = FlextLDAPAdapters.SearchService(client)
            self.entries = FlextLDAPAdapters.EntryService(client)
            self.directory = FlextLDAPAdapters.DirectoryService(client)

        async def get_all_entries(
            self, base_dn: str, filter_str: str = "(objectClass=*)"
        ) -> FlextResult[list[dict[str, object]]]:
            """Get all directory entries."""
            # Validate base DN
            if not base_dn or not base_dn.strip():
                return FlextResult[list[dict[str, object]]].fail(
                    "Base DN cannot be empty"
                )

            return await self.directory.get_all_entries(base_dn, filter_str)

        async def search_entries(
            self,
            base_dn: str,
            filter_str: str = "(objectClass=*)",
            scope: str = "subtree",
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Search directory entries."""
            return await self.search.search_entries(base_dn, filter_str, scope)


# =============================================================================
# LEGACY COMPATIBILITY CLASSES - Backward Compatibility
# =============================================================================

# Legacy class aliases for backward compatibility
DirectoryEntry = FlextLDAPAdapters.DirectoryEntry
ConnectionConfig = FlextLDAPAdapters.ConnectionConfig
OperationExecutor = FlextLDAPAdapters.OperationExecutor
FlextLDAPConnectionService = FlextLDAPAdapters.ConnectionService
FlextLDAPSearchService = FlextLDAPAdapters.SearchService
# FlextLDAPEntities.EntryService = FlextLDAPAdapters.EntryService - removed dynamic assignment
FlextLDAPDirectoryEntry = FlextLDAPAdapters.DirectoryEntry
FlextLDAPDirectoryService = FlextLDAPAdapters.DirectoryService
FlextLDAPDirectoryAdapter = FlextLDAPAdapters.DirectoryAdapter


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Legacy compatibility classes (if they exist)
    "DirectoryEntry",
    # Primary consolidated class
    "FlextLDAPAdapters",
]
