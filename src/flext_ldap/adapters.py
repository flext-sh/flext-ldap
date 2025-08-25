"""LDAP Adapters - Single FlextLdapAdapters class following FLEXT patterns.

Single consolidated class with all LDAP adapter functionality including directory operations,
connection management, search services, and entry management organized as specialized
internal subclasses for complete backward compatibility.

Examples:
    Connection and directory operations:
    
        from adapters import FlextLdapAdapters
        
        # Create connection service
        connection = FlextLdapAdapters.ConnectionService(config)
        
        # Create search service  
        search = FlextLdapAdapters.SearchService(client)
        
        # Create directory adapter
        adapter = FlextLdapAdapters.DirectoryAdapter(client)

    Entry and operation management:
    
        # Entry service for CRUD operations
        entry_service = FlextLdapAdapters.EntryService(client)
        
        # Directory entry handling
        entry = FlextLdapAdapters.DirectoryEntry(dn="cn=user,dc=example,dc=com")
        
        # Operation execution
        executor = FlextLdapAdapters.OperationExecutor(client)

    Legacy compatibility:
    
        # All previous classes still work as direct imports
        from adapters import FlextLdapConnectionService, FlextLdapSearchService
        conn_service = FlextLdapConnectionService(config)

"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import cast, override
from urllib.parse import urlparse

from flext_core import (
    FlextDomainService,
    FlextModel,
    FlextResult,
    get_logger,
)
from pydantic import ConfigDict, Field, field_validator

from .clients import FlextLdapClient
from .constants import FlextLdapConstants
from .exceptions import FlextLdapExceptions
from .models import FlextLdapModels
from .typings import LdapAttributeDict, LdapSearchResult
from .utils import FlextLdapUtils

logger = get_logger(__name__)

# =============================================================================
# SINGLE FLEXT LDAP ADAPTERS CLASS - Consolidated adapter functionality
# =============================================================================


class FlextLdapAdapters:
    """Single FlextLdapAdapters class with all LDAP adapter functionality.

    Consolidates ALL LDAP adapter functionality into a single class following FLEXT patterns.
    Everything from connection services to directory adapters is available as specialized
    internal classes with full backward compatibility and enterprise-grade functionality.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP adapter functionality consolidated
        - Open/Closed: Extensible without modification through internal class inheritance
        - Liskov Substitution: All internal classes maintain consistent interfaces
        - Interface Segregation: Specialized classes for specific adapter concerns
        - Dependency Inversion: Depends on FlextDomainService and FlextModel abstractions

    Examples:
        Connection management:
        
            config = FlextLdapAdapters.ConnectionConfig(
                server="ldap://localhost:389",
                bind_dn="cn=admin,dc=example,dc=com"
            )
            connection = FlextLdapAdapters.ConnectionService(config)

        Search operations:
        
            search_service = FlextLdapAdapters.SearchService(client)
            results = await search_service.search_entries(
                base_dn="dc=example,dc=com",
                filter_str="(uid=john)"
            )

        Directory operations:
        
            adapter = FlextLdapAdapters.DirectoryAdapter(client)
            entries = await adapter.get_all_entries("ou=users,dc=example,dc=com")

    """

    # =========================================================================
    # CONFIGURATION AND MODELS - Specialized configuration classes
    # =========================================================================

    class DirectoryEntry(FlextModel):
        """Directory entry model for LDAP operations."""
        
        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
            frozen=True,
        )

        dn: str = Field(..., description="Distinguished Name", min_length=3)
        object_classes: list[str] = Field(
            default_factory=list,
            description="LDAP object classes"
        )
        attributes: LdapAttributeDict = Field(
            default_factory=dict,
            description="LDAP attributes dictionary"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format using centralized validation."""
            return FlextLdapUtils.Validation.validate_dn_field(v)

    class ConnectionConfig(FlextModel):
        """Connection configuration for LDAP operations."""
        
        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        server: str = Field(..., description="LDAP server URI", min_length=1)
        bind_dn: str | None = Field(None, description="Bind DN for authentication")
        bind_password: str | None = Field(None, description="Bind password")
        timeout: int = Field(
            default=FlextLdapConstants.Connection.DEFAULT_TIMEOUT,
            description="Connection timeout in seconds",
            gt=0,
            le=300
        )
        use_tls: bool = Field(default=False, description="Use TLS encryption")

        @field_validator("server")
        @classmethod
        def validate_server(cls, v: str) -> str:
            """Validate server URI format."""
            parsed = urlparse(v)
            if not parsed.scheme or parsed.scheme not in ["ldap", "ldaps"]:
                msg = "Server must be a valid LDAP URI (ldap:// or ldaps://)"
                raise ValueError(msg)
            return v

    # =========================================================================
    # OPERATION SERVICES - Specialized operation execution classes
    # =========================================================================

    class OperationExecutor(FlextDomainService[FlextResult[list[FlextLdapModels.Entry]]]):
        """Base operation executor for LDAP operations with async support."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize with LDAP client."""
            super().__init__()
            self._client = client

        async def execute_async_operation(
            self,
            operation_func: Callable[[], Coroutine[None, None, FlextResult[list[FlextLdapModels.Entry]]]],
            context: str = "LDAP operation"
        ) -> FlextResult[list[FlextLdapModels.Entry]]:
            """Execute async operation with proper error handling."""
            try:
                logger.debug(f"Executing {context}")
                return await operation_func()
            except Exception as e:
                error_msg = f"Failed to execute {context}: {e}"
                logger.error(error_msg)
                return FlextResult[list[FlextLdapModels.Entry]].fail(error_msg)

        @override
        async def execute(self, request: object) -> FlextResult[list[FlextLdapModels.Entry]]:
            """Execute operation based on request type."""
            return FlextResult[list[FlextLdapModels.Entry]].fail("Not implemented in base class")

    class ConnectionService(OperationExecutor):
        """Specialized connection service for LDAP server connectivity."""

        def __init__(self, config: FlextLdapAdapters.ConnectionConfig) -> None:
            """Initialize with connection configuration."""
            # Create client from config
            client = FlextLdapClient(
                server=config.server,
                timeout=config.timeout
            )
            super().__init__(client)
            self._config = config

        async def test_connection(self) -> FlextResult[None]:
            """Test LDAP server connection."""
            try:
                if self._config.bind_dn and self._config.bind_password:
                    return await self._client.bind(
                        self._config.bind_dn,
                        self._config.bind_password
                    )
                else:
                    return await self._client.connect(self._config.server)
            except Exception as e:
                error_msg = f"Connection test failed: {e}"
                logger.error(error_msg)
                return FlextResult[None].fail(error_msg)

        async def connect_and_bind(self) -> FlextResult[None]:
            """Connect to server and bind with credentials."""
            connect_result = await self._client.connect(self._config.server)
            if not connect_result.is_success:
                return connect_result

            if self._config.bind_dn and self._config.bind_password:
                return await self._client.bind(
                    self._config.bind_dn,
                    self._config.bind_password
                )
            
            return FlextResult[None].ok(None)

    class SearchService(FlextDomainService[FlextResult[list[FlextLdapModels.Entry]]]):
        """Specialized search service for LDAP search operations."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize with LDAP client."""
            super().__init__()
            self._client = client

        async def search_entries(
            self,
            base_dn: str,
            filter_str: str = "(objectClass=*)",
            scope: str = "subtree",
            attributes: list[str] | None = None
        ) -> FlextResult[list[FlextLdapModels.Entry]]:
            """Search LDAP entries with comprehensive error handling."""
            try:
                # Validate parameters
                validation_error = self._validate_search_params(base_dn, filter_str)
                if validation_error:
                    return FlextResult[list[FlextLdapModels.Entry]].fail(validation_error)

                # Perform search
                search_result = await self._client.search(
                    base_dn=base_dn,
                    search_filter=filter_str,
                    scope=scope,
                    attributes=attributes
                )

                if search_result.is_success:
                    # Convert to FlextLdapEntry objects
                    entries = self._convert_search_results_to_ldap_entries(search_result.value)
                    return FlextResult[list[FlextLdapModels.Entry]].ok(entries)
                else:
                    return FlextResult[list[FlextLdapModels.Entry]].fail(search_result.error)

            except Exception as e:
                error_msg = f"Search operation failed: {e}"
                logger.error(error_msg)
                return FlextResult[list[FlextLdapModels.Entry]].fail(error_msg)

        def _validate_search_params(self, base_dn: str, search_filter: str) -> str | None:
            """Validate search parameters."""
            if not FlextLdapUtils.Validation.validate_dn(base_dn):
                return f"Invalid base DN: {base_dn}"
            
            if not search_filter.startswith("(") or not search_filter.endswith(")"):
                return f"Invalid filter format: {search_filter}"
            
            return None

        def _convert_search_results_to_ldap_entries(
            self, 
            results: list[LdapSearchResult]
        ) -> list[FlextLdapModels.Entry]:
            """Convert search results to FlextLdapEntry objects."""
            entries: list[FlextLdapModels.Entry] = []
            
            for result in results:
                try:
                    # Extract DN from result
                    dn = result.get("dn", "")
                    if isinstance(dn, list):
                        dn = dn[0] if dn else ""
                    
                    # Convert attributes
                    attributes_dict = FlextLdapUtils.Core.safe_convert_external_dict_to_ldap_attributes(
                        {k: v for k, v in result.items() if k != "dn"}
                    )
                    
                    # Create entry
                    entry = FlextLdapModels.Entry(
                        dn=str(dn),
                        attributes=attributes_dict
                    )
                    entries.append(entry)
                    
                except Exception as e:
                    logger.warning(
                        f"Failed to convert search result to FlextLdapEntry: {e}"
                    )
                    continue
            
            return entries

        @override
        async def execute(self, request: object) -> FlextResult[list[FlextLdapModels.Entry]]:
            """Execute search operation."""
            return FlextResult[list[FlextLdapModels.Entry]].fail("Use search_entries method")

    class EntryService(OperationExecutor):
        """Specialized entry service for LDAP entry CRUD operations."""

        async def add_entry(
            self,
            dn: str,
            attributes: dict[str, object]
        ) -> FlextResult[None]:
            """Add new LDAP entry."""
            try:
                # Validate DN parameter
                validation_func = lambda: self._validate_dn_param(dn)
                validation_result = await self.execute_async_operation(
                    lambda: self._async_validation_wrapper(validation_func),
                    "DN validation"
                )
                
                if not validation_result.is_success:
                    return FlextResult[None].fail(validation_result.error)

                # Use type-safe utility to convert modifications to LdapAttributeDict
                ldap_attrs = (
                    FlextLdapUtils.Core.safe_convert_external_dict_to_ldap_attributes(
                        attributes
                    )
                )

                return await self._client.add_entry(dn, ldap_attrs)

            except Exception as e:
                error_msg = f"Failed to add entry {dn}: {e}"
                logger.error(error_msg)
                return FlextResult[None].fail(error_msg)

        async def modify_entry(
            self,
            dn: str,
            modifications: dict[str, object]
        ) -> FlextResult[None]:
            """Modify existing LDAP entry."""
            try:
                validation_func = lambda: self._validate_modify_params(dn, modifications)
                validation_result = await self.execute_async_operation(
                    lambda: self._async_validation_wrapper(validation_func),
                    "modify parameters validation"
                )
                
                if not validation_result.is_success:
                    return FlextResult[None].fail(validation_result.error)

                return await self._client.modify_entry(dn, modifications)

            except Exception as e:
                error_msg = f"Failed to modify entry {dn}: {e}"
                logger.error(error_msg)
                return FlextResult[None].fail(error_msg)

        async def delete_entry(self, dn: str) -> FlextResult[None]:
            """Delete LDAP entry."""
            try:
                validation_func = lambda: self._validate_dn_param(dn)
                validation_result = await self.execute_async_operation(
                    lambda: self._async_validation_wrapper(validation_func),
                    "DN validation"
                )
                
                if not validation_result.is_success:
                    return FlextResult[None].fail(validation_result.error)

                return await self._client.delete_entry(dn)

            except Exception as e:
                error_msg = f"Failed to delete entry {dn}: {e}"
                logger.error(error_msg)
                return FlextResult[None].fail(error_msg)

        async def _async_validation_wrapper(
            self, 
            validation_func: Callable[[], str | None]
        ) -> FlextResult[list[FlextLdapModels.Entry]]:
            """Wrapper to make validation async compatible."""
            error = validation_func()
            if error:
                return FlextResult[list[FlextLdapModels.Entry]].fail(error)
            return FlextResult[list[FlextLdapModels.Entry]].ok([])

        def _validate_modify_params(
            self, 
            dn: str, 
            modifications: dict[str, object]
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
            
            if not FlextLdapUtils.Validation.validate_dn(dn):
                return f"Invalid DN format: {dn}"
            
            return None

    # =========================================================================
    # DIRECTORY SERVICES - High-level directory operation classes
    # =========================================================================

    class DirectoryEntry:
        """Directory entry handler for LDAP entry operations."""

        def __init__(self, dn: str, attributes: dict[str, object] | None = None) -> None:
            """Initialize directory entry."""
            self.dn = dn
            self.attributes: dict[str, str | list[str]] = {}
            
            if attributes:
                # Use type-safe utility to convert attributes
                ldap_attrs = FlextLdapUtils.Core.safe_convert_external_dict_to_ldap_attributes(
                    attributes
                )
                
                # Normalize attributes format
                for key, value in ldap_attrs.items():
                    if isinstance(value, list):
                        self.attributes[key] = FlextLdapUtils.Core.safe_convert_list_to_strings(
                            cast("list[object]", value)
                        )
                    else:
                        # Single value converted to list using utility
                        str_value = FlextLdapUtils.Core.safe_convert_value_to_str(value)
                        self.attributes[key] = [str_value] if str_value else []

        def get_attribute(self, name: str) -> list[str]:
            """Get attribute values as list."""
            return self.attributes.get(name, [])

        def set_attribute(self, name: str, value: str | list[str]) -> None:
            """Set attribute value."""
            if isinstance(value, list):
                self.attributes[name] = value
            else:
                self.attributes[name] = [value]

    class DirectoryService(FlextDomainService[FlextResult[object]]):
        """High-level directory service for comprehensive LDAP operations."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize with LDAP client."""
            super().__init__()
            self._client = client

        async def get_all_entries(
            self, 
            base_dn: str,
            filter_str: str = "(objectClass=*)"
        ) -> FlextResult[list[dict[str, object]]]:
            """Get all entries from directory."""
            try:
                search_result = await self._client.search(
                    base_dn=base_dn,
                    search_filter=filter_str,
                    scope="subtree"
                )

                if search_result.is_success:
                    # Convert results to protocol format
                    protocol_entries = self._convert_entries_to_protocol(search_result.value)
                    return FlextResult[list[dict[str, object]]].ok(protocol_entries)
                else:
                    return FlextResult[list[dict[str, object]]].fail(search_result.error)

            except Exception as e:
                error_msg = f"Failed to get all entries: {e}"
                logger.error(error_msg)
                return FlextResult[list[dict[str, object]]].fail(error_msg)

        def _convert_entries_to_protocol(
            self, 
            entries: list[LdapSearchResult]
        ) -> list[dict[str, object]]:
            """Convert entries to protocol format."""
            protocol_entries: list[dict[str, object]] = []
            
            for entry in entries:
                try:
                    # Extract DN
                    dn = entry.get("dn", "")
                    if isinstance(dn, list):
                        dn = dn[0] if dn else ""
                    
                    # Get other attributes
                    entry_attrs = {k: v for k, v in entry.items() if k != "dn"}
                    
                    # Create protocol entry
                    protocol_entry = {
                        "dn": str(dn),
                        **cast(
                            "object", self._normalize_entry_attributes(entry_attrs)
                        ),
                    }
                    protocol_entries.append(protocol_entry)
                    
                except Exception as e:
                    logger.warning(f"Failed to convert entry to protocol format: {e}")
                    continue
            
            return protocol_entries

        def _normalize_entry_attributes(
            self, 
            attributes: dict[str, object]
        ) -> dict[str, object]:
            """Normalize entry attributes for protocol compatibility."""
            # Use type-safe utility to convert external dict
            ldap_attrs = (
                FlextLdapUtils.Core.safe_convert_external_dict_to_ldap_attributes(attributes)
            )
            
            # Return normalized format with explicit typing
            normalized_attrs: dict[str, object] = {}
            for k, v in ldap_attrs.items():
                if isinstance(v, list) and len(v) == 1:
                    normalized_attrs[k] = v[0]
                else:
                    normalized_attrs[k] = v
            return normalized_attrs

        @override
        async def execute(self, request: object) -> FlextResult[object]:
            """Execute directory service operation."""
            return FlextResult[object].fail("Use specific methods like get_all_entries")

    class DirectoryAdapter:
        """Main directory adapter orchestrating all LDAP operations."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize with LDAP client and create specialized services."""
            self._client = client
            self.connection = FlextLdapAdapters.ConnectionService(
                FlextLdapAdapters.ConnectionConfig(server="ldap://localhost:389")
            )
            self.search = FlextLdapAdapters.SearchService(client)
            self.entries = FlextLdapAdapters.EntryService(client)
            self.directory = FlextLdapAdapters.DirectoryService(client)

        async def get_all_entries(
            self, 
            base_dn: str,
            filter_str: str = "(objectClass=*)"
        ) -> FlextResult[list[dict[str, object]]]:
            """Get all directory entries."""
            return await self.directory.get_all_entries(base_dn, filter_str)

        async def search_entries(
            self,
            base_dn: str,
            filter_str: str = "(objectClass=*)",
            scope: str = "subtree"
        ) -> FlextResult[list[FlextLdapModels.Entry]]:
            """Search directory entries."""
            return await self.search.search_entries(base_dn, filter_str, scope)


# =============================================================================
# LEGACY COMPATIBILITY CLASSES - Backward Compatibility
# =============================================================================

# Legacy class aliases for backward compatibility
DirectoryEntry = FlextLdapAdapters.DirectoryEntry
ConnectionConfig = FlextLdapAdapters.ConnectionConfig
OperationExecutor = FlextLdapAdapters.OperationExecutor
FlextLdapConnectionService = FlextLdapAdapters.ConnectionService
FlextLdapSearchService = FlextLdapAdapters.SearchService
FlextLdapEntryService = FlextLdapAdapters.EntryService
FlextLdapDirectoryEntry = FlextLdapAdapters.DirectoryEntry
FlextLdapDirectoryService = FlextLdapAdapters.DirectoryService
FlextLdapDirectoryAdapter = FlextLdapAdapters.DirectoryAdapter


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Primary consolidated class
    "FlextLdapAdapters",
    
    # Legacy compatibility classes
    "DirectoryEntry",
    "ConnectionConfig", 
    "OperationExecutor",
    "FlextLdapConnectionService",
    "FlextLdapSearchService",
    "FlextLdapEntryService",
    "FlextLdapDirectoryEntry",
    "FlextLdapDirectoryService",
    "FlextLdapDirectoryAdapter",
]