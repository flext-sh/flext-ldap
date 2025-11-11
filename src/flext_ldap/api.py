"""Consolidated LDAP operations with FLEXT integration.

LDAP operations unified into FlextLdap main class following
single-class-per-project pattern with nested subsystems.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import types
from collections.abc import Callable
from typing import ClassVar, Self, cast, override

from flext_core import (
    FlextResult,
    FlextService,
)
from flext_ldif import FlextLdif, FlextLdifModels
from pydantic import Field, SecretStr, ValidationError

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.acl import FlextLdapAclService
from flext_ldap.services.authentication import FlextLdapAuthentication
from flext_ldap.services.clients import FlextLdapClients
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.services.servers import FlextLdapServersService

# Type aliases for handler message types and common return types
HandlerMessageType = (
    str
    | type[FlextLdapModels.SearchRequest]
    | type[FlextLdapModels.SearchResponse]
    | type[FlextLdifModels.Entry]
)

# Type aliases to eliminate cast() repetition (DRY principle)
SearchResultType = FlextLdapModels.SearchResponse | FlextLdifModels.Entry | None
OperationResultType = bool | list[bool]


class FlextLdap(FlextService[None]):
    """Consolidated LDAP operations with FLEXT integration.

    Main class providing LDAP functionality with nested subsystems for
    complex operations following single-class-per-project pattern.

    Implements Application.Handler protocol for standardized command handling
    and routing of LDAP operations.

    Features:
    - Connection management and authentication
    - Search, add, modify, delete operations
    - Server-specific operations (OpenLDAP, Oracle OID/OUD, AD)
    - ACL management and schema operations
    - Entry validation and LDIF integration
    - Handler protocol for command routing and processing

    Uses FlextResult[T] for error handling, FlextService for dependency
    injection, and FlextLogger for structured logging.
    """

    # Singleton pattern
    _instance: FlextLdap | None = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    # Pydantic field declaration (required for validate_assignment=True)
    s_mode: FlextLdapConstants.Types.QuirksMode = Field(
        default=FlextLdapConstants.Types.QuirksMode.AUTOMATIC,
        description="Server-specific LDIF quirks handling mode for entry transformation",
    )

    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize consolidated LDAP operations.

        Args:
        config: Optional LDAP configuration. If not provided, uses default instance.

        """
        super().__init__()

        # Core state
        self._config: FlextLdapConfig = (
            config if config is not None else FlextLdapConfig()
        )
        self._ldif: FlextLdif = FlextLdif.get_instance()  # Always use singleton
        self._entry_adapter: FlextLdapEntryAdapter | None = None
        # s_mode is auto-initialized by Field default above

        # Lazy-loaded subsystems
        self._client: FlextLdapClients | None = None
        self._servers: FlextLdapServersService | None = None
        self._acl: FlextLdapAclService | None = None

    @classmethod
    def get_instance(cls) -> FlextLdap:
        """Get singleton FlextLdap instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def create(cls, config: FlextLdapConfig | None = None) -> FlextLdap:
        """Create new FlextLdap instance (factory method).

        Args:
            config: Optional LDAP configuration.

        Returns:
            New FlextLdap instance.

        """
        return cls(config=config)

    @property
    def config(self) -> FlextLdapConfig:
        """Get LDAP configuration."""
        return self._config

    @property
    def ldif(self) -> FlextLdif:
        """Get FlextLdif singleton instance for deep LDIF integration."""
        return self._ldif

    def _lazy_init[T_lazy](
        self,
        attr_name: str,
        factory: Callable[[], T_lazy],
    ) -> T_lazy:
        """Advanced lazy initialization using Python 3.13 generics and type safety.

        Unified lazy initialization pattern with full type safety and generic support.
        Eliminates repetitive lazy-load properties while maintaining type safety.

        Uses type parameters (PEP 695) for advanced generic programming patterns.
        """
        # Get attribute with proper type narrowing
        attr: T_lazy | None = getattr(self, f"_{attr_name}", None)

        if attr is None:
            # Factory execution with type safety
            attr = factory()
            # Set attribute with type preservation
            setattr(self, f"_{attr_name}", attr)

        # Type narrowing ensures non-None return
        return attr

    @property
    def client(self) -> FlextLdapClients:
        """Get LDAP client instance with advanced generic lazy initialization."""
        return self._lazy_init("client", lambda: FlextLdapClients(config=self._config))

    @property
    def servers(self) -> FlextLdapServersService:
        """Get server operations instance with advanced generic lazy initialization."""
        return self._lazy_init("servers", FlextLdapServersService)

    @property
    def acl(self) -> FlextLdapAclService:
        """Get ACL operations instance with advanced generic lazy initialization."""
        return self._lazy_init("acl", FlextLdapAclService)

    def can_handle(self, message_type: HandlerMessageType) -> bool:
        """Check if FlextLdap handler can process this message type using Python 3.13 pattern matching.

        Implements Application.Handler protocol for command routing using advanced
        structural pattern matching for type checking and validation.

        Args:
            message_type: The message type to check (typically a class or string)

        Returns:
            True if handler can process this message type, False otherwise

        """
        match message_type:
            # String-based LDAP operations using guard pattern
            case str() as operation if operation.lower() in {
                FlextLdapConstants.OperationNames.SEARCH,
                FlextLdapConstants.OperationNames.ADD,
                FlextLdapConstants.OperationNames.MODIFY,
                FlextLdapConstants.OperationNames.DELETE,
                FlextLdapConstants.OperationNames.BIND,
                FlextLdapConstants.OperationNames.UNBIND,
                FlextLdapConstants.OperationNames.COMPARE,
                FlextLdapConstants.OperationNames.UPSERT,
                FlextLdapConstants.OperationNames.SCHEMA,
                FlextLdapConstants.OperationNames.ACL,
            }:
                return True

            # Specific model types
            case FlextLdapModels.SearchRequest:
                return True
            case FlextLdapModels.SearchResponse:
                return True
            case FlextLdifModels.Entry:
                return True

            # Default case for unsupported types
            case _:
                return False

    @property
    def authentication(self) -> FlextLdapAuthentication:
        """Get authentication operations instance with advanced generic lazy initialization."""
        return self._lazy_init("authentication", FlextLdapAuthentication)

    @property
    def quirks_mode(self) -> FlextLdapConstants.Types.QuirksMode:
        """Get current quirks mode."""
        return self.s_mode

    @override
    def execute(self) -> FlextResult[None]:
        """Execute main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # PUBLIC API METHODS - Unified Consolidated Interface
    # =========================================================================
    # CONSOLIDATED PUBLIC API (7 CORE METHODS WITH QUIRKS SUPPORT)
    # =========================================================================

    def connect(
        self,
        uri: str | None = None,
        bind_dn: str | None = None,
        password: SecretStr | str | None = None,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode = FlextLdapConstants.Types.QuirksMode.AUTOMATIC,
    ) -> FlextResult[bool]:
        """Connect to LDAP server with optional configuration and quirks control.

        Handles connection with all configuration options. Supports automatic
        server detection and server-specific quirks handling.

        Args:
            uri: Optional server URI (ldap://host:port or ldaps://host:port).
                 If not provided, uses configured URI.
            bind_dn: Optional bind DN for authentication.
                    If not provided, uses configured bind DN.
            password: Optional bind password.
                     If not provided, uses configured password.
            quirks_mode: Quirks handling mode:
                        - "{FlextLdapConstants.Types.QuirksMode.AUTOMATIC}": Auto-detect server, apply quirks
                        - "{FlextLdapConstants.Types.QuirksMode.SERVER}": Use explicit server type (must set in config)
                        - "{FlextLdapConstants.Types.QuirksMode.RFC}": RFC-compliant only, no extensions
                        - "{FlextLdapConstants.Types.QuirksMode.RELAXED}": Permissive mode, accept anything

        Returns:
            FlextResult[bool]: True if connection successful.

        Examples:
            # Connect with default config
            result = ldap.connect(quirks_mode=FlextLdapConstants.Types.QuirksMode.AUTOMATIC)

            # Connect with explicit credentials
            result = ldap.connect(
                uri="ldap://ldap.example.com:389",
                bind_dn="cn=admin,dc=example,dc=com",
                password=SecretStr("admin123")
            )

        """
        # Advanced parameter parsing using Python 3.13 pattern matching with guards
        # URI parameter handling with type narrowing
        if isinstance(uri, str) and uri:
            self._config.ldap_server_uri = uri

        # Credential parameters with structural validation using pattern matching
        match (bind_dn, password):
            case (str() as dn_value, str() as pwd_value) if dn_value and pwd_value:
                # Both DN and password provided as strings
                self._config.__dict__["ldap_bind_dn"] = dn_value
                self._config.__dict__["ldap_bind_password"] = SecretStr(pwd_value)

            case (str() as dn_value, SecretStr() as pwd_secret) if (
                dn_value and pwd_secret
            ):
                # Both DN and password provided (password already SecretStr)
                self._config.__dict__["ldap_bind_dn"] = dn_value
                self._config.__dict__["ldap_bind_password"] = pwd_secret

            case (str() as dn_value, None) if dn_value:
                # Only DN provided
                self._config.__dict__["ldap_bind_dn"] = dn_value

            case (None, str() as pwd_value) if pwd_value:
                # Only password provided
                self._config.__dict__["ldap_bind_password"] = SecretStr(pwd_value)

            case (None, SecretStr() as pwd_secret) if pwd_secret:
                # Only password provided (already SecretStr)
                self._config.__dict__["ldap_bind_password"] = pwd_secret

            case _:
                # No credential changes needed
                pass

        # Store quirks_mode for internal modules
        self.s_mode = quirks_mode

        # Connect using client with explicit config values
        password_value = ""  # nosec: default empty string, actual password from config.ldap_bind_password
        if self._config.ldap_bind_password is not None:
            password_value = self._config.ldap_bind_password.get_secret_value()

        # Create ConnectionRequest model for connect()
        request = FlextLdapModels.ConnectionRequest(
            server_uri=self._config.ldap_server_uri,
            bind_dn=self._config.ldap_bind_dn
            or "",  # Handle None with default empty string
            password=password_value,
            quirks_mode=quirks_mode,
        )
        result = self.client.connect(request)
        if result.is_failure:
            return FlextResult[bool].fail(f"Connection failed: {result.error}")

        return FlextResult[bool].ok(True)

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server and release resources.

        Closes the LDAP connection and releases all associated resources.
        This method is safe to call multiple times (idempotent).

        Returns:
            FlextResult[None]: Success if unbind completed successfully.

        Examples:
            # Unbind after operations
            result = ldap.unbind()
            if result.is_success:
                print("Successfully unbound from LDAP server")
            else:
                print(f"Unbind failed: {result.error}")

        """
        return self.client.unbind()

    def _normalize_search_entries(
        self, entries_result: object
    ) -> list[FlextLdifModels.Entry]:
        """Normalize search results to list of entries (helper for query).

        Reduces complexity by extracting normalization logic.
        """
        match entries_result:
            case list() as entries_list:
                return cast("list[FlextLdifModels.Entry]", entries_list)
            case object() as single_entry if single_entry:
                return [cast("FlextLdifModels.Entry", single_entry)]
            case _:
                return []

    def _create_search_response(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextLdapModels.SearchResponse:
        """Create SearchResponse from entries (helper for query).

        Reduces code duplication by centralizing SearchResponse creation.
        """
        return FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=len(entries),
            result_code=0,
            time_elapsed=0.0,
        )

    def _process_query_result(
        self,
        response: FlextLdapModels.SearchResponse,
        *,
        single: bool,
    ) -> FlextResult[SearchResultType]:
        """Process query result based on single flag (helper for query).

        Applies Railway-Oriented Programming pattern for result handling.
        """
        if single:
            # Single mode: return first entry or None
            first_entry = response.entries[0] if response.entries else None
            return cast("FlextResult[SearchResultType]", FlextResult.ok(first_entry))
        # Multi mode: return full SearchResponse
        return cast("FlextResult[SearchResultType]", FlextResult.ok(response))

    def query(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        *,
        single: bool = False,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[FlextLdapModels.SearchResponse | FlextLdifModels.Entry | None]:
        """Unified query method (search consolidation) with quirks support.

        Queries LDAP directory with support for single entry or full response.
        Respects quirks_mode for server-specific behavior.

        Refactored using helper methods to reduce complexity and code duplication.

        Args:
            base_dn: Base distinguished name for search.
            filter_str: LDAP search filter string (RFC 4515 compliant).
            attributes: Optional list of attributes to retrieve.
            single: If True, return first Entry only. If False, return SearchResponse.
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with SearchResponse or Entry | None based on single parameter.

        Examples:
            # Get all matching entries
            result = ldap.query("dc=example,dc=com", FlextLdapConstants.Filters.ALL_USERS_FILTER)

            # Get first matching entry
            result = ldap.query("dc=example,dc=com", "(uid=jdoe)", single=True)

        """
        # Railway-Oriented Programming: propagate failures early
        # Create SearchRequest model for search()
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            attributes=attributes,
            quirks_mode=quirks_mode,
        )
        result = self.client.search(search_request)
        if result.is_failure:
            return cast("FlextResult[SearchResultType]", result)

        # Use helper methods to reduce complexity (DRY principle)
        entries = self._normalize_search_entries(result.unwrap())
        response = self._create_search_response(entries)
        return self._process_query_result(response, single=single)

    # Apply Changes Helper Methods

    def _execute_batch_add(
        self,
        modifications: list[tuple[str, dict[str, str | list[str]]]],
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> list[bool]:
        """Execute batch add operations."""
        results: list[bool] = []
        for batch_dn, batch_attrs in modifications:
            result = self.client.add_entry(
                batch_dn, batch_attrs, quirks_mode=quirks_mode
            )
            results.append(result.is_success)
        return results

    def _execute_batch_modify_atomic(
        self,
        modifications: list[tuple[str, dict[str, str | list[str]]]],
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[list[bool]]:
        """Execute batch modify operations atomically."""
        temp_results = []
        for batch_dn, batch_changes in modifications:
            result = self.client.modify_entry(
                batch_dn,
                cast("FlextLdapModels.EntryChanges", batch_changes),
                quirks_mode=quirks_mode,
            )
            temp_results.append(result.is_success)

        if not all(temp_results):
            return FlextResult[list[bool]].fail(
                "Atomic batch modify failed - one or more operations failed",
            )
        return FlextResult[list[bool]].ok(temp_results)

    def _execute_batch_modify_non_atomic(
        self,
        modifications: list[tuple[str, dict[str, str | list[str]]]],
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> list[bool]:
        """Execute batch modify operations non-atomically."""
        results: list[bool] = []
        for batch_dn, batch_changes in modifications:
            result = self.client.modify_entry(
                batch_dn,
                cast("FlextLdapModels.EntryChanges", batch_changes),
                quirks_mode=quirks_mode,
            )
            results.append(result.is_success)
        return results

    def _execute_single_add(
        self,
        dn: str,
        changes: dict[str, str | list[str]],
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Execute single add operation."""
        return self.client.add_entry(dn, changes, quirks_mode=quirks_mode)

    def _execute_single_modify(
        self,
        dn: str,
        changes: dict[str, str | list[str]],
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Execute single modify operation."""
        return self.client.modify_entry(
            dn,
            cast("FlextLdapModels.EntryChanges", changes),
            quirks_mode=quirks_mode,
        )

    def _execute_batch_operations(
        self,
        operation: FlextLdapConstants.Types.ApiOperation,
        modifications: list[tuple[str, dict[str, str | list[str]]]],
        *,
        atomic: bool,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[list[bool]]:
        """Execute batch operations using Python 3.13 structural pattern matching.

        Consolidates batch operation logic using advanced pattern matching
        to eliminate conditional chains and improve type safety.
        """
        match (operation, atomic):
            case (FlextLdapConstants.OperationNames.ADD, _):
                # Add operations are always non-atomic by nature
                results = self._execute_batch_add(
                    modifications, quirks_mode=quirks_mode
                )
                return FlextResult[list[bool]].ok(results)

            case (FlextLdapConstants.OperationNames.MODIFY, True):
                # Atomic modify operations
                return self._execute_batch_modify_atomic(
                    modifications, quirks_mode=quirks_mode
                )

            case (FlextLdapConstants.OperationNames.MODIFY, False):
                # Non-atomic modify operations
                results = self._execute_batch_modify_non_atomic(
                    modifications, quirks_mode=quirks_mode
                )
                return FlextResult[list[bool]].ok(results)

            # Fallback for unsupported operations or unreachable states
            case _:
                return FlextResult[list[bool]].fail(f"Unknown operation: {operation}")

    def apply_changes(
        self,
        request: FlextLdapModels.ApplyChangesRequest,
    ) -> FlextResult[bool | list[bool]]:
        """Universal CRUD apply_changes method with quirks support (refactored from 8 parameters to 1 model).

        Consolidates add, modify, and delete operations with unified interface.
        Supports both single and batch operations with optional atomic semantics.

        Args:
            request: ApplyChangesRequest model containing operation parameters.

        Returns:
            FlextResult[bool] for single operation, FlextResult[list[bool]] for batch.

        """
        # Extract parameters from request model (DRY - single source of truth)
        changes = request.changes
        dn = request.dn
        # Cast to proper types for internal methods (type safety)
        operation = cast(
            "FlextLdapConstants.Types.ApiOperation",
            request.operation,
        )
        atomic = request.atomic
        batch = request.batch
        modifications = request.modifications
        quirks_mode = cast(
            "FlextLdapConstants.Types.QuirksMode | None",
            request.quirks_mode,
        )

        # Use structural pattern matching for operation routing
        match (operation, batch, modifications, dn):
            # Delete operation - requires DN
            case (FlextLdapConstants.OperationNames.DELETE, _, _, None):
                return FlextResult[OperationResultType].fail(
                    "DN required for delete operation"
                )
            case (FlextLdapConstants.OperationNames.DELETE, _, _, dn_value) if (
                dn_value is not None
            ):
                return cast(
                    "FlextResult[OperationResultType]",
                    self.client.delete_entry(dn_value),
                )

            # Batch operations - require modifications list
            case (op, True, mods, _) if mods:
                batch_result = self._execute_batch_operations(
                    op, mods, atomic=atomic, quirks_mode=quirks_mode
                )
                return cast("FlextResult[OperationResultType]", batch_result)

            # Single operations - require DN
            case (_, _, _, None):
                return FlextResult[OperationResultType].fail(
                    f"DN required for {operation} operation"
                )

            # Single add operation
            case (FlextLdapConstants.OperationNames.ADD, False, _, dn_value) if (
                dn_value is not None
            ):
                return cast(
                    "FlextResult[OperationResultType]",
                    self._execute_single_add(
                        dn_value, changes, quirks_mode=quirks_mode
                    ),
                )

            # Single modify operation
            case (FlextLdapConstants.OperationNames.MODIFY, False, _, dn_value) if (
                dn_value is not None
            ):
                return cast(
                    "FlextResult[OperationResultType]",
                    self._execute_single_modify(
                        dn_value, changes, quirks_mode=quirks_mode
                    ),
                )

            # Fallback for unknown operations or unreachable states
            case _:
                return FlextResult[OperationResultType].fail(
                    f"Unknown operation: {operation}"
                )

    def validate_entries(
        self,
        entries: FlextLdifModels.Entry | list[FlextLdifModels.Entry],
        *,
        server_type: str | None = None,
        mode: FlextLdapConstants.Types.ValidationMode = "all",
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Validation method with quirks support.

        Validates entries against server schema and business rules.
        Consolidates validate_entry_for_server and detect_entry_server_type.

        Args:
            entries: Entry or list of entries to validate.
            server_type: Optional explicit server type for validation.
            mode: Validation mode: "schema", "business", or "all".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with validation report including any errors or warnings.

        """
        _ = quirks_mode  # Reserved for future server-specific validation rules
        if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
            self._entry_adapter = FlextLdapEntryAdapter()

        # Normalize input
        entry_list = entries if isinstance(entries, list) else [entries]

        # Perform validation
        all_valid = True
        validation_issues: list[str] = []

        for entry in entry_list:
            if (
                mode
                in {
                    FlextLdapConstants.ValidationModeValues.SCHEMA,
                    FlextLdapConstants.ValidationModeValues.ALL,
                }
                and self._entry_adapter is not None
            ):
                # Pass LDAP entry directly - adapter handles both LDAP and LDIF entries
                result = self._entry_adapter.validate_entry_for_server(
                    entry,  # LDAP entry
                    server_type or self.servers.server_type,
                )
                if result.is_failure:
                    all_valid = False
                    validation_issues.append(
                        f"Schema validation failed for {entry.dn}: {result.error}",
                    )

            if mode in {
                FlextLdapConstants.ValidationModeValues.BUSINESS,
                FlextLdapConstants.ValidationModeValues.ALL,
            }:
                # Business rule validation can be extended
                pass

        return FlextResult[dict[str, object]].ok({
            "valid": all_valid,
            "issues": validation_issues,
            "entry_count": len(entry_list),
        })

    def convert(
        self,
        entries: FlextLdifModels.Entry | list[FlextLdifModels.Entry],
        source_server: str | None = None,
        target_server: str | None = None,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[FlextLdifModels.Entry | list[FlextLdifModels.Entry]]:
        """Entry conversion method with quirks support.

        Converts entries between server types with server-specific transformations.

        Args:
            entries: Entry or list of entries to convert.
            source_server: Source server type (auto-detect if None).
            target_server: Target server type (use current if None).
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with converted entry/entries.

        """
        _ = quirks_mode  # Reserved for future server-specific conversion rules
        if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
            self._entry_adapter = FlextLdapEntryAdapter()

        # Normalize input
        is_single = not isinstance(entries, list)
        entry_list = entries if isinstance(entries, list) else [entries]

        # Determine source server
        if not source_server:
            detect_result = self._entry_adapter.detect_entry_server_type(entry_list[0])
            if detect_result.is_failure:
                return FlextResult.fail(
                    f"Could not detect source server: {detect_result.error}",
                )
            source_server = detect_result.unwrap()

        # Determine target server
        if not target_server:
            target_server = (
                self.servers.server_type or FlextLdapConstants.Types.QuirksMode.RFC
            )

        # Convert entries
        converted_list: list[FlextLdifModels.Entry] = []
        for entry in entry_list:
            convert_result = self._entry_adapter.convert_entry_format(
                entry,
                source_server,
                target_server,
            )
            if convert_result.is_failure:
                return FlextResult.fail(
                    f"Conversion failed for {entry.dn}: {convert_result.error}",
                )
            converted_list.append(convert_result.unwrap())

        if is_single:
            return FlextResult[FlextLdifModels.Entry | list[FlextLdifModels.Entry]].ok(
                converted_list[0],
            )
        return FlextResult[FlextLdifModels.Entry | list[FlextLdifModels.Entry]].ok(
            converted_list,
        )

    def exchange(
        self,
        data: str | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        *,
        data_format: FlextLdapConstants.Types.DataFormat = "ldif",
        direction: FlextLdapConstants.Types.ExchangeDirection = "import",
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[str | list[FlextLdifModels.Entry]]:
        """Data exchange method for import/export with quirks support.

        Consolidates import_from_ldif and export_to_ldif operations.
        Refactored with Railway Pattern: 7→3 returns (SOLID/DRY compliance).

        Args:
            data: Data string for import operation.
            entries: Entries for export operation.
            data_format: Data format: "ldif", "json", or "csv".
            direction: Operation direction: "import" or "export".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with imported entries or exported data string.

        """
        # Create ExchangeRequest model - Pydantic validates data/entries by direction
        try:
            request = FlextLdapModels.ExchangeRequest(
                data=data,
                entries=entries,
                data_format=data_format,
                direction=direction,
                quirks_mode=quirks_mode,
            )
        except ValueError as e:
            return FlextResult[str | list[FlextLdifModels.Entry]].fail(str(e))

        # Railway Pattern: delegate to direction-specific handler
        if request.direction == FlextLdapConstants.ExchangeDirectionValues.IMPORT:
            return self._execute_import(request)
        return self._execute_export(request)

    def _execute_import(
        self, request: FlextLdapModels.ExchangeRequest
    ) -> FlextResult[str | list[FlextLdifModels.Entry]]:
        """Execute import operation - extracted for Railway Pattern."""
        if request.data_format != FlextLdapConstants.DataFormatValues.LDIF:
            return FlextResult[str | list[FlextLdifModels.Entry]].fail(
                f"Import format {request.data_format} not yet supported",
            )
        return cast(
            "FlextResult[str | list[FlextLdifModels.Entry]]",
            self.import_from_ldif(request.data),  # type: ignore[arg-type]
        )

    def _execute_export(
        self, request: FlextLdapModels.ExchangeRequest
    ) -> FlextResult[str | list[FlextLdifModels.Entry]]:
        """Execute export operation - extracted for Railway Pattern.

        Railway Pattern: propagate FlextResult without intermediate checks.
        """
        if request.data_format != "ldif":
            return FlextResult[str | list[FlextLdifModels.Entry]].fail(
                f"Export format {request.data_format} not yet supported",
            )
        # Railway Pattern: export_to_ldif returns FlextResult, propagate it
        return cast(
            "FlextResult[str | list[FlextLdifModels.Entry]]",
            self.export_to_ldif(request.entries),  # type: ignore[arg-type]
        )

    def info(
        self,
        *,
        detail_level: FlextLdapConstants.Types.InfoDetailLevel = "basic",
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Server information method with quirks support.

        Consolidates get_server_info, get_server_capabilities, get_acl_info, etc.

        Args:
            detail_level: Level of detail: "basic", "full", or "diagnostic".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with comprehensive server information.

        """
        _ = quirks_mode  # Reserved for future server-specific info formatting
        info_dict: dict[str, object] = {
            FlextLdapConstants.ApiDictKeys.TYPE: self.servers.server_type,
            FlextLdapConstants.ApiDictKeys.CONNECTED: self.client.is_connected,
            FlextLdapConstants.ApiDictKeys.QUIRKS_MODE: self.s_mode,
        }

        if detail_level in {
            FlextLdapConstants.InfoDetailLevelValues.FULL,
            FlextLdapConstants.InfoDetailLevelValues.DIAGNOSTIC,
        }:
            info_dict.update({
                FlextLdapConstants.ApiDictKeys.DEFAULT_PORT: self.servers.get_default_port(),
                FlextLdapConstants.ApiDictKeys.STARTTLS: self.servers.supports_start_tls(),
            })

        if detail_level == FlextLdapConstants.InfoDetailLevelValues.DIAGNOSTIC:
            caps_result = self.get_server_capabilities()
            if caps_result.is_success:
                caps = caps_result.unwrap()
                info_dict[FlextLdapConstants.ApiDictKeys.CAPABILITIES] = {
                    FlextLdapConstants.ApiDictKeys.SSL: caps.supports_ssl,
                    FlextLdapConstants.ApiDictKeys.STARTTLS: caps.supports_starttls,
                    FlextLdapConstants.ApiDictKeys.PAGED_RESULTS: caps.supports_paged_results,
                    FlextLdapConstants.CapabilityNames.SASL: caps.supports_sasl,
                    FlextLdapConstants.ApiDictKeys.MAX_PAGE_SIZE: caps.max_page_size,
                }

            acl_result = self.get_acl_info()
            if acl_result.is_success:
                acl_entry = acl_result.unwrap()
                acl_format_attr = acl_entry.attributes.get(
                    FlextLdapConstants.ApiDictKeys.ACL_FORMAT,
                )
                info_dict[FlextLdapConstants.ApiDictKeys.ACL_FORMAT] = (
                    acl_format_attr[0]
                    if acl_format_attr
                    else FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR
                )

        if detail_level == FlextLdapConstants.InfoDetailLevelValues.DIAGNOSTIC:
            info_dict["server_specific_attributes"] = (
                self.get_server_specific_attributes(self.servers.server_type)
            )

        return FlextResult[dict[str, object]].ok(info_dict)

    def get_server_info(self) -> FlextResult[FlextLdifModels.Entry]:
        """Get server information as Entry object using Entry.create()."""
        entry_result = FlextLdifModels.Entry.create(
            dn=FlextLdapConstants.SyntheticDns.SERVER_INFO,
            attributes={
                FlextLdapConstants.AclAttributes.SERVER_TYPE_ALT: [
                    self.servers.server_type,
                ],
                FlextLdapConstants.LdapDictKeys.DEFAULT_PORT: [
                    str(self.servers.get_default_port()),
                ],
                FlextLdapConstants.LdapDictKeys.SUPPORTS_START_TLS: [
                    FlextLdapConstants.BooleanStrings.TRUE
                    if self.servers.supports_start_tls()
                    else FlextLdapConstants.BooleanStrings.FALSE,
                ],
            },
        )
        if entry_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create server info entry: {entry_result.error}",
            )
        return FlextResult.ok(entry_result.unwrap())

    def get_acl_info(self) -> FlextResult[FlextLdifModels.Entry]:
        """Get ACL information as Entry object using Entry.create()."""
        entry_result = FlextLdifModels.Entry.create(
            dn=FlextLdapConstants.SyntheticDns.ACL_INFO,
            attributes={
                FlextLdapConstants.ApiDictKeys.ACL_FORMAT: [self.acl.get_acl_format()],
            },
        )
        if entry_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create ACL info entry: {entry_result.error}",
            )
        return FlextResult.ok(entry_result.unwrap())

    def get_server_specific_attributes(self, server_type: str) -> list[str]:
        """Get server-specific attributes."""
        # This would need to be implemented based on server type
        # For now, return generic attributes
        _ = server_type  # Mark as used to avoid linting warning
        return [
            FlextLdapConstants.LdapAttributeNames.DN,
            FlextLdapConstants.LdapAttributeNames.CN,
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
        ]

    def detect_entry_server_type(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[str]:
        """Detect server type from entry attributes."""
        try:
            # Use entry adapter for detection
            if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
                self._entry_adapter = FlextLdapEntryAdapter()

            return self._entry_adapter.detect_entry_server_type(entry)
        except (
            AttributeError,
            ValidationError,
        ) as e:
            return FlextResult[str].fail(f"Entry server type detection failed: {e}")

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server: str,
    ) -> FlextLdifModels.Entry:
        """Normalize entry for target server using FlextLdapEntryAdapter.

        Delegates to FlextLdapEntryAdapter for server-specific normalization.
        """
        if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
            self._entry_adapter = FlextLdapEntryAdapter()

        normalize_result = self._entry_adapter.normalize_entry_for_server(
            entry,
            target_server_type=target_server,
        )
        if normalize_result.is_failure:
            return entry
        return normalize_result.unwrap()

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[bool]:
        """Validate entry for server compatibility."""
        try:
            # Use entry adapter for validation
            if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
                self._entry_adapter = FlextLdapEntryAdapter()

            return self._entry_adapter.validate_entry_for_server(entry, server_type)
        except (
            AttributeError,
            ValidationError,
        ) as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")

    def convert_entry_between_servers(
        self,
        entry: FlextLdifModels.Entry,
        from_server: str,
        to_server: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert entry between server types."""
        try:
            # Use entry adapter for conversion
            if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
                self._entry_adapter = FlextLdapEntryAdapter()

            return self._entry_adapter.convert_entry_format(
                entry,
                from_server,
                to_server,
            )
        except (
            AttributeError,
            ValidationError,
        ) as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry conversion failed: {e}",
            )

    def export_to_ldif(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Export entries to LDIF format using FlextLdif library.

        Delegates to FlextLdif.write() to eliminate duplication and ensure
        RFC-compliant LDIF formatting.

        Args:
            entries: List of entries to export

        Returns:
            FlextResult[str] containing LDIF data or failure with error message

        """
        # Use integrated FlextLdif singleton instance
        write_result = self._ldif.write(entries)
        if write_result.is_failure:
            return FlextResult[str].fail(f"LDIF export failed: {write_result.error}")
        # FlextLdif.write() returns FlextResult[str] directly
        return FlextResult[str].ok(write_result.unwrap())

    def import_from_ldif(
        self,
        ldif_content: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Import entries from LDIF content using FlextLdif library."""
        # Use integrated FlextLdif singleton instance
        result = self._ldif.parse(ldif_content)

        if result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(result.error)

        entries = result.value if result.value is not None else []
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def get_server_capabilities(
        self,
    ) -> FlextResult[FlextLdapModels.ServerCapabilities]:
        """Get server capabilities information."""
        return FlextResult.ok(
            FlextLdapModels.ServerCapabilities(
                supports_ssl=True,
                supports_starttls=self.servers.supports_start_tls(),
                supports_paged_results=True,
                supports_vlv=False,
                supports_sasl=True,
                max_page_size=1000,
            ),
        )

    def get_detected_server_type(self) -> FlextResult[str | None]:
        """Get detected server type based on connection."""
        if not self.client.is_connected:
            return FlextResult.fail(FlextLdapConstants.ErrorStrings.NOT_CONNECTED)
        server_type = self.servers.server_type
        return FlextResult.ok(
            server_type
            if server_type != FlextLdapConstants.Defaults.SERVER_TYPE
            else None,
        )

    def get_servers_info(self) -> FlextResult[dict[str, object]]:
        """Get quirks information for the current LDAP server connection.

        Returns server-specific quirks information including special handling
        requirements, attribute mappings, and capability flags for the currently
        connected LDAP server type.

        Returns:
            FlextResult with dict containing quirks information including:
            - acl_attribute: Name of the ACL attribute for this server
            - naming_attribute: Server naming style
            - capabilities: Server-specific capabilities
            - special_filters: Server-specific LDAP filter requirements

        Example:
            ldap = FlextLdap(config)
            result = ldap.connect(...)
            if result.is_success:
                quirks = ldap.get_servers_info()
                if quirks.is_success:
                    info = quirks.unwrap()
                    acl_attr = info.get("acl_attribute")

        """
        try:
            if not self.client.is_connected:
                return FlextResult[dict[str, object]].fail(
                    "Cannot get server quirks info: not connected to LDAP server",
                )
            return self.client.get_servers_info()
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get server quirks information: {e}",
            )

    def get_server_attributes(self, capability: str) -> FlextResult[list[str]]:
        """Get attributes specific to current LDAP server for a given capability.

        Returns a list of LDAP attributes that are specific to the currently
        connected server type and relate to the specified capability
        (e.g., ACL operations, schema operations, etc.).

        Args:
            capability: Capability name (e.g., 'acl', 'schema', 'operational')

        Returns:
            FlextResult with list of attribute names supported for this capability

        Example:
            ldap = FlextLdap(config)
            result = ldap.connect(...)
            if result.is_success:
                acl_attrs = ldap.get_server_attributes("acl")
                if acl_attrs.is_success:
                    attrs = acl_attrs.unwrap()
                    print(f"ACL attributes: {attrs}")

        """
        try:
            if not self.client.is_connected:
                return FlextResult[list[str]].fail(
                    "Cannot get server attributes: not connected to LDAP server",
                )
            return self.client.get_server_attributes(capability)
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            return FlextResult[list[str]].fail(
                f"Failed to get server attributes for capability '{capability}': {e}",
            )

    def transform_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Transform an LDIF entry for a different target LDAP server type.

        Applies server-specific transformations to convert an entry from the
        current server format to be compatible with a different target LDAP
        server type. Includes attribute name remapping, value transformations,
        and other server-specific adjustments.

        Args:
            entry: LDIF entry to transform
            target_server_type: Target LDAP server type (e.g., 'OID', 'OUD', 'OpenLDAP')

        Returns:
            FlextResult with transformed Entry ready for the target server

        Example:
            ldap = FlextLdap(config)
            result = ldap.connect(...)
            if result.is_success:
                # Load an entry from current server
                entry = FlextLdifModels.Entry(...)
                # Transform it for Oracle OUD
                transformed = ldap.transform_entry_for_server(entry, "OUD")
                if transformed.is_success:
                    oud_entry = transformed.unwrap()
                    # Can now load into OUD

        """
        try:
            if not entry:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Cannot transform: entry is empty or None",
                )
            return self.client.transform_entry_for_server(entry, target_server_type)
        except (ValueError, TypeError, AttributeError, KeyError) as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to transform entry for server type '{target_server_type}': {e}",
            )

    # =========================================================================
    # SEARCH DELEGATION - Forward to FlextLdapClients
    # =========================================================================

    def search(
        self,
        base_dn: FlextLdifModels.DistinguishedName | str,
        filter_str: str,
        attributes: list[str] | None = None,
        scope: FlextLdapConstants.Types.Ldap3Scope = "SUBTREE",
        page_size: int = 0,
        paged_cookie: bytes | None = None,
        *,
        single: bool = False,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None]:
        """Perform LDAP search - delegates to client.

        Args:
            base_dn: Search base DN
            filter_str: LDAP filter string
            attributes: Attributes to retrieve
            scope: Search scope (BASE, LEVEL, SUBTREE)
            page_size: Page size for paged results
            paged_cookie: Cookie for paged results continuation
            single: If True, return first entry only
            quirks_mode: Override default quirks mode for this search

        Returns:
            FlextResult with list of entries or single entry based on single parameter.

        """
        # Create SearchRequest model for delegation to client
        # Convert DistinguishedName to str if needed
        base_dn_str = str(base_dn) if not isinstance(base_dn, str) else base_dn
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn_str,
            filter_str=filter_str,
            attributes=attributes,
            scope=scope,
            page_size=page_size,
            paged_cookie=paged_cookie,
            single=single,
            quirks_mode=quirks_mode,
        )
        return self.client.search(search_request)

    # =========================================================================
    # MODIFY DELEGATION - Forward to FlextLdapClients
    # =========================================================================

    def add_entry(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
        attributes: FlextLdifModels.LdifAttributes | dict[str, str | list[str]],
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Add new LDAP entry - delegates to client.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes
            quirks_mode: Override default quirks mode for this operation

        Returns:
            FlextResult[bool]: Success if entry was added

        """
        return self.client.add_entry(dn, attributes, quirks_mode=quirks_mode)

    def modify_entry(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
        changes: FlextLdapModels.EntryChanges,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Modify existing LDAP entry - delegates to client.

        Args:
            dn: Distinguished name of entry to modify
            changes: Entry changes to apply
            quirks_mode: Override default quirks mode for this operation

        Returns:
            FlextResult[bool]: Success if entry was modified

        """
        return self.client.modify_entry(dn, changes, quirks_mode=quirks_mode)

    def __enter__(self) -> Self:
        """Enter context manager with advanced Python 3.13 error handling.

        Establishes LDAP connection using configuration with comprehensive
        error handling and type safety.

        Raises:
            ConnectionError: If connection fails with detailed error information

        """
        # Extract password with type narrowing and safety
        password_value: str = ""
        if self._config.ldap_bind_password is not None:
            password_value = self._config.ldap_bind_password.get_secret_value()

        # Create ConnectionRequest model for connect()
        request = FlextLdapModels.ConnectionRequest(
            server_uri=self._config.ldap_server_uri,
            bind_dn=self._config.ldap_bind_dn or "",
            password=password_value,
            quirks_mode=self.s_mode,
        )

        # Attempt connection with structured error handling
        result = self.client.connect(request)

        # Pattern matching for connection result handling
        match result:
            case FlextResult() if result.is_success:
                return self
            case FlextResult() if result.is_failure:
                error_msg = f"Failed to connect to LDAP server: {result.error}"
                raise ConnectionError(error_msg) from None
            case _:
                # Fallback for unexpected result types
                error_msg = "Unexpected connection result type"
                raise ConnectionError(error_msg) from None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        _exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit context manager with advanced Python 3.13 exception handling.

        Uses structural pattern matching to handle different exception scenarios
        during LDAP connection cleanup.

        Args:
            exc_type: Type of exception that occurred (if any)
            exc_val: Exception instance that occurred (if any)
            _exc_tb: Exception traceback (if any) - intentionally unused

        """
        # Always attempt to unbind, even if an exception occurred
        try:
            self.client.unbind()
        except Exception as unbind_error:
            # Log unbind error but don't suppress original exception
            # In Python 3.13 context managers, we don't suppress exceptions
            match (exc_type, exc_val):
                case (None, None):
                    # No original exception, raise unbind error
                    raise unbind_error from None
                case (_, BaseException() as original_exc):
                    # Original exception exists, add unbind error as context
                    raise unbind_error from original_exc
                case (_, None):
                    # Original exception was None, raise unbind error
                    raise unbind_error from None

        # Advanced exception analysis using pattern matching
        match (exc_type, exc_val):
            case (_, _) if isinstance(exc_type, type) and issubclass(
                exc_type, ConnectionError
            ):
                # LDAP connection errors - already handled in __enter__
                pass
            case (_, _) if isinstance(exc_type, type) and issubclass(
                exc_type, ValueError
            ):
                # Data validation errors - let them propagate
                pass
            case (_, _) if isinstance(exc_type, type) and issubclass(
                exc_type, TypeError
            ):
                # Type validation errors - let them propagate
                pass
            case (_, _):
                # Other exceptions - ensure proper cleanup occurred
                pass
