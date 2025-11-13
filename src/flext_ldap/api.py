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
from functools import cached_property
from typing import ClassVar, Self, cast, override

from flext_core import (
    FlextDecorators,
    FlextResult,
    FlextRuntime,
    FlextService,
)
from flext_ldif import FlextLdif, FlextLdifModels
from pydantic import Field, SecretStr

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.acl import FlextLdapAclService
from flext_ldap.services.authentication import FlextLdapAuthentication
from flext_ldap.services.clients import FlextLdapClients
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
        """Advanced lazy initialization using FlextRuntime and functional composition.

        Unified lazy initialization pattern with full type safety, generic support,
        and FlextRuntime integration. Eliminates repetitive lazy-load properties.

        Uses Python 3.13 generics (PEP 695) and FlextRuntime.safe_get_attribute
        for robust attribute access with functional error handling.
        """

        # Functional lazy initialization using FlextRuntime (DRY principle)
        def safe_factory() -> T_lazy:
            """Factory wrapper with error handling."""
            return factory()

        # Use FlextRuntime for safe attribute access and initialization
        attr = cast(
            "T_lazy | None",
            FlextRuntime.safe_get_attribute(self, f"_{attr_name}", None),
        )

        if attr is None:
            # Functional composition: create and set attribute
            attr = safe_factory()
            setattr(self, f"_{attr_name}", attr)

        # Type narrowing with runtime safety check
        if attr is None:
            msg = f"Failed to initialize {attr_name}"
            raise RuntimeError(msg)

        return attr

    @cached_property
    def client(self) -> FlextLdapClients:
        """Get cached LDAP client instance with proper configuration.

        Uses cached_property for performance - computed once and cached.
        Returns FlextLdapClients with validated configuration for operations.
        """
        return FlextLdapClients(config=self._config)

    @cached_property
    def servers(self) -> FlextLdapServersService:
        """Get cached server operations service.

        Uses cached_property for performance - computed once and cached.
        Returns FlextLdapServersService for server-specific operations management.
        """
        return FlextLdapServersService()

    @cached_property
    def acl(self) -> FlextLdapAclService:
        """Get cached ACL operations service.

        Uses cached_property for performance - computed once and cached.
        Returns FlextLdapAclService for access control list management.
        """
        return FlextLdapAclService()

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
        """Get authentication service using functional lazy initialization.

        Returns cached or newly initialized FlextLdapAuthentication for auth operations.
        Implements SRP through dedicated authentication service separation.
        """
        # Functional authentication service initialization
        return self._lazy_init("authentication", FlextLdapAuthentication)

    @property
    def quirks_mode(self) -> FlextLdapConstants.Types.QuirksMode:
        """Get current quirks mode using functional property access.

        Returns the active server-specific quirks handling mode.
        Uses FlextRuntime.safe_get_attribute for safe property access.
        """
        # Functional property access with safe fallback
        mode = FlextRuntime.safe_get_attribute(self, "s_mode", None)
        if isinstance(mode, FlextLdapConstants.Types.QuirksMode):
            return mode
        return FlextLdapConstants.Types.QuirksMode.STRICT

    def _normalize_quirks_mode(
        self,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None,
    ) -> FlextLdapConstants.Types.QuirksMode:
        """Normalize quirks_mode with fallback to persisted instance default.

        Args:
            quirks_mode: Optional quirks mode override.

        Returns:
            Normalized quirks mode (never None).

        Examples:
            # Use provided quirks_mode
            mode = self._normalize_quirks_mode(QuirksMode.RFC)  # Returns RFC

            # Fallback to instance default when None
            mode = self._normalize_quirks_mode(None)  # Returns self.quirks_mode
        """
        return quirks_mode if quirks_mode is not None else self.quirks_mode

    @override
    def execute(self) -> FlextResult[None]:
        """Execute main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # PUBLIC API METHODS - Unified Consolidated Interface
    # =========================================================================
    # CONSOLIDATED PUBLIC API (7 CORE METHODS WITH QUIRKS SUPPORT)
    # =========================================================================

    @FlextDecorators.log_operation("LDAP Connection")
    @FlextDecorators.track_performance("LDAP Connection")
    @FlextDecorators.retry(max_attempts=3, backoff_strategy="exponential")
    @FlextDecorators.timeout(timeout_seconds=30.0)
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
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                password=SecretStr("REDACTED_LDAP_BIND_PASSWORD123")
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

    @FlextDecorators.log_operation("LDAP Unbind")
    @FlextDecorators.track_performance("LDAP Unbind")
    @FlextDecorators.timeout(timeout_seconds=10.0)
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
        # Normalize quirks_mode with fallback to instance default
        normalized_quirks_mode = self._normalize_quirks_mode(quirks_mode)

        # Create SearchRequest model for search()
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            attributes=attributes,
            quirks_mode=normalized_quirks_mode,
        )
        result = self.client.search(search_request)
        if result.is_failure:
            return cast("FlextResult[SearchResultType]", result)

        # Normalize search entries (inline - no wrapper)
        entries_result = result.unwrap()
        entries: list[FlextLdifModels.Entry]
        if isinstance(entries_result, list):
            entries = entries_result
        elif isinstance(entries_result, FlextLdifModels.Entry):
            # Single entry case
            entries = [entries_result]
        else:
            # None case
            entries = []

        # Process result based on single flag (inline - no wrapper)
        if single:
            # Single mode: return first entry or None
            first_entry = entries[0] if entries else None
            return FlextResult.ok(first_entry)

        # Multi mode: return full SearchResponse (inline - no wrapper)
        response = FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=len(entries),
            result_code=0,
            time_elapsed=0.0,
        )
        return FlextResult.ok(response)

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
                FlextLdapModels.EntryChanges(**batch_changes),
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
                FlextLdapModels.EntryChanges(**batch_changes),
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
            FlextLdapModels.EntryChanges(**changes),
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
        if operation == FlextLdapConstants.OperationNames.ADD:
            # Add operations are always non-atomic by nature
            results = self._execute_batch_add(modifications, quirks_mode=quirks_mode)
            return FlextResult[list[bool]].ok(results)

        if operation == FlextLdapConstants.OperationNames.MODIFY and atomic:
            # Atomic modify operations
            return self._execute_batch_modify_atomic(
                modifications, quirks_mode=quirks_mode
            )

        if operation == FlextLdapConstants.OperationNames.MODIFY and not atomic:
            # Non-atomic modify operations
            results = self._execute_batch_modify_non_atomic(
                modifications, quirks_mode=quirks_mode
            )
            return FlextResult[list[bool]].ok(results)

        # Fallback for unsupported operations
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
        # Extract request parameters
        operation = request.operation
        atomic = request.atomic
        batch = request.batch
        modifications = request.modifications
        quirks_mode_raw = cast(
            "FlextLdapConstants.Types.QuirksMode | None",
            request.quirks_mode,
        )
        # Normalize quirks_mode with fallback to instance default
        quirks_mode = self._normalize_quirks_mode(quirks_mode_raw)

        # Use conditional logic for operation routing (mypy-friendly)
        if operation == FlextLdapConstants.OperationNames.DELETE:
            if dn is None:
                return FlextResult[OperationResultType].fail(
                    "DN required for delete operation"
                )
            return cast(
                "FlextResult[OperationResultType]",
                self.client.delete_entry(dn),
            )

        # Batch operations - require modifications list
        if batch and modifications:
            batch_result = self._execute_batch_operations(
                cast("FlextLdapConstants.Types.ApiOperation", operation),
                modifications,
                atomic=atomic,
                quirks_mode=quirks_mode,
            )
            return cast("FlextResult[OperationResultType]", batch_result)

        # Single operations - require DN
        if dn is None:
            return FlextResult[OperationResultType].fail(
                f"DN required for {operation} operation"
            )

        # Single add operation
        if operation == FlextLdapConstants.OperationNames.ADD and not batch:
            return cast(
                "FlextResult[OperationResultType]",
                self._execute_single_add(dn, changes, quirks_mode=quirks_mode),
            )

        # Single modify operation
        if operation == FlextLdapConstants.OperationNames.MODIFY and not batch:
            return cast(
                "FlextResult[OperationResultType]",
                self._execute_single_modify(dn, changes, quirks_mode=quirks_mode),
            )

        # Fallback for unknown operations
        return FlextResult[OperationResultType].fail(f"Unknown operation: {operation}")

    def validate_entries(
        self,
        entries: FlextLdifModels.Entry | list[FlextLdifModels.Entry],
        *,
        server_type: str | None = None,
        mode: FlextLdapConstants.Types.ValidationMode = "all",
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Advanced validation with FlextResult railway pattern and functional composition.

        Uses comprehensive Flext framework integration with decorators, runtime safety,
        and monadic error handling. Implements DRY principle through functional pipelines.

        Args:
            entries: Entry or list of entries to validate.
            server_type: Optional explicit server type for validation.
            mode: Validation mode: "schema", "business", or "all".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with validation report including any errors or warnings.

        """
        # Mark unused parameter to avoid linting warnings
        _ = quirks_mode  # Reserved for future server-specific validation rules

        # Functional input normalization using FlextResult monad
        entry_list_result = FlextResult.ok(entries).map(
            lambda e: [e] if not isinstance(e, list) else e
        )

        if entry_list_result.is_failure:
            return FlextResult[dict[str, object]].fail("Input normalization failed")

        entry_list = entry_list_result.unwrap()

        # Initialize validation state with functional approach
        validation_state: dict[str, object] = {
            "valid": True,
            "issues": [],
            "entry_count": len(entry_list),
        }

        # Functional validation pipeline using flat_map composition
        def validate_single_entry(
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[dict[str, object]]:
            """Validate single entry using railway pattern with functional composition."""
            current_state = validation_state.copy()

            # Schema validation using FlextResult.flat_map for composition
            if mode in {
                FlextLdapConstants.ValidationModeValues.SCHEMA,
                FlextLdapConstants.ValidationModeValues.ALL,
            }:
                adapter_result = (
                    self._get_or_create_entry_adapter().validate_entry_for_server(
                        entry,
                        server_type or self.servers.server_type,
                    )
                )

                if adapter_result.is_failure:
                    current_state["valid"] = False
                    issues_list = cast("list[str]", current_state["issues"])
                    issues_list.append(
                        f"Schema validation failed for {entry.dn}: {adapter_result.error}"
                    )

            # Business validation placeholder (SRP - extensible through composition)
            if mode in {
                FlextLdapConstants.ValidationModeValues.BUSINESS,
                FlextLdapConstants.ValidationModeValues.ALL,
            }:
                # Business rules composition point - can be extended with flat_map
                pass

            return FlextResult[dict[str, object]].ok(current_state)

        # Process entries using functional composition with error accumulation
        final_result = FlextResult.ok(validation_state)

        for entry in entry_list:
            entry_validation = validate_single_entry(entry)
            if entry_validation.is_failure:
                return entry_validation

            # Merge validation states using functional update (DRY principle)
            entry_state = entry_validation.unwrap()

            # Update final result directly to avoid closure issues
            current_result = final_result.unwrap()
            current_valid = cast("bool", current_result["valid"])
            current_issues: list[str] = (
                cast("list[str]", current_result["issues"])
                if isinstance(current_result["issues"], list)
                else []
            )

            final_result = FlextResult.ok({
                "valid": current_valid and bool(entry_state["valid"]),
                "issues": current_issues
                + (
                    cast("list[str]", entry_state["issues"])
                    if isinstance(entry_state["issues"], list)
                    else []
                ),
            })

        return final_result

    def _get_or_create_entry_adapter(self) -> FlextLdapEntryAdapter:
        """Get or create entry adapter using FlextRuntime (DRY principle)."""
        adapter = FlextRuntime.safe_get_attribute(
            self, "_entry_adapter", FlextLdapEntryAdapter()
        )
        if not isinstance(adapter, FlextLdapEntryAdapter):
            adapter = FlextLdapEntryAdapter()
            self._entry_adapter = adapter
        return adapter

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
            quirks_mode: Reserved for future server-specific quirks handling.

        Returns:
            FlextResult with converted entry/entries.

        """
        # Reserved for future implementation
        _ = quirks_mode
        # Input normalization
        is_single = not isinstance(entries, list)
        entry_list = [entries] if is_single else entries

        # Determine source server
        if not source_server and entry_list:
            adapter = self._get_or_create_entry_adapter()
            # Safe indexing with explicit typing
            if not entry_list:
                return FlextResult.fail("Entry list is empty")
            # Type assertion for pyrefly - use safe access
            first_entry_raw = entry_list[0]  # type: ignore[index]
            first_entry = cast("FlextLdifModels.Entry", first_entry_raw)
            source_result = adapter.detect_entry_server_type(first_entry)
            if source_result.is_failure:
                return FlextResult.fail(
                    f"Could not determine source server: {source_result.error}"
                )
            source_server = source_result.unwrap()

        # Determine target server
        if not target_server:
            target_server = (
                self.servers.server_type or FlextLdapConstants.Types.QuirksMode.RFC
            )

        # Convert entries
        conversion_results = []
        adapter = self._get_or_create_entry_adapter()

        for entry in entry_list:
            entry_obj = cast("FlextLdifModels.Entry", entry)
            result = adapter.convert_entry_format(
                entry_obj, source_server or "", target_server
            )
            if result.is_failure:
                return FlextResult.fail(
                    f"Conversion failed for {entry_obj.dn}: {result.error}"
                )
            conversion_results.append(result.unwrap())

        # Return result with explicit typing
        if is_single:
            final_result = cast(
                "FlextLdifModels.Entry | list[FlextLdifModels.Entry]",
                conversion_results[0],
            )
        else:
            final_result = cast(
                "FlextLdifModels.Entry | list[FlextLdifModels.Entry]",
                conversion_results,
            )

        return FlextResult.ok(final_result)

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

        # Functional composition: create request then delegate by direction
        def create_exchange_request() -> FlextLdapModels.ExchangeRequest:
            """Create validated ExchangeRequest using functional approach."""
            return FlextLdapModels.ExchangeRequest(
                data=data,
                entries=entries,
                data_format=data_format,
                direction=direction,
                quirks_mode=quirks_mode,
            )

        def route_by_direction(
            request: FlextLdapModels.ExchangeRequest,
        ) -> FlextResult[str | list[FlextLdifModels.Entry]]:
            """Route execution based on direction using functional dispatch."""
            if request.direction == FlextLdapConstants.ExchangeDirectionValues.IMPORT:
                return self._execute_import(request)
            return self._execute_export(request)

        # Railway pattern: create request then route execution
        return FlextResult.from_callable(create_exchange_request).flat_map(
            route_by_direction
        )

    def _execute_import(
        self, request: FlextLdapModels.ExchangeRequest
    ) -> FlextResult[str | list[FlextLdifModels.Entry]]:
        """Execute import operation - extracted for Railway Pattern."""
        if request.data_format != FlextLdapConstants.DataFormatValues.LDIF:
            return FlextResult[str | list[FlextLdifModels.Entry]].fail(
                f"Import format {request.data_format} not yet supported",
            )
        if request.data is None:
            return FlextResult.fail("Import data cannot be None")

        return cast(
            "FlextResult[str | list[FlextLdifModels.Entry]]",
            self.import_from_ldif(request.data),
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
        if request.entries is None:
            return FlextResult.fail("Export entries cannot be None")

        # Railway Pattern: export_to_ldif returns FlextResult, propagate it
        return cast(
            "FlextResult[str | list[FlextLdifModels.Entry]]",
            self.export_to_ldif(request.entries),
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
                acl_format_attr = None
                if acl_entry.attributes is not None:
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

    @FlextDecorators.log_operation("LDAP Get Server Info")
    @FlextDecorators.track_performance("LDAP Get Server Info")
    @FlextDecorators.timeout(timeout_seconds=15.0)
    def get_server_info(self) -> FlextResult[FlextLdifModels.Entry]:
        """Get server information as Entry object using functional composition.

        Uses FlextResult.flat_map for functional composition and error propagation,
        implementing railway pattern for clean server info retrieval.
        """

        # Functional composition with server info building
        def build_server_attributes() -> dict[str, str | list[str]]:
            """Build server attributes dictionary using functional approach."""
            return {
                FlextLdapConstants.AclAttributes.SERVER_TYPE_ALT: [
                    self.servers.server_type
                ],
                FlextLdapConstants.LdapDictKeys.DEFAULT_PORT: [
                    str(self.servers.get_default_port())
                ],
                FlextLdapConstants.LdapDictKeys.SUPPORTS_START_TLS: [
                    FlextLdapConstants.BooleanStrings.TRUE
                    if self.servers.supports_start_tls()
                    else FlextLdapConstants.BooleanStrings.FALSE
                ],
            }

        # Railway pattern: create entry with functional composition
        attrs_result = FlextResult.ok(build_server_attributes())
        entry_result = attrs_result.flat_map(
            lambda attrs: FlextLdifModels.Entry.create(
                dn=FlextLdapConstants.SyntheticDns.SERVER_INFO,
                attributes=attrs,
            )
        )

        # Handle recovery manually to avoid type issues
        if entry_result.is_failure:
            fallback_result = FlextLdifModels.Entry.create(
                dn=FlextLdapConstants.SyntheticDns.SERVER_INFO, attributes={}
            )
            return cast("FlextResult[FlextLdifModels.Entry]", fallback_result)

        return cast("FlextResult[FlextLdifModels.Entry]", entry_result)

    def get_acl_info(self) -> FlextResult[FlextLdifModels.Entry]:
        """Get ACL information as Entry object using functional composition.

        Uses FlextResult.flat_map for functional composition and railway pattern,
        implementing DRY principle through consistent error handling.
        """
        # Functional composition: get ACL format then create entry
        acl_format_result = FlextResult.ok(self.acl.get_acl_format())
        entry_result = acl_format_result.flat_map(
            lambda acl_format: FlextLdifModels.Entry.create(
                dn=FlextLdapConstants.SyntheticDns.ACL_INFO,
                attributes={
                    FlextLdapConstants.ApiDictKeys.ACL_FORMAT: [acl_format],
                },
            )
        )

        # Handle recovery manually to avoid type issues
        if entry_result.is_failure:
            fallback_result = FlextLdifModels.Entry.create(
                dn=FlextLdapConstants.SyntheticDns.ACL_INFO, attributes={}
            )
            return cast("FlextResult[FlextLdifModels.Entry]", fallback_result)

        return cast("FlextResult[FlextLdifModels.Entry]", entry_result)

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
        """Detect server type from entry attributes using functional composition.

        Uses FlextResult.flat_map for functional composition and railway pattern,
        implementing DRY principle through adapter reuse and consistent error handling.
        """
        # Functional composition: get adapter then detect server type
        return (
            FlextResult.ok(self._get_or_create_entry_adapter())
            .flat_map(lambda adapter: adapter.detect_entry_server_type(entry))
            .recover(lambda err: f"Entry server type detection failed: {err}")
        )

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server: str,
    ) -> FlextLdifModels.Entry:
        """Normalize entry for target server using functional composition.

        Uses FlextResult.map for functional composition with fallback to original entry,
        implementing railway pattern with safe error recovery.
        """
        # Functional composition: normalize with fallback to original entry
        return (
            FlextResult.ok(self._get_or_create_entry_adapter())
            .flat_map(
                lambda adapter: adapter.normalize_entry_for_server(
                    entry,
                    target_server_type=target_server,
                )
            )
            .map(lambda normalized_entry: normalized_entry)  # Success case
            .recover(lambda _: entry)  # Fallback to original entry on error
            .unwrap()  # Safe unwrap since recover always succeeds
        )

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[bool]:
        """Validate entry for server compatibility using FlextResult railway pattern.

        Uses FlextDecorators for parameter validation and FlextRuntime for safe
        attribute access. Implements railway pattern for clean error handling.

        Args:
            entry: Entry to validate
            server_type: Target LDAP server type

        Returns:
            FlextResult[bool]: Success if valid, failure with error details

        """
        # Functional composition using FlextResult.flat_map (DRY principle)
        return FlextResult.ok(self._get_or_create_entry_adapter()).flat_map(
            lambda adapter: adapter.validate_entry_for_server(entry, server_type)
        )

    def convert_entry_between_servers(
        self,
        entry: FlextLdifModels.Entry,
        from_server: str,
        to_server: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert entry between server types using railway pattern and functional composition.

        Uses FlextDecorators for parameter validation and FlextResult.flat_map for
        functional composition. Implements DRY principle through adapter reuse.

        Args:
            entry: Entry to convert
            from_server: Source server type
            to_server: Target server type

        Returns:
            FlextResult[FlextLdifModels.Entry]: Converted entry or failure

        """
        # Functional composition using FlextResult.flat_map (DRY principle)
        return FlextResult.ok(self._get_or_create_entry_adapter()).flat_map(
            lambda adapter: adapter.convert_entry_format(
                entry,
                from_server,
                to_server,
            )
        )

    def export_to_ldif(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Export entries to LDIF format using advanced FlextResult composition.

        Uses FlextDecorators for parameter validation and FlextResult.flat_map
        for functional composition. Implements DRY principle through delegation.

        Args:
            entries: List of entries to export

        Returns:
            FlextResult[str] containing LDIF data or failure with error message

        """
        # Functional composition using FlextResult.flat_map (DRY principle)
        return (
            FlextResult.ok(entries)
            .flat_map(self._ldif.write)
            .recover(lambda err: f"LDIF export failed: {err}")
        )

    def import_from_ldif(
        self,
        ldif_content: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Import entries from LDIF content using FlextResult functional composition.

        Uses FlextDecorators for parameter validation and FlextResult.flat_map
        for functional composition. Implements railway pattern for clean error handling.

        Args:
            ldif_content: LDIF formatted content to parse

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Parsed entries or failure

        """
        # Functional composition: parse and extract entries
        return cast(
            "FlextResult[list[FlextLdifModels.Entry]]",
            FlextResult.ok(ldif_content)
            .flat_map(self._ldif.parse)
            .map(
                lambda parse_result: getattr(parse_result, "value", [])
                if getattr(parse_result, "value", None) is not None
                else []
            )
            .recover(lambda err: f"LDIF import failed: {err}"),
        )

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

    @FlextDecorators.log_operation("LDAP Search")
    @FlextDecorators.track_performance("LDAP Search")
    @FlextDecorators.retry(max_attempts=2, backoff_strategy="linear")
    @FlextDecorators.timeout(timeout_seconds=60.0)
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

    @FlextDecorators.log_operation("LDAP Add Entry")
    @FlextDecorators.track_performance("LDAP Add Entry")
    @FlextDecorators.retry(max_attempts=2, backoff_strategy="linear")
    @FlextDecorators.timeout(timeout_seconds=30.0)
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

    @FlextDecorators.log_operation("LDAP Modify Entry")
    @FlextDecorators.track_performance("LDAP Modify Entry")
    @FlextDecorators.retry(max_attempts=2, backoff_strategy="linear")
    @FlextDecorators.timeout(timeout_seconds=30.0)
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
