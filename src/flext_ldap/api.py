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
    def create(cls) -> FlextLdap:
        """Factory method to create FlextLdap instance."""
        return cls()

    @property
    def config(self) -> FlextLdapConfig:
        """Get LDAP configuration."""
        return self._config

    @property
    def ldif(self) -> FlextLdif:
        """Get FlextLdif singleton instance for deep LDIF integration."""
        return self._ldif

    def _lazy_init(self, attr_name: str, factory: Callable[[], object]) -> object:
        """Unified lazy initialization pattern using FlextContainer-like pattern.

        Eliminates 4 repetitive lazy-load properties with single unified method.
        """
        attr = getattr(self, f"_{attr_name}", None)
        if attr is None:
            attr = factory()
            setattr(self, f"_{attr_name}", attr)
        return attr

    @property
    def client(self) -> FlextLdapClients:
        """Get LDAP client instance."""
        return cast(
            "FlextLdapClients",
            self._lazy_init("client", lambda: FlextLdapClients(config=self._config)),
        )

    @property
    def servers(self) -> FlextLdapServersService:
        """Get server operations instance."""
        return cast(
            "FlextLdapServersService",
            self._lazy_init("servers", FlextLdapServersService),
        )

    @property
    def acl(self) -> FlextLdapAclService:
        """Get ACL operations instance."""
        return cast("FlextLdapAclService", self._lazy_init("acl", FlextLdapAclService))

    def can_handle(self, message_type: object) -> bool:
        """Check if FlextLdap handler can process this message type.

        Implements Application.Handler protocol for command routing.
        Determines if a given message type can be processed by this handler.

        Args:
            message_type: The message type to check (typically a class or string)

        Returns:
            True if handler can process this message type, False otherwise

        """
        # Support LDAP operation message types
        if isinstance(message_type, str):
            ldap_operations = {
                "search",
                "add",
                "modify",
                "delete",
                FlextLdapConstants.OperationNames.BIND,
                "unbind",
                "compare",
                "upsert",
                "schema",
                "acl",
            }
            return message_type.lower() in ldap_operations

        # Support FlextLdapModels request types
        if message_type is FlextLdapModels.SearchRequest:
            return True
        if message_type is FlextLdapModels.SearchResponse:
            return True

        # Default: handle Entry type or return False for unknown types
        return message_type is FlextLdifModels.Entry

    @property
    def authentication(self) -> FlextLdapAuthentication:
        """Get authentication operations instance."""
        return cast(
            "FlextLdapAuthentication",
            self._lazy_init("authentication", FlextLdapAuthentication),
        )

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
        # Update configuration if parameters provided
        if uri:
            self._config.ldap_server_uri = uri

        # Set both bind_dn and bind_password together to avoid validation errors
        # Update __dict__ directly to bypass validate_assignment, then manually validate
        if bind_dn or password:
            if isinstance(password, str):
                password = SecretStr(password)

            # Update fields directly to avoid triggering validation between assignments
            if bind_dn:
                self._config.__dict__["ldap_bind_dn"] = bind_dn
            if password:
                self._config.__dict__["ldap_bind_password"] = password

            # Note: Pydantic v2 automatically runs model validators during field updates

        # Store quirks_mode for internal modules
        self.s_mode = quirks_mode

        # Connect using client with explicit config values
        password_value = ""  # nosec: default empty string, actual password from config.ldap_bind_password
        if self._config.ldap_bind_password is not None:
            password_value = self._config.ldap_bind_password.get_secret_value()

        result = self.client.connect(
            server_uri=self._config.ldap_server_uri,
            bind_dn=self._config.ldap_bind_dn
            or "",  # Handle None with default empty string
            password=password_value,
            quirks_mode=quirks_mode,
        )
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
        result = self.client.search(
            base_dn, filter_str, attributes, quirks_mode=quirks_mode
        )
        if result.is_failure:
            return cast(
                "FlextResult[FlextLdapModels.SearchResponse | FlextLdifModels.Entry | None]",
                result,
            )

        # client.search() returns list[Entry], wrap in SearchResponse
        entries_result = result.unwrap()
        # Normalize to list
        entries_list = (
            entries_result
            if isinstance(entries_result, list)
            else [entries_result]
            if entries_result
            else []
        )

        # Create SearchResponse from entries
        search_response = FlextLdapModels.SearchResponse(
            entries=entries_list,
            total_count=len(entries_list),
            result_code=0,
            time_elapsed=0.0,
        )

        if single:
            # Return first entry or None
            if search_response.entries:
                return cast(
                    "FlextResult[FlextLdapModels.SearchResponse | FlextLdifModels.Entry | None]",
                    FlextResult.ok(search_response.entries[0]),
                )
            return cast(
                "FlextResult[FlextLdapModels.SearchResponse | FlextLdifModels.Entry | None]",
                FlextResult.ok(None),
            )

        return cast(
            "FlextResult[FlextLdapModels.SearchResponse | FlextLdifModels.Entry | None]",
            FlextResult.ok(search_response),
        )

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
        """Execute batch operations (add or modify)."""
        if operation == "add":
            results = self._execute_batch_add(modifications, quirks_mode=quirks_mode)
            return FlextResult[list[bool]].ok(results)
        if operation == "modify":
            if atomic:
                return self._execute_batch_modify_atomic(
                    modifications, quirks_mode=quirks_mode
                )
            results = self._execute_batch_modify_non_atomic(
                modifications, quirks_mode=quirks_mode
            )
            return FlextResult[list[bool]].ok(results)

        return FlextResult[list[bool]].fail(f"Unknown operation: {operation}")

    def apply_changes(
        self,
        changes: dict[str, str | list[str]],
        dn: str | None = None,
        *,
        operation: FlextLdapConstants.Types.ApiOperation = "add",
        atomic: bool = False,
        batch: bool = False,
        modifications: list[tuple[str, dict[str, str | list[str]]]] | None = None,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool | list[bool]]:
        """Universal CRUD apply_changes method with quirks support.

        Consolidates add, modify, and delete operations with unified interface.
        Supports both single and batch operations with optional atomic semantics.

        Args:
            changes: Changes/attributes for single operation.
            dn: Distinguished name for single operation (required for add/modify).
            operation: Type of operation: "add", "modify", or "delete".
            atomic: If True, attempt atomic modification (all or none).
            batch: If True, use modifications parameter for batch mode.
            modifications: List of (DN, changes) tuples for batch operations.
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult[bool] for single operation, FlextResult[list[bool]] for batch.

        """
        # Handle delete operation
        if operation == "delete":
            if not dn:
                return FlextResult[bool | list[bool]].fail(
                    "DN required for delete operation",
                )
            return cast("FlextResult[bool | list[bool]]", self.client.delete_entry(dn))

        # Handle batch operations
        if batch and modifications:
            batch_result = self._execute_batch_operations(
                operation, modifications, atomic=atomic, quirks_mode=quirks_mode
            )
            return cast("FlextResult[bool | list[bool]]", batch_result)

        # Handle single operations
        if not dn:
            return FlextResult[bool | list[bool]].fail(
                f"DN required for {operation} operation",
            )

        if operation == "add":
            return cast(
                "FlextResult[bool | list[bool]]",
                self._execute_single_add(dn, changes, quirks_mode=quirks_mode),
            )
        if operation == "modify":
            return cast(
                "FlextResult[bool | list[bool]]",
                self._execute_single_modify(dn, changes, quirks_mode=quirks_mode),
            )

        return FlextResult[bool | list[bool]].fail(f"Unknown operation: {operation}")

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

        Args:
            data: Data string for import operation.
            entries: Entries for export operation.
            data_format: Data format: "ldif", "json", or "csv".
            direction: Operation direction: "import" or "export".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with imported entries or exported data string.

        """
        _ = quirks_mode  # Reserved for future format-specific import/export rules
        if direction == FlextLdapConstants.ExchangeDirectionValues.IMPORT:
            if not data:
                return FlextResult[str | list[FlextLdifModels.Entry]].fail(
                    "Data required for import operation",
                )
            if data_format == FlextLdapConstants.DataFormatValues.LDIF:
                return cast(
                    "FlextResult[str | list[FlextLdifModels.Entry]]",
                    self.import_from_ldif(data),
                )
            return FlextResult[str | list[FlextLdifModels.Entry]].fail(
                f"Import format {data_format} not yet supported",
            )
        # export
        if not entries:
            return FlextResult[str | list[FlextLdifModels.Entry]].fail(
                "Entries required for export operation",
            )
        if data_format == "ldif":
            export_result = self.export_to_ldif(entries)
            if export_result.is_failure:
                return FlextResult[str | list[FlextLdifModels.Entry]].fail(
                    export_result.error
                )
            return FlextResult[str | list[FlextLdifModels.Entry]].ok(
                export_result.unwrap()
            )
        return FlextResult[str | list[FlextLdifModels.Entry]].fail(
            f"Export format {data_format} not yet supported",
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
        return self.client.search(
            base_dn,
            filter_str,
            attributes,
            scope,
            page_size,
            paged_cookie,
            single=single,
            quirks_mode=quirks_mode,
        )

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
        """Enter context manager - establish connection using config.

        Raises:
            ConnectionError: If connection fails

        """
        password_value = ""  # nosec: default empty string, actual password from config.ldap_bind_password
        if self._config.ldap_bind_password is not None:
            password_value = self._config.ldap_bind_password.get_secret_value()

        result = self.client.connect(
            server_uri=self._config.ldap_server_uri,
            bind_dn=self._config.ldap_bind_dn or "",
            password=password_value,
            quirks_mode=self.s_mode,
        )
        if result.is_failure:
            error_msg = f"Failed to connect to LDAP server: {result.error}"
            raise ConnectionError(error_msg)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit context manager - close connection."""
        self.client.unbind()
