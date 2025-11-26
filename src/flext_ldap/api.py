"""FLEXT-LDAP API - Unified Facade for LDAP Operations.

This module provides the primary entry point for all LDAP operations.
The FlextLdap class serves as the sole facade for the FLEXT LDAP library,
coordinating connection management and LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import types
from collections.abc import Callable
from typing import ClassVar, Self, TypeVar, override

from flext_core import (
    FlextContainer,
    FlextDispatcher,
    FlextRegistry,
    FlextResult,
)
from flext_ldif import FlextLdif, FlextLdifModels
from pydantic import ConfigDict, PrivateAttr

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.typings import FlextLdapTypes

TResult = TypeVar("TResult")


class FlextLdap(FlextLdapServiceBase[FlextLdapModels.SearchResult]):
    """Main API facade for LDAP operations.

    This is the sole entry point for all LDAP operations, coordinating
    connection management and LDAP CRUD operations. It inherits from
    FlextService to leverage dependency injection, logging, and event
    publishing capabilities.

    Capabilities:
        - Connect to LDAP servers using ldap3
        - Search LDAP directories
        - Add, modify, and delete LDAP entries
        - Automatic conversion between LDAP results and Entry models
        - Reuses FlextLdif API for parsing operations
        - Service initialization and dependency injection via FlextContainer
        - Context management with correlation tracking

    Implementation:
        This class coordinates LDAP operations through a unified facade,
        managing service coordination, DI container operations, and business logic.

    Example:
        # Create instance
        ldap = FlextLdap()

        # Connect to server with context tracking
        config = FlextLdapModels.ConnectionConfig(
            host="ldap.example.com",
            port=389,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="password"
        )

        with ldap.context.set_correlation_id("req-123"):
            result = ldap.connect(config)
            if result.is_success:
                # Search entries
                search_options = FlextLdapModels.SearchOptions(
                    base_dn="dc=example,dc=com",
                    filter_str="(objectClass=person)"
                )
                search_result = ldap.search(search_options)
                if search_result.is_success:
                    entries = search_result.unwrap().entries

        # Disconnect
        ldap.disconnect()

    """

    model_config = ConfigDict(extra="allow")

    # Private attributes using Pydantic PrivateAttr for proper initialization
    _connection: FlextLdapConnection = PrivateAttr()
    _operations: FlextLdapOperations = PrivateAttr()
    _config: FlextLdapConfig = PrivateAttr()
    _ldif: FlextLdif = PrivateAttr()
    _dispatcher: FlextDispatcher = PrivateAttr()
    _registry: FlextRegistry = PrivateAttr()
    _context: dict[str, object] = PrivateAttr(default_factory=dict)
    _handlers: dict[str, object] = PrivateAttr(default_factory=dict)

    # Singleton instance storage
    _instance: ClassVar[FlextLdap | None] = None
    # Temporary storage for config/parser during __init__ → model_post_init
    _pending_config: ClassVar[FlextLdapConfig | None] = None
    _pending_ldif: ClassVar[FlextLdif | None] = None

    @classmethod
    def get_instance(
        cls,
        config: FlextLdapConfig | None = None,
        ldif: FlextLdif | None = None,
    ) -> FlextLdap:
        """Get singleton instance of FlextLdap facade.

        Args:
            config: Optional FlextLdapConfig (only used on first call)
            ldif: Optional FlextLdif instance (only used on first call)

        Returns:
            Singleton FlextLdap instance

        Example:
            # Recommended usage
            ldap = FlextLdap.get_instance(config=my_config)

            # All calls return same instance
            ldap2 = FlextLdap.get_instance()
            assert ldap is ldap2

        """
        if cls._instance is None:
            # Create instance with config/ldif if provided
            cls._instance = cls(config=config, ldif=ldif)
        return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset singleton instance (for testing only).

        WARNING: This method is intended for testing purposes only.
        Do not use in production code as it breaks the singleton pattern.

        Clears the singleton instance and initialization flag, allowing a fresh
        instance to be created on the next call to get_instance(). This ensures
        test isolation and idempotency by preventing state leakage between tests.

        Example:
            # In test fixture
            FlextLdap._reset_instance()
            ldap = FlextLdap.get_instance()  # Fresh instance

        """
        cls._instance = None

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        ldif: FlextLdif | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDAP facade - the entry point for all LDAP operations.

        Integrates Flext components for infrastructure support:
            - FlextContainer: Dependency injection
            - FlextLogger: Structured logging
            - FlextContext: Request context management
            - FlextConfig: Configuration with validation
            - FlextBus: Event publishing
            - FlextDispatcher: Message dispatching
            - FlextRegistry: Component registration

        Args:
            config: FlextLdapConfig instance (optional, creates default if not provided)
            ldif: FlextLdif instance (optional, uses singleton if not provided)
            **kwargs: Configuration parameters (passed to Pydantic)

        """
        # Store config and ldif in CLASS variables for use in model_post_init
        # Cannot set PrivateAttr before super().__init__() in Pydantic v2
        # Using class variables ensures they survive super().__init__()
        FlextLdap._pending_config = config
        FlextLdap._pending_ldif = ldif

        # Remove config from kwargs to prevent Pydantic from treating it as a field
        _ = kwargs.pop("config", None)
        _ = kwargs.pop("ldif", None)

        # Call super().__init__() for Pydantic v2 model initialization
        # This will call model_post_init() which initializes all services
        super().__init__(**kwargs)

        # Clear class variables after initialization
        FlextLdap._pending_config = None
        FlextLdap._pending_ldif = None

    def model_post_init(self, _context: object, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes and handles:
        - Service setup and dependency injection via FlextContainer
        - Context and handler initialization
        - Logging configuration

        Singleton pattern ensures this is only called once (when the single instance is created).

        Args:
            _context: Pydantic's validation context dictionary or None (unused).

        """
        # Initialize dispatcher, registry, and logger FIRST
        # These are needed by _setup_services() below
        dispatcher = FlextDispatcher()
        self._dispatcher = dispatcher
        self._registry = FlextRegistry(dispatcher=dispatcher)

        # Initialize config and ldif from CLASS variables (set in __init__)
        init_config = FlextLdap._pending_config
        init_ldif = FlextLdap._pending_ldif

        # Use FlextConfig namespace pattern: access via self.config.ldap
        # ldap namespace is registered via @FlextConfig.auto_register
        ldap_config = self.config.get_namespace("ldap", FlextLdapConfig)
        self._config = init_config if init_config is not None else ldap_config
        self._ldif = init_ldif if init_ldif is not None else FlextLdif.get_instance()

        # Initialize context and handlers
        self._context = {}
        self._handlers = {}

        # Initialize service instances
        self._connection = FlextLdapConnection(
            config=self._config,
            parser=self._ldif.parser,
        )
        self._operations = FlextLdapOperations(connection=self._connection)

        # Register services in container
        self._setup_services()

        # Log initialization with detailed context
        self.logger.info(
            "FlextLdap facade initialized",
            config_available=True,
            ldif_available=True,
            connection_ready=True,
            operations_ready=True,
        )
        self.logger.debug(
            "Services setup completed",
            services_registered=["connection", "operations", "parser"],
        )

    # =========================================================================
    # PRIVATE: Helpers
    # =========================================================================

    def _log_operation_result(
        self,
        operation: str,
        result: FlextResult[TResult],
        entry_dn: str | None = None,
        *,
        extra_debug: dict[str, object] | None = None,
        extra_info: dict[str, object] | None = None,
        extra_error: dict[str, object] | None = None,
    ) -> FlextResult[TResult]:
        """Generalized helper for logging operation results."""
        dn_truncated = entry_dn[:100] if entry_dn else None
        debug_fields: dict[str, object] = {
            "operation": operation,
            "entry_dn": dn_truncated,
            "is_connected": self.is_connected,
        }
        if extra_debug:
            debug_fields.update(extra_debug)
        self.logger.debug(
            f"LDAP {operation} operation", return_result=False, **debug_fields
        )

        if result.is_success:
            info_fields: dict[str, object] = {
                "operation": operation,
                "entry_dn": dn_truncated,
            }
            if extra_info:
                info_fields.update(extra_info)
            self.logger.info(
                f"LDAP {operation} completed", return_result=False, **info_fields
            )
        else:
            error_fields: dict[str, object] = {
                "operation": operation,
                "entry_dn": dn_truncated,
                "error": str(result.error),
            }
            if extra_error:
                error_fields.update(extra_error)
            self.logger.error(
                f"LDAP {operation} failed", return_result=False, **error_fields
            )

        return result

    # =========================================================================
    # PRIVATE: Service Setup
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services using FlextContainer patterns with metadata."""
        container = self.container

        # Execute service registration with error handling
        try:
            self._register_core_services(container)
        except Exception as e:
            self.logger.exception(
                "Failed to setup services - critical initialization error",
                exception=e,
            )
            raise

    def _register_core_services(self, container: FlextContainer) -> None:
        """Register core infrastructure services using generalized helper."""
        services = [
            ("connection", self._connection),
            ("operations", self._operations),
            ("parser", self._ldif.parser),
        ]
        for service_name, service_instance in services:
            if not container.has_service(service_name):
                result = container.register(service_name, service_instance)
                if result.is_failure:
                    error_msg = (
                        f"Failed to register {service_name} service: {result.error}"
                    )
                    self.logger.error(error_msg, critical=True)
                    raise RuntimeError(error_msg)
                self.logger.debug(f"Registered {service_name} service in container")

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        **_kwargs: object,
    ) -> FlextResult[bool]:
        """Establish LDAP connection with optional auto-retry.

        Args:
            connection_config: Connection configuration (required, no fallback)
            auto_retry: Enable automatic retry on connection failure (default: False)
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)

        Returns:
            FlextResult[bool] indicating connection success

        """
        self.logger.debug(
            "Connecting to LDAP server",
            operation="connect",
            host=connection_config.host,
            port=connection_config.port,
            use_ssl=connection_config.use_ssl,
            use_tls=connection_config.use_tls,
            auto_retry=auto_retry,
            max_retries=max_retries,
            retry_delay=retry_delay,
            bind_dn=connection_config.bind_dn[:50]
            if connection_config.bind_dn
            else None,
            has_password=connection_config.bind_password is not None,
        )

        result = self._connection.connect(
            connection_config,
            auto_retry=auto_retry,
            max_retries=max_retries,
            retry_delay=retry_delay,
        )

        if result.is_success:
            self.logger.info(
                "LDAP connection established",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
            )
        else:
            self.logger.error(
                "LDAP connection failed",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
                error=str(result.error),
            )

        return result

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self.logger.debug(
            "Disconnecting from LDAP server",
            operation="disconnect",
            was_connected=self.is_connected,
        )

        self._connection.disconnect()

        self.logger.info(
            "LDAP connection closed",
            operation="disconnect",
        )

    @property
    def is_connected(self) -> bool:
        """Check if facade has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._connection.is_connected

    @property
    def client(self) -> FlextLdapOperations:
        """Get LDAP operations client.

        Returns:
            FlextLdapOperations instance for direct operations access

        """
        return self._operations

    def __enter__(self) -> Self:
        """Context manager entry.

        Returns:
            Self for use in 'with' statement

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit.

        Automatically disconnects when exiting 'with' block.

        Args:
            exc_type: Exception type if exception occurred
            exc_val: Exception value if exception occurred
            exc_tb: Exception traceback if exception occurred

        """
        self.disconnect()

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        base_dn = search_options.base_dn[:100] if search_options.base_dn else None
        result = self._operations.search(search_options, server_type)
        if result.is_success:
            search_result = result.unwrap()
            return self._log_operation_result(
                operation="search",
                result=result,
                entry_dn=base_dn,
                extra_debug={
                    "base_dn": base_dn,
                    "filter_str": search_options.filter_str[:100]
                    if search_options.filter_str
                    else None,
                    "scope": search_options.scope,
                    "server_type": server_type,
                },
                extra_info={
                    "base_dn": base_dn,
                    "total_entries": search_result.total_count,
                    "entries_found": len(search_result.entries),
                },
            )
        return self._log_operation_result(
            operation="search",
            result=result,
            entry_dn=base_dn,
            extra_debug={
                "base_dn": base_dn,
                "filter_str": search_options.filter_str[:100]
                if search_options.filter_str
                else None,
                "scope": search_options.scope,
                "server_type": server_type,
            },
        )

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Args:
            entry: Entry model to add

        Returns:
            FlextResult containing OperationResult

        """
        entry_dn_str = FlextLdapServiceBase.safe_dn_string(entry.dn)
        result = self._operations.add(entry)
        self._log_operation_result(
            operation="add",
            result=result,
            entry_dn=entry_dn_str,
            extra_debug={
                "attributes_count": len(entry.attributes.attributes)
                if entry.attributes
                else 0
            },
        )
        return result

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: FlextLdapTypes.LdapModifyChanges,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        dn_str = FlextLdapServiceBase.safe_dn_string(dn)
        result = self._operations.modify(dn, changes)
        self._log_operation_result(
            operation="modify",
            result=result,
            entry_dn=dn_str,
            extra_debug={
                "changes_count": len(changes),
                "changed_attributes": list(changes.keys())[:20] if changes else [],
            },
            extra_info={"changes_applied": len(changes)},
            extra_error={"changes_count": len(changes)},
        )
        return result

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult containing OperationResult

        """
        dn_str = FlextLdapServiceBase.safe_dn_string(dn)
        result = self._operations.delete(dn)
        self._log_operation_result(operation="delete", result=result, entry_dn=dn_str)
        return result

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> FlextResult[FlextLdapTypes.LdapOperationResult]:
        """Upsert LDAP entry (add if doesn't exist, skip if exists) with optional retry.

        Generic method that handles both regular entries and schema modifications.
        For regular entries: tries add, returns "added" or "skipped" if already exists.
        For schema entries (changetype=modify): applies modify operation.

        Args:
            entry: Entry model to upsert
            retry_on_errors: List of error patterns to retry on (default: None = no retry)
            max_retries: Maximum number of retry attempts (default: 1)

        Returns:
            FlextResult containing dict with "operation" key:
                - "added": Entry was added
                - "modified": Entry was modified (for schema)
                - "skipped": Entry already exists

        """
        entry_dn_str = FlextLdapServiceBase.safe_dn_string(entry.dn)
        result = self._operations.upsert(
            entry, retry_on_errors=retry_on_errors, max_retries=max_retries
        )
        if result.is_success:
            operation_result = result.unwrap()
            operation_type = operation_result.get("operation", "unknown")
            self._log_operation_result(
                operation="upsert",
                result=result,
                entry_dn=entry_dn_str,
                extra_debug={
                    "attributes_count": len(entry.attributes.attributes)
                    if entry.attributes
                    else 0,
                    "retry_on_errors": retry_on_errors,
                    "max_retries": max_retries,
                },
                extra_info={"operation_type": operation_type},
            )
        else:
            self._log_operation_result(
                operation="upsert",
                result=result,
                entry_dn=entry_dn_str,
                extra_debug={
                    "attributes_count": len(entry.attributes.attributes)
                    if entry.attributes
                    else 0,
                    "retry_on_errors": retry_on_errors,
                    "max_retries": max_retries,
                },
            )
        return result

    def batch_upsert(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        progress_callback: Callable[
            [int, int, str, FlextLdapTypes.LdapBatchStats], None
        ]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> FlextResult[FlextLdapTypes.LdapBatchStats]:
        """Batch upsert multiple LDAP entries with progress tracking and retry.

        Processes entries sequentially, applying retry logic per-entry if configured.
        Aggregates results into synced/failed/skipped counters.

        Args:
            entries: List of entries to upsert
            progress_callback: Optional callback(idx: int, total: int, dn: str, stats: FlextLdapTypes.LdapBatchStats) after each entry
            retry_on_errors: Error patterns to retry on (passed to each upsert)
            max_retries: Maximum retries per entry (default: 1)
            stop_on_error: Stop processing on first error (default: False)

        Returns:
            FlextResult with dict containing:
                - "synced": Number of entries successfully added/modified
                - "failed": Number of entries that failed
                - "skipped": Number of entries skipped (already identical)

        """
        result = self._operations.batch_upsert(
            entries,
            progress_callback=progress_callback,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
            stop_on_error=stop_on_error,
        )
        if result.is_success:
            stats = result.unwrap()
            self._log_operation_result(
                operation="batch_upsert",
                result=result,
                entry_dn=None,
                extra_debug={
                    "entries_count": len(entries),
                    "has_progress_callback": progress_callback is not None,
                    "retry_on_errors": retry_on_errors,
                    "max_retries": max_retries,
                    "stop_on_error": stop_on_error,
                },
                extra_info={
                    "entries_count": len(entries),
                    "synced": stats.get("synced", 0),
                    "failed": stats.get("failed", 0),
                    "skipped": stats.get("skipped", 0),
                    "success_rate": f"{(stats.get('synced', 0) / len(entries) * 100):.1f}%"
                    if entries
                    else "0%",
                },
            )
        else:
            self._log_operation_result(
                operation="batch_upsert",
                result=result,
                entry_dn=None,
                extra_debug={
                    "entries_count": len(entries),
                    "has_progress_callback": progress_callback is not None,
                    "retry_on_errors": retry_on_errors,
                    "max_retries": max_retries,
                    "stop_on_error": stop_on_error,
                },
            )
        return result

    @override
    def execute(self, **_kwargs: object) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns:
            FlextResult containing service status

        """
        # Fast fail - delegate to operations, no fallback
        return self._operations.execute()
