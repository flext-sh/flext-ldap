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
from typing import ClassVar, Self, cast, override

from flext_core import (
    FlextConfig,
    FlextContainer,
    FlextDispatcher,
    FlextLogger,
    FlextRegistry,
    FlextResult,
    FlextService,
)
from flext_ldif import FlextLdifModels, FlextLdifParser, FlextLdifUtilities
from pydantic import PrivateAttr

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdap(FlextService[FlextLdapModels.SearchResult]):
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
        - Reuses FlextLdifParser for parsing operations
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
            bind_dn="cn=admin,dc=example,dc=com",
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

    # Private attributes using Pydantic PrivateAttr for proper initialization
    _connection: FlextLdapConnection = PrivateAttr()
    _operations: FlextLdapOperations = PrivateAttr()
    _config: FlextLdapConfig = PrivateAttr()
    _logger: FlextLogger = PrivateAttr()
    _parser: FlextLdifParser = PrivateAttr()
    _dispatcher: FlextDispatcher = PrivateAttr()
    _registry: FlextRegistry = PrivateAttr()
    _context: dict[str, object] = PrivateAttr(default_factory=dict)
    _handlers: dict[str, object] = PrivateAttr(default_factory=dict)

    # Singleton instance storage
    _instance: ClassVar[FlextLdap | None] = None
    # Temporary storage for config/parser during __init__ → model_post_init
    _pending_config: ClassVar[FlextLdapConfig | None] = None
    _pending_parser: ClassVar[FlextLdifParser | None] = None

    @classmethod
    def get_instance(
        cls,
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> FlextLdap:
        """Get singleton instance of FlextLdap facade.

        Args:
            config: Optional FlextLdapConfig (only used on first call)
            parser: Optional FlextLdifParser (only used on first call)

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
            # Create instance with config/parser if provided
            cls._instance = cls(config=config, parser=parser)
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
        parser: FlextLdifParser | None = None,
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
            parser: FlextLdifParser instance (optional, creates default if not provided)
            **kwargs: Configuration parameters (passed to Pydantic)

        """
        # Store config and parser in CLASS variables for use in model_post_init
        # Cannot set PrivateAttr before super().__init__() in Pydantic v2
        # Using class variables ensures they survive super().__init__()
        FlextLdap._pending_config = config
        FlextLdap._pending_parser = parser

        # Remove config from kwargs to prevent Pydantic from treating it as a field
        _ = kwargs.pop("config", None)
        _ = kwargs.pop("parser", None)

        # Call super().__init__() for Pydantic v2 model initialization
        # This will call model_post_init() which initializes all services
        super().__init__(**kwargs)

        # Clear class variables after initialization
        FlextLdap._pending_config = None
        FlextLdap._pending_parser = None

    def model_post_init(self, __context: object, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes and handles:
        - Service setup and dependency injection via FlextContainer
        - Context and handler initialization
        - Logging configuration

        Singleton pattern ensures this is only called once (when the single instance is created).

        Args:
            __context: Pydantic's validation context dictionary or None (unused).

        """
        # Initialize dispatcher, registry, and logger FIRST
        # These are needed by _setup_services() below
        dispatcher = FlextDispatcher()
        self._dispatcher = dispatcher
        self._registry = FlextRegistry(dispatcher=dispatcher)
        self._logger = FlextLogger(__name__)

        # Initialize config and parser from CLASS variables (set in __init__)
        init_config = FlextLdap._pending_config
        init_parser = FlextLdap._pending_parser

        # Use FlextConfig namespace pattern: access via namespace when config not provided
        self._config = (
            init_config
            if init_config is not None
            else cast("FlextLdapConfig", FlextConfig.get_global_instance().ldap)
        )
        self._parser = init_parser if init_parser is not None else FlextLdifParser()

        # Initialize context and handlers
        self._context = {}
        self._handlers = {}

        # Initialize service instances
        self._connection = FlextLdapConnection(
            config=self._config,
            parser=self._parser,
        )
        self._operations = FlextLdapOperations(connection=self._connection)

        # Register services in container
        self._setup_services()

        # Log initialization with detailed context
        self.logger.info(
            "FlextLdap facade initialized",
            config_available=True,
            parser_available=True,
            connection_ready=True,
            operations_ready=True,
        )

        self.logger.debug(
            "Services setup completed",
            services_registered=["connection", "operations", "parser"],
        )

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
        """Register core infrastructure services."""
        # Register connection service (check if already exists - container is global)
        if not container.has("connection"):
            result = container.register_service("connection", self._connection)
            if result.is_failure:
                error_msg = f"Failed to register connection service: {result.error}"
                self.logger.error(error_msg, critical=True)
                raise RuntimeError(error_msg)

            self.logger.debug("Registered connection service in container")

        # Register operations service
        if not container.has("operations"):
            result = container.register_service("operations", self._operations)
            if result.is_failure:
                error_msg = f"Failed to register operations service: {result.error}"
                self.logger.error(error_msg, critical=True)
                raise RuntimeError(error_msg)

            self.logger.debug("Registered operations service in container")

        # Register parser service
        if not container.has("parser"):
            result = container.register_service("parser", self._parser)
            if result.is_failure:
                error_msg = f"Failed to register parser service: {result.error}"
                self.logger.error(error_msg, critical=True)
                raise RuntimeError(error_msg)

            self.logger.debug("Registered parser service in container")

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
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
        self._logger.debug(
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
            self._logger.info(
                "LDAP connection established",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
            )
        else:
            self._logger.error(
                "LDAP connection failed",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
                error=str(result.error),
            )

        return result

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self._logger.debug(
            "Disconnecting from LDAP server",
            operation="disconnect",
            was_connected=self.is_connected,
        )

        self._connection.disconnect()

        self._logger.info(
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
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        self._logger.debug(
            "Searching LDAP directory",
            operation="search",
            base_dn=search_options.base_dn[:100] if search_options.base_dn else None,
            filter_str=search_options.filter_str[:100]
            if search_options.filter_str
            else None,
            scope=search_options.scope,
            server_type=server_type,
            is_connected=self.is_connected,
        )

        result = self._operations.search(search_options, server_type)

        if result.is_success:
            search_result = result.unwrap()
            self._logger.info(
                "LDAP search completed",
                operation="search",
                base_dn=search_options.base_dn[:100]
                if search_options.base_dn
                else None,
                total_entries=search_result.total_count,
                entries_found=len(search_result.entries),
            )
        else:
            self._logger.error(
                "LDAP search failed",
                operation="search",
                base_dn=search_options.base_dn[:100]
                if search_options.base_dn
                else None,
                error=str(result.error),
            )

        return result

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Args:
            entry: Entry model to add

        Returns:
            FlextResult containing OperationResult

        """
        entry_dn_str = str(entry.dn) if entry.dn else "unknown"
        self._logger.debug(
            "Adding LDAP entry",
            operation="add",
            entry_dn=entry_dn_str[:100] if entry_dn_str else None,
            attributes_count=len(entry.attributes.attributes)
            if entry.attributes
            else 0,
            is_connected=self.is_connected,
        )

        result = self._operations.add(entry)

        if result.is_success:
            self._logger.info(
                "LDAP entry added",
                operation="add",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
            )
        else:
            self._logger.error(
                "LDAP add entry failed",
                operation="add",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=str(result.error),
            )

        return result

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        # Use FlextLdifUtilities.DN.get_dn_value for consistent DN extraction
        dn_str = FlextLdifUtilities.DN.get_dn_value(dn) if dn else "unknown"
        self._logger.debug(
            "Modifying LDAP entry",
            operation="modify",
            entry_dn=dn_str[:100] if dn_str else None,
            changes_count=len(changes),
            changed_attributes=list(changes.keys())[:20] if changes else [],
            is_connected=self.is_connected,
        )

        result = self._operations.modify(dn, changes)

        if result.is_success:
            self._logger.info(
                "LDAP entry modified",
                operation="modify",
                entry_dn=dn_str[:100] if dn_str else None,
                changes_applied=len(changes),
            )
        else:
            self._logger.error(
                "LDAP modify entry failed",
                operation="modify",
                entry_dn=dn_str[:100] if dn_str else None,
                error=str(result.error),
                changes_count=len(changes),
            )

        return result

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult containing OperationResult

        """
        # Use FlextLdifUtilities.DN.get_dn_value for consistent DN extraction
        dn_str = FlextLdifUtilities.DN.get_dn_value(dn) if dn else "unknown"
        self._logger.debug(
            "Deleting LDAP entry",
            operation="delete",
            entry_dn=dn_str[:100] if dn_str else None,
            is_connected=self.is_connected,
        )

        result = self._operations.delete(dn)

        if result.is_success:
            self._logger.info(
                "LDAP entry deleted",
                operation="delete",
                entry_dn=dn_str[:100] if dn_str else None,
            )
        else:
            self._logger.error(
                "LDAP delete entry failed",
                operation="delete",
                entry_dn=dn_str[:100] if dn_str else None,
                error=str(result.error),
            )

        return result

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> FlextResult[dict[str, str]]:
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
        entry_dn_str = str(entry.dn) if entry.dn else "unknown"
        self._logger.debug(
            "Upserting LDAP entry",
            operation="upsert",
            entry_dn=entry_dn_str[:100] if entry_dn_str else None,
            attributes_count=len(entry.attributes.attributes)
            if entry.attributes
            else 0,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
            is_connected=self.is_connected,
        )

        result = self._operations.upsert(
            entry,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
        )

        if result.is_success:
            operation_result = result.unwrap()
            operation_type = operation_result.get("operation", "unknown")
            self._logger.info(
                "LDAP upsert completed",
                operation="upsert",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                operation_type=operation_type,
            )
        else:
            self._logger.error(
                "LDAP upsert failed",
                operation="upsert",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=str(result.error),
            )

        return result

    def batch_upsert(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        progress_callback: Callable[[int, int, str, dict[str, int]], None]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> FlextResult[dict[str, int]]:
        """Batch upsert multiple LDAP entries with progress tracking and retry.

        Processes entries sequentially, applying retry logic per-entry if configured.
        Aggregates results into synced/failed/skipped counters.

        Args:
            entries: List of entries to upsert
            progress_callback: Optional callback(idx: int, total: int, dn: str, stats: dict[str, int]) after each entry
            retry_on_errors: Error patterns to retry on (passed to each upsert)
            max_retries: Maximum retries per entry (default: 1)
            stop_on_error: Stop processing on first error (default: False)

        Returns:
            FlextResult with dict containing:
                - "synced": Number of entries successfully added/modified
                - "failed": Number of entries that failed
                - "skipped": Number of entries skipped (already identical)

        """
        self._logger.debug(
            "Starting batch upsert",
            operation="batch_upsert",
            entries_count=len(entries),
            has_progress_callback=progress_callback is not None,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
            stop_on_error=stop_on_error,
            is_connected=self.is_connected,
        )

        result = self._operations.batch_upsert(
            entries,
            progress_callback=progress_callback,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
            stop_on_error=stop_on_error,
        )

        if result.is_success:
            stats = result.unwrap()
            self._logger.info(
                "Batch upsert completed",
                operation="batch_upsert",
                entries_count=len(entries),
                synced=stats.get("synced", 0),
                failed=stats.get("failed", 0),
                skipped=stats.get("skipped", 0),
                success_rate=f"{(stats.get('synced', 0) / len(entries) * 100):.1f}%"
                if entries
                else "0%",
            )
        else:
            self._logger.error(
                "Batch upsert failed",
                operation="batch_upsert",
                entries_count=len(entries),
                error=str(result.error),
            )

        return result

    @override
    def execute(self, **kwargs: object) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns:
            FlextResult containing service status

        """
        # Fast fail - delegate to operations, no fallback
        return self._operations.execute()
