"""FLEXT-LDAP API - Unified Facade for LDAP Operations.

This module provides the primary entry point for all LDAP operations.
The FlextLdap class serves as the sole facade for the FLEXT LDAP library,
coordinating connection management and LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import types
from typing import Self, override

from flext_core import (
    FlextContainer,
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextRegistry,
    FlextResult,
    FlextService,
)
from flext_ldif import FlextLdifModels, FlextLdifParser
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
        # Store config and parser for use in model_post_init
        # Cannot set PrivateAttr before super().__init__() in Pydantic v2
        object.__setattr__(self, "_init_config_value", config)
        object.__setattr__(self, "_init_parser_value", parser)

        # Call super().__init__() for Pydantic v2 model initialization
        # This will call model_post_init() which initializes all services
        super().__init__(**kwargs)

    def model_post_init(self, __context: object, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes and handles:
        - Service setup and dependency injection via FlextContainer
        - Context and handler initialization
        - Logging configuration

        Pydantic v2 calls this method exactly once per instance, so no guard is needed.

        Args:
            __context: Pydantic's validation context dictionary or None (unused).

        """
        # Initialize dispatcher, registry, and logger FIRST
        # These are needed by _setup_services() below
        dispatcher = FlextDispatcher()
        self._dispatcher = dispatcher
        self._registry = FlextRegistry(dispatcher=dispatcher)
        self._logger = FlextLogger(__name__)

        # Initialize config and parser from stored values
        init_config = getattr(self, "_init_config_value", None)
        init_parser = getattr(self, "_init_parser_value", None)
        self._config = init_config if init_config is not None else FlextLdapConfig()
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
            config_available=self._config is not None,
            parser_available=self._parser is not None,
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
        except Exception:
            self.logger.error(
                "Failed to setup services - critical initialization error",
                exc_info=True,
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
    ) -> FlextResult[bool]:
        """Establish LDAP connection.

        Args:
            connection_config: Connection configuration (required, no fallback)

        Returns:
            FlextResult[bool] indicating connection success

        """
        # Fast fail - connection_config is required, no fallback
        return self._connection.connect(connection_config)

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self._connection.disconnect()

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
        return self._operations.search(search_options, server_type)

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
        return self._operations.add(entry)

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
        return self._operations.modify(dn, changes)

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
        return self._operations.delete(dn)

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Upsert LDAP entry (add if doesn't exist, skip if exists).

        Generic method that handles both regular entries and schema modifications.
        For regular entries: tries add, returns "added" or "skipped" if already exists.
        For schema entries (changetype=modify): applies modify operation.

        Args:
            entry: Entry model to upsert

        Returns:
            FlextResult containing dict with "operation" key:
                - "added": Entry was added
                - "modified": Entry was modified (for schema)
                - "skipped": Entry already exists

        """
        return self._operations.upsert(entry)

    @override
    def execute(self, **kwargs: object) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns:
            FlextResult containing service status

        """
        # Fast fail - delegate to operations, no fallback
        return self._operations.execute()
